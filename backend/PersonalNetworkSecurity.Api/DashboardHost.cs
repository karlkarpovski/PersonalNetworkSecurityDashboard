using System.Net;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Http.Connections;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.Data.Sqlite;
using PersonalNetworkSecurity.Capture;
using PersonalNetworkSecurity.GeoIP;

public static class DashboardHost
{
    public static async Task<DesktopDashboard> StartDesktopAsync(string webRoot)
    {
        if (!File.Exists(Path.Combine(webRoot, "index.html")))
            throw new FileNotFoundException("The dashboard files are missing. Extract the complete Windows package.");
        var app = Build([], Path.GetFullPath(webRoot));
        try
        {
            await app.StartAsync();
            var addresses = app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!;
            var uri = new Uri(addresses.Addresses.Single());
            app.Services.GetRequiredService<CapturePorts>().Api = uri.Port;
            return new DesktopDashboard(app, uri, app.Services.GetRequiredService<CaptureAccess>().Code);
        }
        catch
        {
            await app.DisposeAsync();
            throw;
        }
    }

    public static WebApplication Build(string[] args, string? webRoot = null)
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            Args = args,
            WebRootPath = webRoot,
            ContentRootPath = webRoot is null ? null : AppContext.BaseDirectory,
        });
        var ports = new CapturePorts(builder.Configuration.GetValue("PNS_API_PORT", 5181),
            builder.Configuration.GetValue("PNS_UI_PORT", 5173));
        if (webRoot is not null) ports = new CapturePorts(0, 0);
        else if (ports.Api is < 1024 or > 65535 || ports.Ui is < 1024 or > 65535 || ports.Api == ports.Ui)
            throw new InvalidOperationException("Choose distinct loopback API and UI ports between 1024 and 65535.");
        builder.WebHost.ConfigureKestrel(options =>
        {
            options.AddServerHeader = false;
            options.Limits.MaxRequestBodySize = 4096;
            options.Listen(IPAddress.Loopback, ports.Api);
        });
        builder.Logging.AddJsonConsole();
        // Browser WebSockets carry their bearer token in the query. Avoid request URL logging.
        builder.Logging.AddFilter("Microsoft.AspNetCore.Hosting.Diagnostics", LogLevel.None);
        builder.Logging.AddFilter("Microsoft.AspNetCore.Server.Kestrel", LogLevel.Warning);
        builder.Logging.AddFilter("Microsoft.AspNetCore.Http.Connections", LogLevel.Warning);
        builder.Logging.AddFilter("Microsoft.AspNetCore.SignalR", LogLevel.Warning);
        builder.Services.AddSingleton(_ => new CaptureAccess(webRoot is not null));
        builder.Services.AddSingleton(_ => new LocalStore(builder.Configuration["PNS_DB_PATH"] ??
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "PersonalNetworkSecurity", "dashboard.sqlite3")));
        builder.Services.AddSingleton(_ => new GeoIpDatabase(builder.Configuration["PNS_GEOIP_DIR"] ??
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "PersonalNetworkSecurity", "GeoIP")));
        builder.Services.AddSingleton<CaptureGeography>();
        builder.Services.AddSingleton<SecurityMonitor>();
        builder.Services.AddSingleton(ports);
        builder.Services.AddSingleton<CaptureMonitor>();
        builder.Services.AddHostedService(services => services.GetRequiredService<CaptureMonitor>());
        builder.Services.AddSingleton<NetworkTools>();
        builder.Services.AddHostedService(services => services.GetRequiredService<NetworkTools>());
        builder.Services.ConfigureHttpJsonOptions(options =>
            options.SerializerOptions.Converters.Add(new JsonStringEnumConverter(JsonNamingPolicy.CamelCase)));
        builder.Services.AddSignalR(options => options.MaximumReceiveMessageSize = 4096)
            .AddJsonProtocol(options => options.PayloadSerializerOptions.Converters.Add(
                new JsonStringEnumConverter(JsonNamingPolicy.CamelCase)));

        var app = builder.Build();
        app.Use(async (context, next) =>
        {
            if (context.Request.Host.Host != "127.0.0.1" || context.Request.Host.Port != ports.Api)
            {
                context.Response.StatusCode = StatusCodes.Status400BadRequest;
                return;
            }
            if (webRoot is not null)
            {
                context.Response.Headers.ContentSecurityPolicy = "default-src 'self'; " +
                    $"connect-src 'self' ws://127.0.0.1:{ports.Api}; " +
                    "style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; object-src 'none'; " +
                    "base-uri 'none'; frame-ancestors 'none'; form-action 'self'";
                context.Response.Headers.XContentTypeOptions = "nosniff";
                context.Response.Headers["Referrer-Policy"] = "no-referrer";
            }

            try { await next(context); }
            catch (SqliteException error) when (!context.Response.HasStarted)
            {
                app.Logger.LogWarning("A local database request failed with SQLite code {Code}.", error.SqliteErrorCode);
                context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
                await context.Response.WriteAsJsonAsync(new { error = "The local database could not complete the request." });
            }
        });

        app.MapGet("/api/health", (HttpContext context) =>
        {
            context.Response.Headers.CacheControl = "no-store";
            return TypedResults.Ok(new HealthStatus("ready"));
        });

        app.UseWebSockets();
        var access = app.Services.GetRequiredService<CaptureAccess>();
        app.Use(async (context, next) =>
        {
            if (!context.Request.Path.StartsWithSegments("/api/capture"))
            {
                await next(context);
                return;
            }

            context.Response.Headers.CacheControl = "no-store";
            var request = context.Request;
            var origin = request.Headers.Origin.ToString();
            var trustedOrigin = origin == ports.ApiOrigin || webRoot is null && origin == ports.UiOrigin;
            if ((origin.Length > 0 || !HttpMethods.IsGet(request.Method) || context.WebSockets.IsWebSocketRequest)
                && !trustedOrigin)
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                return;
            }
            if (!access.Accepts(context))
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                return;
            }
            await next(context);
        });
        var capture = app.MapGroup("/api/capture");
        var tools = capture.MapGroup("/tools");
        tools.MapPost("/health", async (HealthTarget target, NetworkTools network, CancellationToken token) =>
        {
            if (NetworkTools.ValidateHost(target.Host) is not { } host)
                return Results.BadRequest(new { error = "Enter one hostname or IP address." });
            var results = await network.CheckAsync(host, token);
            return results is null ? Results.Conflict(new { error = "A connection check is already running." }) : Results.Ok(results);
        });
        tools.MapGet("/timeline", (NetworkTools network) => network.Timeline());
        tools.MapGet("/devices", (NetworkTools network) => network.Devices());
        tools.MapPut("/devices", (DeviceName name, NetworkTools network) => network.NameDevice(name)
            ? Results.Ok(network.Devices()) : Results.BadRequest(new { error = "Select an observed device and use a name of up to 64 characters." }));
        var storage = capture.MapGroup("/storage");
        storage.MapGet("/settings", (LocalStore store) => new StorageView(store.Path, store.Settings.RetentionDays, store.CheckpointWarning));
        storage.MapPut("/settings", (StorageSettings settings, LocalStore store) => store.SetRetention(settings)
            ? Results.Ok(new StorageView(store.Path, store.Settings.RetentionDays, store.CheckpointWarning))
            : Results.BadRequest(new { error = "Choose a retention period from 1 to 90 days." }));
        storage.MapGet("/sessions", (LocalStore store) => store.Sessions());
        storage.MapGet("/sessions/{id:guid}", (Guid id, LocalStore store) =>
            store.Archive(id) is { } archive ? Results.Ok(archive) : Results.NotFound(new { error = "This capture checkpoint is no longer retained." }));
        capture.MapGet("/session", () => Results.NoContent());
        capture.MapGet("/adapters", (CaptureMonitor monitor) => monitor.GetAdaptersAsync());
        capture.MapGet("/status", (CaptureMonitor monitor, CancellationToken token) => monitor.GetViewAsync(token));
        capture.MapGet("/history", async (CaptureMonitor monitor, string? search, long? before, int? limit,
            Guid? sessionId, CancellationToken token) =>
        {
            if (search?.Length > 100 || before <= 0 || limit is < 1 or > TrafficAccumulator.HistoryLimit)
                return Results.BadRequest(new { error = "Invalid packet history filter or page size." });
            return Results.Ok(await monitor.GetHistoryAsync(search, before, limit ?? 100, sessionId, token));
        });
        capture.MapPost("/start", async (CaptureStart request, CaptureMonitor monitor) =>
        {
            var (code, error) = await monitor.StartAsync(request.AdapterId);
            return error is null ? Results.NoContent() : Results.Json(new { error }, statusCode: code);
        });
        capture.MapPost("/stop", async (CaptureMonitor monitor) =>
        {
            await monitor.StopCaptureAsync();
            return Results.NoContent();
        });
        capture.MapGet("/diagnostics", (LocalStore store) => new {
            version = typeof(DashboardHost).Assembly.GetName().Version?.ToString() ?? "unknown",
            databasePath = store.Path,
            captureDriver = System.IO.File.Exists(System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "Npcap", "wpcap.dll")),
            runtime = System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription
        });
        var geo = capture.MapGroup("/geo");
        geo.MapGet("/settings", (CaptureGeography geography) => geography.Settings());
        geo.MapPost("/reload", (CaptureGeography geography) => geography.Reload());
        geo.MapPut("/origin", (OriginRequest request, CaptureGeography geography) =>
            geography.SetOrigin(request) is { } error
                ? Results.BadRequest(new { error }) : Results.Ok(geography.Settings()));
        geo.MapPost("/lookup", (GeoLookup request, CaptureGeography geography) =>
            geography.Lookup(request.Ip) is { } result
                ? Results.Ok(result) : Results.BadRequest(new { error = "Enter a valid IPv4 or IPv6 address." }));
        var security = capture.MapGroup("/security");
        security.MapGet("/alerts", (SecurityMonitor monitor) => monitor.History());
        security.MapGet("/settings", (SecurityMonitor monitor) => monitor.Settings());
        security.MapPut("/rules", (AlertRules rules, SecurityMonitor monitor) => monitor.SetRules(rules)
            ? Results.Ok(monitor.Settings()) : Results.BadRequest(new { error = "Review the threshold, port, and country limits." }));
        security.MapPut("/address", (AddressRule entry, SecurityMonitor monitor) => monitor.SetAddress(entry)
            ? Results.Ok(monitor.Settings()) : Results.BadRequest(new { error = "Enter a valid address and list. Up to 256 addresses are supported." }));
        security.MapPut("/alerts/{id:guid}", (Guid id, AlertAction action, SecurityMonitor monitor) =>
            action.State is not ("acknowledged" or "dismissed") ? Results.BadRequest(new { error = "Choose a supported alert action." }) :
            monitor.SetState(id, action.State) ? Results.NoContent() : Results.NotFound(new { error = "The alert is unavailable for this action." }));
        app.MapHub<CaptureHub>(CaptureAccess.HubPath, options =>
        {
            options.Transports = HttpTransportType.WebSockets;
            options.ApplicationMaxBufferSize = 128 * 1024;
            options.TransportMaxBufferSize = 16 * 1024;
            options.TransportSendTimeout = TimeSpan.FromSeconds(5);
        });

        if (webRoot is null)
            app.Lifetime.ApplicationStarted.Register(() => Console.WriteLine($"Dashboard access code: {access.Code}"));
        else
        {
            app.UseDefaultFiles();
            app.UseStaticFiles();
        }
        return app;
    }
}

internal sealed record HealthStatus(string Status);
internal sealed record CaptureStart(string? AdapterId);
internal sealed record GeoLookup(string? Ip);
internal sealed record AlertAction(string? State);
internal sealed record StorageView(string Path, int RetentionDays, string? Warning);
internal sealed class CapturePorts(int api, int ui)
{
    public int Api { get; set; } = api;
    public int Ui => ui == 0 ? Api : ui;
    public string ApiOrigin => $"http://127.0.0.1:{Api}";
    public string UiOrigin { get; } = $"http://127.0.0.1:{ui}";
}

public sealed class DesktopDashboard : IAsyncDisposable
{
    private readonly WebApplication app;
    public Uri Origin { get; }
    public string CookieName => CaptureAccess.CookieName;
    public string CookieValue { get; }

    internal DesktopDashboard(WebApplication app, Uri origin, string cookieValue) =>
        (this.app, Origin, CookieValue) = (app, origin, cookieValue);

    public async ValueTask DisposeAsync()
    {
        try { await app.StopAsync(); }
        finally { await app.DisposeAsync(); }
    }
}
