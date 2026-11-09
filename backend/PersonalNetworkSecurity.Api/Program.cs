using System.Net;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Http.Connections;
using PersonalNetworkSecurity.Capture;
using PersonalNetworkSecurity.GeoIP;

var builder = WebApplication.CreateBuilder(args);
var ports = new CapturePorts(builder.Configuration.GetValue("PNS_API_PORT", 5181),
    builder.Configuration.GetValue("PNS_UI_PORT", 5173));
if (ports.Api is < 1024 or > 65535 || ports.Ui is < 1024 or > 65535 || ports.Api == ports.Ui)
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
builder.Services.AddSingleton<CaptureAccess>();
builder.Services.AddSingleton(_ => new GeoIpDatabase(builder.Configuration["PNS_GEOIP_DIR"] ??
    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "PersonalNetworkSecurity", "GeoIP")));
builder.Services.AddSingleton<CaptureGeography>();
builder.Services.AddSingleton<SecurityMonitor>();
builder.Services.AddSingleton(ports);
builder.Services.AddSingleton<CaptureMonitor>();
builder.Services.AddHostedService(services => services.GetRequiredService<CaptureMonitor>());
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

    await next(context);
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
    var trustedOrigin = origin == ports.UiOrigin || origin == ports.ApiOrigin;
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

app.Lifetime.ApplicationStarted.Register(() => Console.WriteLine($"Dashboard access code: {access.Code}"));
app.Run();

internal sealed record HealthStatus(string Status);
internal sealed record CaptureStart(string? AdapterId);
internal sealed record GeoLookup(string? Ip);
internal sealed record AlertAction(string? State);
internal sealed record CapturePorts(int Api, int Ui)
{
    public string ApiOrigin { get; } = $"http://127.0.0.1:{Api}";
    public string UiOrigin { get; } = $"http://127.0.0.1:{Ui}";
}
