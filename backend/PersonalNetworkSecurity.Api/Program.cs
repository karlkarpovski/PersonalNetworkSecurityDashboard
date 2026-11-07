using System.Net;

var builder = WebApplication.CreateBuilder(args);
builder.WebHost.ConfigureKestrel(options =>
{
    options.AddServerHeader = false;
    options.Listen(IPAddress.Loopback, 5181);
});
builder.Logging.AddJsonConsole();

var app = builder.Build();
app.Use(async (context, next) =>
{
    if (context.Request.Host.Host != "127.0.0.1" || context.Request.Host.Port != 5181)
    {
        context.Response.StatusCode = StatusCodes.Status400BadRequest;
        return;
    }

    await next(context);
});

app.MapGet("/api/health", (HttpContext context) =>
{
    context.Response.Headers.CacheControl = "no-store";
    return TypedResults.Ok(new HealthStatus("ready", "unavailable"));
});

app.Run();

internal sealed record HealthStatus(string Status, string Capture);
