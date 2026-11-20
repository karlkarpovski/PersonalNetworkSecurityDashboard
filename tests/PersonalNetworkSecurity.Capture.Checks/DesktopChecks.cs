using System.Net;
using System.Net.Http.Json;
using System.Net.Sockets;
using System.Text.Json;

internal static class DesktopChecks
{
    public static async Task RunAsync()
    {
        var directory = Directory.CreateTempSubdirectory("pns-desktop-checks-").FullName;
        var path = Path.Combine(directory, "test.sqlite3");
        var oldPath = Environment.GetEnvironmentVariable("PNS_DB_PATH");
        var oldGeo = Environment.GetEnvironmentVariable("PNS_GEOIP_DIR");
        Environment.SetEnvironmentVariable("PNS_DB_PATH", path);
        Environment.SetEnvironmentVariable("PNS_GEOIP_DIR", directory);
        try
        {
            File.WriteAllText(Path.Combine(directory, "index.html"), "<title>Offline dashboard fixture</title>");
            ushort? testPort = null;
            await using (var host = await DashboardHost.StartDesktopAsync(directory))
            {
                using var client = new HttpClient { BaseAddress = host.Origin, Timeout = TimeSpan.FromSeconds(8) };
                using var index = await client.GetAsync("/");
                Require(index.IsSuccessStatusCode && (await index.Content.ReadAsStringAsync()).Contains("Offline dashboard fixture"),
                    "static dashboard served on loopback");
                Require(index.Headers.Contains("Content-Security-Policy"), "content security policy");
                using var unauthenticated = await client.GetAsync("api/capture/session");
                Require(unauthenticated.StatusCode == HttpStatusCode.Unauthorized, "cookie required");
                client.DefaultRequestHeaders.Add("Cookie", $"{host.CookieName}={host.CookieValue}");
                using var authenticated = await client.GetAsync("api/capture/session");
                Require(authenticated.StatusCode == HttpStatusCode.NoContent, "valid desktop cookie");
                using var foreign = new HttpRequestMessage(HttpMethod.Get, "api/capture/session");
                foreign.Headers.Add("Origin", "https://foreign.invalid");
                using var denied = await client.SendAsync(foreign);
                Require(denied.StatusCode == HttpStatusCode.Forbidden, "foreign origin rejected");

                if (Environment.GetEnvironmentVariable("PNS_TEST_DESKTOP_CAPTURE") == "1")
                    testPort = await CaptureLoopback(client);
                if (Environment.GetEnvironmentVariable("PNS_TEST_PHYSICAL_CAPTURE") == "1")
                {
                    using var stopped = await client.PostAsync("api/capture/stop", null);
                    stopped.EnsureSuccessStatusCode();
                    var adapters = await client.GetFromJsonAsync<AdapterResult>("api/capture/adapters");
                    var physical = adapters?.Adapters.FirstOrDefault(adapter => adapter.LinkStatus == "Up" &&
                        !adapter.Id.EndsWith("NPF_Loopback", StringComparison.OrdinalIgnoreCase));
                    Require(physical is not null, "connected physical adapter available");
                    using var started = await client.PostAsJsonAsync("api/capture/start", new CaptureStart(physical!.Id));
                    started.EnsureSuccessStatusCode();
                    await Task.Delay(TimeSpan.FromSeconds(15));
                    using var status = await client.GetFromJsonAsync<JsonDocument>("api/capture/status");
                    Require(status!.RootElement.GetProperty("state").GetString() == "running", "physical adapter remains running");
                    using var ended = await client.PostAsync("api/capture/stop", null);
                    ended.EnsureSuccessStatusCode();
                    Console.WriteLine("Physical adapter passive capture remained running for 15 seconds and stopped successfully.");
                }
            }
            if (testPort is { } port)
            {
                using var store = new LocalStore(path);
                Require(store.Sessions().Any(session => store.History(session.Id, port.ToString(), null, 100).Packets.Any(packet => packet.SourcePort == port)),
                    "host shutdown saved the real loopback packet");
            }
            Console.WriteLine(testPort.HasValue
                ? "Desktop host checks passed for offline assets, cookie authentication, origin rejection, real Npcap capture and shutdown checkpoint."
                : "Desktop host checks passed for offline assets, cookie authentication and origin rejection.");
        }
        finally
        {
            Environment.SetEnvironmentVariable("PNS_DB_PATH", oldPath);
            Environment.SetEnvironmentVariable("PNS_GEOIP_DIR", oldGeo);
            Directory.Delete(directory, recursive: true);
        }
    }

    private static async Task<ushort> CaptureLoopback(HttpClient client)
    {
        using var sender = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        using var receiver = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        var port = (ushort)((IPEndPoint)sender.Client.LocalEndPoint!).Port;
        var adapters = await client.GetFromJsonAsync<AdapterResult>("api/capture/adapters");
        var loopback = adapters?.Adapters.SingleOrDefault(adapter => adapter.Id.EndsWith("NPF_Loopback", StringComparison.OrdinalIgnoreCase));
        Require(loopback is not null, "Npcap loopback adapter");
        client.DefaultRequestHeaders.Add("Origin", client.BaseAddress!.GetLeftPart(UriPartial.Authority));
        using var started = await client.PostAsJsonAsync("api/capture/start", new CaptureStart(loopback!.Id));
        Require(started.StatusCode == HttpStatusCode.NoContent, "start loopback capture");
        await sender.SendAsync(new byte[64], (IPEndPoint)receiver.Client.LocalEndPoint!);
        for (var attempt = 0; attempt < 40; attempt++)
        {
            await Task.Delay(150);
            using var history = await client.GetFromJsonAsync<JsonDocument>($"api/capture/history?search={port}");
            if (history!.RootElement.GetProperty("packets").EnumerateArray().Any(packet =>
                packet.GetProperty("sourcePort").ValueKind == JsonValueKind.Number && packet.GetProperty("sourcePort").GetUInt16() == port))
                return port;
        }
        throw new InvalidOperationException("The controlled UDP packet did not reach the desktop capture host.");
    }

    private static void Require(bool condition, string label)
    {
        if (!condition) throw new InvalidOperationException($"Desktop check failed: {label}");
    }
}
