using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Security;
using System.Net.Sockets;
using System.Text.RegularExpressions;

internal sealed record HealthTarget(string? Host);
internal sealed record HealthCheck(string Name, string Result, double? Milliseconds = null, int? Replies = null);
internal sealed record NetworkChangeEntry(DateTimeOffset At, string Adapter, string Change);
internal sealed record NeighborDevice(string Mac, string Ip, DateTimeOffset FirstSeen, DateTimeOffset LastSeen, string? Name);
internal sealed record DeviceName(string? Mac, string? Name);

internal sealed partial class NetworkTools(LocalStore store) : BackgroundService
{
    private const int DeviceLimit = 256;
    private readonly object gate = new();
    private readonly List<NetworkChangeEntry> changes = [];
    private readonly Dictionary<string, NeighborDevice> devices = new(StringComparer.OrdinalIgnoreCase);
    private Dictionary<string, string> names = store.ReadSetting<Dictionary<string, string>>("neighborNames") ?? [];
    private readonly SemaphoreSlim healthGate = new(1, 1);
    private Dictionary<string, AdapterState>? previous;

    public NetworkChangeEntry[] Timeline() { lock (gate) return changes.ToArray(); }
    public NeighborDevice[] Devices() { lock (gate) return devices.Values.OrderByDescending(device => device.LastSeen).ToArray(); }
    public bool NameDevice(DeviceName input)
    {
        var name = input.Name?.Trim();
        lock (gate)
        {
            if (input.Mac is null || name?.Length > 64 || !devices.TryGetValue(input.Mac, out var device)) return false;
            var next = device with { Name = string.IsNullOrEmpty(name) ? null : name };
            var updated = new Dictionary<string, string>(names, StringComparer.OrdinalIgnoreCase);
            if (next.Name is null) updated.Remove(device.Mac);
            else
            {
                if (updated.Count >= DeviceLimit && !updated.ContainsKey(device.Mac)) return false;
                updated[device.Mac] = next.Name;
            }
            store.SaveSetting("neighborNames", updated);
            names = updated;
            devices[device.Mac] = next;
            return true;
        }
    }

    public static string? ValidateHost(string? value)
    {
        var host = value?.Trim();
        return host is { Length: > 0 and <= 253 } && Uri.CheckHostName(host) != UriHostNameType.Unknown
            && !host.Contains('%') ? host : null;
    }

    public async Task<HealthCheck[]?> CheckAsync(string host, CancellationToken token)
    {
        if (!await healthGate.WaitAsync(0, token)) return null;
        try
        {
            var adapters = ReadAdapters().Values;
            var wireless = adapters.Where(adapter => adapter.Wireless).ToArray();
            var wifi = new HealthCheck("Wi-Fi", wireless.Length == 0 ? "No Wi-Fi adapter reported" :
                wireless.Any(adapter => adapter.Up) ? "At least one Wi-Fi link is up" : "Wi-Fi links are down");
            var gateway = adapters.Where(adapter => adapter.Up).SelectMany(adapter => adapter.Gateways)
                .FirstOrDefault(address => address.AddressFamily == AddressFamily.InterNetwork);
            var gatewayCheck = gateway is null
                ? Task.FromResult(new HealthCheck("Gateway", "No IPv4 gateway reported"))
                : PingAsync("Gateway", gateway, token);
            var lookup = Stopwatch.StartNew();
            IPAddress[] addresses;
            HealthCheck dns;
            try
            {
                var literal = IPAddress.TryParse(host, out var address);
                using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
                deadline.CancelAfter(TimeSpan.FromSeconds(4));
                addresses = literal ? [address!] : await Dns.GetHostAddressesAsync(host, deadline.Token);
                dns = new("System DNS", literal ? "IP address supplied" : $"{addresses.Length} address(es) resolved",
                    literal ? null : lookup.Elapsed.TotalMilliseconds);
            }
            catch (Exception error) when (!token.IsCancellationRequested && error is SocketException or OperationCanceledException)
            {
                addresses = [];
                dns = new("System DNS", "Resolution failed or timed out");
            }
            var target = addresses.FirstOrDefault();
            if (target is null) return [wifi, await gatewayCheck, dns, new("Endpoint", "No address to test")];
            var endpointPing = PingAsync("Endpoint", target, token);
            var tls = TlsAsync(host, target, token);
            return [wifi, await gatewayCheck, dns, await endpointPing, await tls];
        }
        finally { healthGate.Release(); }
    }

    private static async Task<HealthCheck> PingAsync(string name, IPAddress address, CancellationToken token)
    {
        using var ping = new Ping();
        var replies = new List<long>(3);
        for (var attempt = 0; attempt < 3; attempt++)
        {
            try
            {
                var reply = await ping.SendPingAsync(address, TimeSpan.FromSeconds(1), cancellationToken: token);
                if (reply.Status == IPStatus.Success) replies.Add(reply.RoundtripTime);
            }
            catch (PingException) { break; }
        }
        return new(name, $"{replies.Count}/3 ICMP replies", replies.Count == 0 ? null : replies.Average(), replies.Count);
    }

    private static async Task<HealthCheck> TlsAsync(string host, IPAddress address, CancellationToken token)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        deadline.CancelAfter(TimeSpan.FromSeconds(4));
        using var client = new TcpClient(address.AddressFamily);
        var timer = Stopwatch.StartNew();
        try
        {
            await client.ConnectAsync(address, 443, deadline.Token);
            using var stream = new SslStream(client.GetStream());
            await stream.AuthenticateAsClientAsync(new SslClientAuthenticationOptions { TargetHost = host }, deadline.Token);
            return new("HTTPS connection", "TCP and TLS completed", timer.Elapsed.TotalMilliseconds);
        }
        catch (Exception error) when (!token.IsCancellationRequested && error is SocketException or IOException
            or System.Security.Authentication.AuthenticationException or OperationCanceledException)
        { return new("HTTPS connection", "TCP or TLS failed or timed out"); }
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(10));
        do
        {
            try
            {
                var current = ReadAdapters();
                var neighbors = await ReadNeighborsAsync(stoppingToken);
                lock (gate)
                {
                    UpdateTimeline(current);
                    var now = DateTimeOffset.UtcNow;
                    foreach (var (ip, mac) in neighbors)
                    {
                        if (devices.TryGetValue(mac, out var device))
                            devices[mac] = device with { Ip = ip, LastSeen = now };
                        else if (devices.Count < DeviceLimit)
                        {
                            devices[mac] = new(mac, ip, now, now, names.GetValueOrDefault(mac));
                            if (!names.ContainsKey(mac)) Record("IPv4 neighbor cache", $"Unlabelled device first observed at {ip}");
                        }
                    }
                }
            }
            catch (Exception error) when (error is NetworkInformationException or IOException or System.ComponentModel.Win32Exception
                || error is OperationCanceledException && !stoppingToken.IsCancellationRequested) { }
        } while (await timer.WaitForNextTickAsync(stoppingToken));
    }

    private void UpdateTimeline(Dictionary<string, AdapterState> current)
    {
        if (previous is { } prior)
        {
            foreach (var (id, adapter) in current)
            {
                if (!prior.TryGetValue(id, out var old)) Record(adapter.Name, "Adapter appeared");
                else
                {
                    if (old.Up != adapter.Up) Record(adapter.Name, adapter.Up ? "Connected" : "Disconnected");
                    if (!old.Gateways.SequenceEqual(adapter.Gateways)) Record(adapter.Name, "Gateway changed");
                    if (old.Dns != adapter.Dns) Record(adapter.Name, "DNS configuration changed");
                    if (old.Addresses != adapter.Addresses) Record(adapter.Name, "Local addresses changed");
                }
            }
            foreach (var (id, adapter) in prior)
                if (!current.ContainsKey(id)) Record(adapter.Name, "Adapter removed");
        }
        previous = current;
    }

    private void Record(string name, string change)
    {
        if (changes.Count == 200) changes.RemoveAt(changes.Count - 1);
        changes.Insert(0, new(DateTimeOffset.UtcNow, name, change));
    }

    private static Dictionary<string, AdapterState> ReadAdapters() => NetworkInterface.GetAllNetworkInterfaces()
        .Where(adapter => adapter.NetworkInterfaceType != NetworkInterfaceType.Loopback)
        .ToDictionary(adapter => adapter.Id, adapter =>
        {
            var properties = adapter.GetIPProperties();
            return new AdapterState(adapter.Name, adapter.OperationalStatus == OperationalStatus.Up,
                adapter.NetworkInterfaceType == NetworkInterfaceType.Wireless80211,
                properties.GatewayAddresses.Select(item => item.Address).Where(ip => !ip.Equals(IPAddress.Any))
                    .OrderBy(ip => ip.ToString(), StringComparer.Ordinal).ToArray(),
                string.Join(",", properties.DnsAddresses.Select(ip => ip.ToString()).Order(StringComparer.Ordinal)),
                string.Join(",", properties.UnicastAddresses.Select(item => item.Address.ToString()).Order(StringComparer.Ordinal)));
        });

    private static async Task<(string Ip, string Mac)[]> ReadNeighborsAsync(CancellationToken token)
    {
        if (!OperatingSystem.IsWindows()) return [];
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        deadline.CancelAfter(TimeSpan.FromSeconds(3));
        using var process = Process.Start(new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "arp.exe"), "-a")
        { UseShellExecute = false, RedirectStandardOutput = true, CreateNoWindow = true });
        if (process is null) return [];
        string output;
        try
        {
            output = await process.StandardOutput.ReadToEndAsync(deadline.Token);
            await process.WaitForExitAsync(deadline.Token);
        }
        catch (OperationCanceledException)
        {
            if (!process.HasExited) process.Kill();
            throw;
        }
        return NeighborPattern().Matches(output).Select(match =>
            (Ip: match.Groups[1].Value, Mac: match.Groups[2].Value.ToLowerInvariant()))
            .Where(entry => entry.Mac != "00-00-00-00-00-00" &&
                (Convert.ToInt32(entry.Mac[..2], 16) & 1) == 0).DistinctBy(entry => entry.Mac).Take(DeviceLimit).ToArray();
    }

    [GeneratedRegex(@"^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})\s", RegexOptions.Multiline)]
    private static partial Regex NeighborPattern();
    private sealed record AdapterState(string Name, bool Up, bool Wireless, IPAddress[] Gateways, string Dns, string Addresses);
}
