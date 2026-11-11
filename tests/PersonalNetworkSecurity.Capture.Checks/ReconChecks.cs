using PersonalNetworkSecurity.Capture;
using PersonalNetworkSecurity.GeoIP;

internal static class ReconChecks
{
    public static void Run(PacketMetadata packet)
    {
        var directory = Directory.CreateTempSubdirectory("pns-recon-checks-").FullName;
        try
        {
            using var geo = new GeoIpDatabase(directory);
            using var store = new LocalStore(Path.Combine(directory, "recon.sqlite3"));
            var geography = new CaptureGeography(geo);
            var monitor = new SecurityMonitor(geography, store);
            var settings = new AlertRules(0, 0, 0, 0, ScanPorts: 2, SweepHosts: 2, StealthProbes: 2,
                UnexpectedPackets: 2, ReconWindowSeconds: 5, AllowedProtocols: [1, 6, 17, 58]);
            Require(!monitor.SetRules(settings with { AllowedProtocols = [] }), "require protocol allowlist");
            Require(!monitor.SetRules(settings with { ReconWindowSeconds = 0 }), "reject zero window");
            Require(monitor.SetRules(settings), "save reconnaissance settings");
            var restored = new SecurityMonitor(geography, store).Settings().Rules;
            Require(restored.ReconWindowSeconds == 5 && restored.ScanPorts == 2 && restored.SweepHosts == 2
                && restored.StealthProbes == 2 && restored.UnexpectedPackets == 2
                && restored.AllowedProtocols!.SequenceEqual(settings.AllowedProtocols!), "restore reconnaissance settings");

            var time = DateTimeOffset.UtcNow;
            time = DateTimeOffset.FromUnixTimeSeconds(time.ToUnixTimeSeconds() / 5 * 5);
            var session = Guid.NewGuid();
            var syn = packet with { Timestamp = time, ProtocolNumber = 6, SourcePort = 50000, DestinationPort = 443,
                Tcp = new(2, 100, 0), Direction = TrafficDirection.Outbound };
            void Observe(PacketMetadata item) => monitor.Observe(session, item);
            int Count(string rule) => monitor.History().Count(alert => alert.Rule == rule);

            Observe(syn);
            Observe(syn);
            Observe(syn with { DestinationPort = 80, Tcp = null });
            Observe(syn with { DestinationPort = 80, Tcp = new(0x11, 200, 0) });
            Require(monitor.History().Length == 0, "duplicates, incomplete TCP, and FIN+ACK stay quiet");

            Observe(syn with { Timestamp = time.AddSeconds(5), DestinationPort = 80 });
            Require(Count("port-scan") == 0, "expire previous window");
            syn = syn with { Timestamp = time.AddSeconds(5) };
            Observe(syn);
            Observe(syn with { DestinationPort = 8080 });
            Require(Count("port-scan") == 1, "distinct ports and duplicate suppression");

            session = Guid.NewGuid();
            Observe(syn);
            Observe(syn with { Destination = "203.0.113.19" });
            Require(monitor.History().Any(alert => alert.SessionId == session &&
                alert.Rule == "port-scan" && alert.Evidence.Contains("across multiple hosts")), "multi-host scan");

            var echo = syn with { ProtocolNumber = 1, SourcePort = null, DestinationPort = null, Tcp = null, IsEchoRequest = true };
            Observe(echo);
            Observe(echo);
            Observe(echo with { Destination = "203.0.113.19", IsEchoRequest = false });
            Require(Count("host-discovery") == 0, "repeated echo destination and non-requests stay quiet");
            Observe(echo with { Destination = "203.0.113.19" });
            Require(Count("host-discovery") == 1, "echo requests to distinct hosts");

            var probe = syn with { Tcp = new(0x29, 1, 0) };
            Observe(probe);
            Observe(probe);
            Require(Count("tcp-stealth-scan") == 0, "stealth retransmission stays quiet");
            Observe(probe with { Tcp = new(0, 2, 0) });
            Require(Count("tcp-stealth-scan") == 1, "distinct unusual TCP probes");

            var unexpected = echo with { ProtocolNumber = 47, IsEchoRequest = false };
            Observe(unexpected);
            Observe(unexpected with { ProtocolNumber = -1 });
            Observe(unexpected with { ProtocolNumber = 17 });
            Require(Count("unusual-protocol") == 0, "allowed and invalid protocols stay quiet");
            Observe(unexpected);
            Observe(unexpected);
            Require(Count("unusual-protocol") == 1, "unexpected protocol count and suppression");
            monitor.Flush();
            Require(new SecurityMonitor(geography, store).History().Any(alert => alert.Rule == "host-discovery"),
                "persist reconnaissance alerts");
        }
        finally { Directory.Delete(directory, recursive: true); }
    }

    private static void Require(bool condition, string description)
    {
        if (!condition) throw new InvalidOperationException($"Reconnaissance check failed: {description}");
    }
}
