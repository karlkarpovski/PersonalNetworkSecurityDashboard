using PersonalNetworkSecurity.Capture;
using PersonalNetworkSecurity.GeoIP;

internal static class FloodChecks
{
    public static void Run(PacketMetadata packet)
    {
        var directory = Directory.CreateTempSubdirectory("pns-flood-checks-").FullName;
        try
        {
            using var geo = new GeoIpDatabase(directory);
            using var store = new LocalStore(Path.Combine(directory, "flood.sqlite3"));
            var geography = new CaptureGeography(geo);
            var monitor = new SecurityMonitor(geography, store);
            var rules = new AlertRules(0, 0, 0, 0, FloodWindowSeconds: 2, InboundSynRate: 2,
                UdpPacketRate: 1, UdpKiBRate: 1, IcmpPacketRate: 1, PendingConnections: 2);
            Require(!monitor.SetRules(rules with { FloodWindowSeconds = 0 }) &&
                !monitor.SetRules(rules with { UdpPacketRate = -1 }), "validate traffic thresholds");
            Require(monitor.SetRules(rules), "save traffic thresholds");
            Require(new SecurityMonitor(geography, store).Settings().Rules == rules, "restore traffic thresholds");

            var time = DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 2 * 2);
            var session = Guid.NewGuid();
            var syn = packet with { Timestamp = time, Source = packet.Destination, Destination = packet.Source,
                SourcePort = 50000, DestinationPort = 443, ProtocolNumber = 6, Protocol = "TCP",
                Tcp = new(2, 100, 0), Direction = TrafficDirection.Inbound };
            var response = syn with { Source = syn.Destination, Destination = syn.Source,
                SourcePort = syn.DestinationPort, DestinationPort = syn.SourcePort,
                Direction = TrafficDirection.Outbound, Tcp = new(0x12, 200, 101) };
            void Observe(PacketMetadata item) => monitor.Observe(session, item);
            int Count(string rule) => monitor.History().Count(alert => alert.Rule == rule);

            Observe(response with { Tcp = new(2, 200, 0) });
            Observe(syn with { Tcp = null });
            Observe(syn);
            Observe(syn);
            Observe(response);
            Observe(syn with { Tcp = new(0x10, 101, 201) });
            Observe(syn with { SourcePort = 50001 });
            Require(monitor.History().Length == 0, "outbound, incomplete metadata, retries, and completed handshake");
            Observe(syn with { SourcePort = 50002 });
            Observe(syn with { SourcePort = 50003 });
            Require(Count("tcp-syn-flood") == 1 && Count("connection-exhaustion") == 1,
                "inbound SYN rate and distinct pending handshakes");

            var udp = syn with { Protocol = "UDP", ProtocolNumber = 17, Tcp = null, Length = 80 };
            Observe(udp);
            Observe(udp with { DestinationPort = 444 });
            Observe(udp with { DestinationPort = null });
            Require(Count("udp-flood") == 0, "separate UDP services and ignore missing ports");
            Observe(udp);
            Observe(udp);
            Observe(udp with { DestinationPort = 445, Length = 2048 });
            Require(Count("udp-flood") == 2 && monitor.History().Any(alert => alert.Evidence.Contains("KiB/s")),
                "UDP packet and byte rates with independent service cooldowns");

            var icmp = udp with { Protocol = "ICMP", ProtocolNumber = 1, SourcePort = null, DestinationPort = null };
            Observe(icmp);
            Observe(icmp with { Timestamp = time.AddSeconds(2) });
            Require(Count("icmp-flood") == 0, "expire ICMP observations across windows");
            Observe(icmp with { Timestamp = time.AddSeconds(2) });
            Observe(icmp with { Timestamp = time.AddSeconds(2) });
            Require(Count("icmp-flood") == 1, "ICMP threshold and duplicate suppression");
            Observe(syn with { Timestamp = time.AddSeconds(2), SourcePort = 50100, DestinationPort = 444 });
            Require(Count("connection-exhaustion") == 1, "pending attempts expire across windows");

            session = Guid.NewGuid();
            Observe(syn);
            Observe(response with { Tcp = new(0x14, 0, 101) });
            Observe(syn with { SourcePort = 50001 });
            Require(Count("connection-exhaustion") == 1, "reset clears an observed attempt");
            monitor.Flush();
            Require(new SecurityMonitor(geography, store).History().Any(alert => alert.Rule == "icmp-flood"),
                "persist traffic anomaly alerts");
            Console.WriteLine("Traffic anomaly checks passed for rates, handshake estimates, windows, suppression, and settings.");
        }
        finally { Directory.Delete(directory, recursive: true); }
    }

    private static void Require(bool condition, string description)
    {
        if (!condition) throw new InvalidOperationException($"Traffic anomaly check failed: {description}");
    }
}
