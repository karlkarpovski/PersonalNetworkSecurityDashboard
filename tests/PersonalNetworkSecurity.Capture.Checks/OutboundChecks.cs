using PersonalNetworkSecurity.Capture;
using PersonalNetworkSecurity.GeoIP;

internal static class OutboundChecks
{
    public static void Run(PacketMetadata packet)
    {
        var directory = Directory.CreateTempSubdirectory("pns-outbound-checks-").FullName;
        try
        {
            using var geo = new GeoIpDatabase(directory);
            using var store = new LocalStore(Path.Combine(directory, "outbound.sqlite3"));
            var geography = new CaptureGeography(geo);
            var monitor = new SecurityMonitor(geography, store);
            var time = DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 60 * 60);
            var outbound = new OutboundRules(BeaconIntervals: 3, UploadMiB: 1, ExpectedPorts: [443],
                ApprovedApps: ["Approved"], ApprovedDestinations: ["203.0.113.3"],
                Indicators: ["203.0.113.99", "203.0.113.100", "198.51.100.128/25", "flagged.test"],
                IndicatorExclusions: ["203.0.113.99", "safe.flagged.test"], Source: "Test snapshot",
                UpdatedAt: time.AddDays(-1), MaxAgeDays: 2);
            var rules = new AlertRules(0, 0, 0, 0, Outbound: outbound);
            Require(!monitor.SetRules(rules with { Outbound = outbound with { Indicators = ["bad/entry"] } })
                && !monitor.SetRules(rules with { Outbound = outbound with { Source = null } }), "validate indicator settings");
            Require(monitor.SetRules(rules), "save outbound settings");
            var restored = new SecurityMonitor(geography, store).Settings().Rules.Outbound;
            Require(restored?.UpdatedAt == outbound.UpdatedAt && restored!.Indicators!.SequenceEqual(outbound.Indicators!),
                "restore indicator snapshot and provenance");

            var session = Guid.NewGuid();
            var syn = packet with { Timestamp = time, Destination = "203.0.113.2", DestinationPort = 443,
                SourcePort = 50000, ProtocolNumber = 6, Protocol = "TCP", Tcp = new(2, 100, 0),
                Length = 60, Direction = TrafficDirection.Outbound };
            void Observe(PacketMetadata value) => monitor.Observe(session, value);
            int Count(string rule) => monitor.History().Count(alert => alert.Rule == rule);
            Observe(syn);
            Observe(syn with { Timestamp = time.AddSeconds(2) });
            for (ushort i = 1; i <= 3; i++)
                Observe(syn with { Timestamp = time.AddSeconds(i * 10), SourcePort = (ushort)(50000 + i) });
            Require(Count("possible-beaconing") == 1, "regular connections with retransmission");
            for (ushort i = 1; i <= 4; i++)
                Observe(syn with { Destination = "203.0.113.4", Timestamp = time.AddSeconds(i * i * 2),
                    SourcePort = (ushort)(50100 + i) });
            Require(Count("possible-beaconing") == 1, "irregular connections");

            var unexpected = syn with { DestinationPort = 8443, Timestamp = time.AddSeconds(40) };
            Observe(unexpected with { Destination = "203.0.113.3" });
            Observe(unexpected with { Owner = new(new(1, "approved", time), "fixture") });
            Require(Count("unexpected-outbound-service") == 0, "approved application and destination");
            Observe(unexpected);
            Observe(unexpected);
            Require(Count("unexpected-outbound-service") == 1, "unexpected service suppression");

            syn = syn with { Timestamp = time.AddSeconds(40) };
            Observe(syn with { Destination = "203.0.113.99" });
            Observe(syn with { Destination = "203.0.113.100" });
            Observe(syn with { Destination = "198.51.100.130" });
            var query = syn with { Protocol = "UDP", ProtocolNumber = 17, DestinationPort = 53, Tcp = null };
            Observe(query with { Dns = new(1, false, 0, "safe.flagged.test", 1) });
            Observe(query with { Dns = new(2, false, 0, "sub.flagged.test", 1) });
            Observe(syn with { Destination = "198.51.100.131", Timestamp = time.AddDays(2) });
            Require(Count("threat-intel-match") == 3 && monitor.History().Where(a => a.Rule == "threat-intel-match")
                .All(a => a.Evidence.Contains("Test snapshot")), "CIDR, domain, exclusions, attribution, and expiry");

            session = Guid.NewGuid();
            var upload = syn with { Length = 600_000, Tcp = new(0x10, 200, 0) };
            var download = upload with { Source = upload.Destination, Destination = upload.Source,
                Direction = TrafficDirection.Inbound, Length = 1_000_000 };
            Observe(download);
            Observe(upload);
            Observe(upload);
            Require(Count("potential-data-exfiltration") == 0, "balanced transfer");
            upload = upload with { Timestamp = time.AddSeconds(60) };
            Observe(upload);
            Require(Count("potential-data-exfiltration") == 0, "window expiration");
            Observe(upload);
            Observe(upload);
            Require(Count("potential-data-exfiltration") == 1, "large asymmetric transfer and suppression");
            monitor.Flush();
            Require(new SecurityMonitor(geography, store).History().Any(a => a.Rule == "possible-beaconing"),
                "persist outbound alert history");
            Console.WriteLine("Outbound checks passed for intervals, transfers, indicator matching, approvals, and persistence.");
        }
        finally { Directory.Delete(directory, recursive: true); }
    }

    private static void Require(bool condition, string description)
    {
        if (!condition) throw new InvalidOperationException($"Outbound check failed: {description}");
    }
}
