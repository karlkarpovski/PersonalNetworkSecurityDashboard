using System.Net;
using PacketDotNet;
using PersonalNetworkSecurity.Capture;
using PersonalNetworkSecurity.GeoIP;

internal static class DnsChecks
{
    public static void Run()
    {
        var directory = Directory.CreateTempSubdirectory("pns-dns-checks-").FullName;
        try
        {
            using var geo = new GeoIpDatabase(directory);
            using var store = new LocalStore(Path.Combine(directory, "dns.sqlite3"));
            var geography = new CaptureGeography(geo);
            var monitor = new SecurityMonitor(geography, store);
            var rules = new AlertRules(0, 0, 0, 0, DnsWindowSeconds: 10, DnsLabelLength: 12,
                DnsTunnelingNames: 2, DnsQueries: 2, DnsNxDomains: 2, DnsConflictingReplies: true,
                DnsBlockedDomains: [" Example.TEST. "], DnsExcludedDomains: ["safe.example.test"], DnsAllowedTypes: [1]);
            Require(!monitor.SetRules(rules with { DnsBlockedDomains = ["a..test"] }), "reject invalid domain");
            Require(monitor.SetRules(rules), "save DNS settings");
            Require(new SecurityMonitor(geography, store).Settings().Rules.DnsBlockedDomains!
                .SequenceEqual(["example.test"]), "persist normalized denylist");

            var time = DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 10 * 10);
            // UDP/53 DNS question for ExAmPlE.test, type A, class IN.
            var bytes = Convert.FromHexString("4500003A0001000040110000C000020AC6336414C000003500260000" +
                "123401000001000000000000074578416D506C4504746573740000010001");
            var addresses = new HashSet<IPAddress> { IPAddress.Parse("192.0.2.10") };
            PacketMetadata? Parse(byte[] frame) =>
                PacketMetadataParser.Parse(LinkLayers.Raw, frame, time, (uint)frame.Length, addresses);
            var wire = Parse(bytes);
            Require(wire?.Dns is { Name: "example.test", Type: 1, Transaction: 0x1234, IsResponse: false }, "wire question");
            var replyBytes = (byte[])bytes.Clone();
            bytes.AsSpan(12, 4).CopyTo(replyBytes.AsSpan(16));
            bytes.AsSpan(16, 4).CopyTo(replyBytes.AsSpan(12));
            bytes.AsSpan(20, 2).CopyTo(replyBytes.AsSpan(22));
            bytes.AsSpan(22, 2).CopyTo(replyBytes.AsSpan(20));
            replyBytes[30] = 0x81;
            replyBytes[31] = 0x83;
            Require(Parse(replyBytes) is { Direction: TrafficDirection.Inbound,
                Dns: { Transaction: 0x1234, IsResponse: true, ResponseCode: 3 } }, "wire NXDOMAIN reply");
            Require(Parse(bytes[..^1])?.Dns is null, "truncated UDP payload");
            var badName = (byte[])bytes.Clone();
            badName[40] = 0xc0;
            Require(Parse(badName)?.Dns is null, "compressed first name rejected");
            Require(!System.Text.Json.JsonSerializer.Serialize(wire).Contains("example.test"), "question excluded from packet JSON");

            var session = Guid.NewGuid();
            void Query(ushort id, string name, ushort type = 1, int seconds = 0) =>
                monitor.Observe(session, wire! with { Timestamp = time.AddSeconds(seconds), Dns = new(id, false, 0, name, type) });
            void Reply(ushort id, string name, int code, int seconds = 0, ushort port = 49152) =>
                monitor.Observe(session, wire! with { Timestamp = time.AddSeconds(seconds),
                    Source = wire!.Destination, Destination = wire.Source, SourcePort = 53, DestinationPort = port,
                    Direction = TrafficDirection.Inbound, Dns = new(id, true, code, name, 1) });
            int Count(string rule) => monitor.History().Count(alert => alert.Rule == rule);

            Query(1, "safe.example.test");
            Query(2, "notexample.test");
            Query(2, "notexample.test");
            Require(monitor.History().Length == 0, "exclusion, label boundaries, and query deduplication");
            Query(3, "sub.example.test", 28);
            Require(Count("dns-blocked-domain") == 1 && Count("dns-query-anomaly") == 2, "denylist, QTYPE, and rate");
            Query(4, "aaaaaaaaaaaaaaaa.payload.test");
            Query(5, "abcdefghijklmnop.payload.test");
            Query(6, "abcdefghijklmnop.payload.test");
            Require(Count("dns-tunneling") == 0, "low entropy and repeated labels stay quiet");
            Query(7, "qrstuvwxyz012345.payload.test");
            Require(Count("dns-tunneling") == 1, "distinct long high-entropy labels");

            Reply(2, "notexample.test", 3, port: 50000);
            Reply(2, "notexample.test", 0);
            Reply(2, "notexample.test", 0);
            Require(Count("dns-conflicting-replies") == 0, "ignore unmatched replies and identical status");
            Reply(2, "notexample.test", 3);
            Reply(2, "notexample.test", 3);
            Require(Count("dns-conflicting-replies") == 1, "correlated conflict and suppression");
            Query(8, "one.test");
            Reply(8, "one.test", 3);
            Reply(8, "one.test", 3);
            Query(9, "two.test");
            Reply(9, "two.test", 3);
            Require(Count("dns-query-anomaly") == 3, "count only distinct correlated NXDOMAIN replies");
            Reply(8, "one.test", 0, 10);
            Require(Count("dns-conflicting-replies") == 1, "expire correlation across windows");
            var bounded = new DnsDetection();
            var capacityAlerts = new List<string>();
            var capacityRules = new AlertRules(DnsWindowSeconds: 10, DnsQueries: 5000, DnsNxDomains: 1);
            void Record(string rule, string severity, string? scope, string evidence) => capacityAlerts.Add(scope ?? rule);
            for (var index = 0; index < 4200; index++)
            {
                var question = new DnsEvidence((ushort)index, false, 0, $"q{index}.test", 1);
                bounded.Observe(wire! with { Timestamp = time }, question, capacityRules, Record);
            }
            bounded.Observe(wire! with { Timestamp = time, Source = wire!.Destination, Destination = wire.Source,
                SourcePort = 53, DestinationPort = 49152, Direction = TrafficDirection.Inbound },
                new(4199, true, 3, "q4199.test", 1), capacityRules, Record);
            Require(capacityAlerts.Count(scope => scope == "capacity") == 1 && capacityAlerts.Contains("nxdomain") &&
                !capacityAlerts.Contains("queries"), "bounded correlation continues and rate counting reports saturation");
            var timer = System.Diagnostics.Stopwatch.StartNew();
            var loadQuery = new DnsEvidence(4201, false, 0, "load.test", 1);
            for (var index = 0; index < 100000; index++)
                bounded.Observe(wire! with { Timestamp = time }, loadQuery with { Transaction = (ushort)index }, capacityRules, Record);
            Console.WriteLine($"100,000 DNS observations at bounded capacity took {timer.Elapsed.TotalMilliseconds:N0} ms.");
            monitor.Flush();
            Require(new SecurityMonitor(geography, store).History().Any(alert => alert.Rule == "dns-tunneling"),
                "persist DNS alert history");
            Console.WriteLine("DNS checks passed for parsing, correlation, heuristics, exclusions, and persistence.");
        }
        finally { Directory.Delete(directory, recursive: true); }
    }

    private static void Require(bool condition, string description)
    {
        if (!condition) throw new InvalidOperationException($"DNS check failed: {description}");
    }
}
