using PersonalNetworkSecurity.Capture;
using PersonalNetworkSecurity.GeoIP;

internal static class SecurityChecks
{
    public static void Run(PacketMetadata packet)
    {
        var directory = Directory.CreateTempSubdirectory("pns-alert-checks-").FullName;
        try
        {
            var geoFixture = Environment.GetEnvironmentVariable("PNS_GEO_TEST_DIR");
            if (!string.IsNullOrEmpty(geoFixture))
                File.Copy(Path.Combine(geoFixture, "GeoLite2-City.mmdb"), Path.Combine(directory, "GeoLite2-City.mmdb"));
            using var database = new GeoIpDatabase(directory);
            var monitor = new SecurityMonitor(new CaptureGeography(database));
            var time = DateTimeOffset.UnixEpoch.AddSeconds(100);
            var session = Guid.NewGuid();
            var ip = packet.Destination;
            var sent = packet with { Timestamp = time, Length = 600_000, Tcp = new(2, 42, 0) };
            var reset = sent with { Source = ip, SourcePort = sent.DestinationPort, Destination = sent.Source,
                DestinationPort = sent.SourcePort, Direction = TrafficDirection.Inbound, Length = 60, Tcp = new(20, 0, 43) };

            Require(!monitor.SetRules(new(Ports: [0])) && !monitor.SetRules(new(Countries: ["XYZ"]))
                && !monitor.SetAddress(new("bad address", "block")), "reject invalid rules");
            Require(monitor.SetRules(new(1, 2, 2, 1, [443], ["gb"])), "configure detection rules");
            Require(monitor.SetAddress(new(ip, "trusted")), "configure trusted address");
            monitor.Observe(session, sent);
            monitor.Observe(session, reset);
            Require(monitor.History().Length == 0, "trusted address suppression");

            Require(monitor.SetAddress(new(ip, "block")), "replace address classification");
            monitor.Observe(session, sent with { Direction = TrafficDirection.Local });
            Require(monitor.History().Length == 0, "local traffic excluded");
            monitor.Observe(session, sent);
            monitor.Observe(session, reset with { Tcp = new(20, 0, 44) });
            Require(!monitor.History().Any(alert => alert.Rule == "tcp-attempt-reset"), "mismatched acknowledgement excluded");
            monitor.Observe(session, reset);
            monitor.Observe(session, sent);
            monitor.Observe(session, sent with { Destination = "203.0.113.9" });
            var alerts = monitor.History();
            Require(alerts.Any(alert => alert.Rule == "tcp-attempt-reset" && alert.Evidence.Contains("matching outbound SYNs")),
                "matched reset evidence");
            Require(alerts.Any(alert => alert.Rule == "repeated-tcp-syn") &&
                alerts.Any(alert => alert.Rule == "bandwidth-threshold") &&
                alerts.Any(alert => alert.Rule == "destination-threshold"), "window thresholds");
            Require(alerts.Count(alert => alert.Rule == "blocklisted-address") == 1, "duplicate suppression");
            Require(alerts.Where(alert => alert.Rule == "monitored-port").All(alert => alert.Severity == "low")
                && alerts.Any(alert => alert.Rule == "monitored-port"), "configured ports only low severity");
            var high = alerts.Single(alert => alert.Rule == "blocklisted-address");
            Require(monitor.Summary().FlaggedIps.SequenceEqual([ip]), "high priority map marker");
            Require(monitor.SetState(high.Id, "acknowledged") && !monitor.Summary().FlaggedIps.Contains(ip), "acknowledgement clears open flag");
            Require(monitor.SetState(high.Id, "dismissed") && !monitor.SetState(high.Id, "acknowledged"), "dismissal remains in history");
            monitor.Observe(session, sent with { Timestamp = time.AddSeconds(11) });
            Require(monitor.History().Count(alert => alert.Rule == "blocklisted-address") == 1, "cooldown crosses windows");
            monitor.Observe(session, sent with { Timestamp = time.AddSeconds(31) });
            Require(monitor.History().Count(alert => alert.Rule == "blocklisted-address") == 2, "cooldown expiry");
            var otherSession = Guid.NewGuid();
            monitor.Observe(otherSession, sent with { Timestamp = time.AddSeconds(32) });
            Require(monitor.History().Any(alert => alert.SessionId == otherSession && alert.Rule == "blocklisted-address"), "fresh capture cooldowns");

            Require(monitor.SetAddress(new(ip, "watch")), "configure watchlist");
            monitor.Observe(otherSession, sent with { Timestamp = time.AddSeconds(33) });
            Require(monitor.History().Any(alert => alert.Rule == "watched-address" && alert.Severity == "informational"), "watchlist evidence");
            if (!string.IsNullOrEmpty(geoFixture))
            {
                monitor.Observe(otherSession, sent with { Timestamp = time.AddSeconds(33), Destination = "81.2.69.142" });
                Require(monitor.History().Any(alert => alert is { Rule: "monitored-country", Severity: "low" }
                    && alert.Evidence.Contains("GB")), "configured country uses approximate local GeoIP evidence");
            }
            var boundary = new SecurityMonitor(new CaptureGeography(database));
            Require(boundary.SetRules(new(0, 0, 0, 1)), "configure reset-only check");
            boundary.Observe(session, sent with { Timestamp = time.AddSeconds(9) });
            boundary.Observe(session, reset with { Timestamp = time.AddSeconds(10) });
            Require(boundary.History().Length == 0, "reset outside the SYN window is excluded");
            for (var index = 0; index < 250; index++)
                monitor.Observe(Guid.NewGuid(), sent with { Timestamp = time.AddSeconds(34 + index) });
            Require(monitor.History().Length == 200, "bounded alert history");
        }
        finally { Directory.Delete(directory, recursive: true); }
        Console.WriteLine("Security checks passed for thresholds, evidence, trust, cooldowns, alert actions, and retention.");
    }

    private static void Require(bool condition, string label)
    {
        if (!condition) throw new Exception($"Security check failed: {label}");
    }
}
