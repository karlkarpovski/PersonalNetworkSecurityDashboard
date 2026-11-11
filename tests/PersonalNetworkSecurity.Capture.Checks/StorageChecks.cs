using Microsoft.Data.Sqlite;
using PersonalNetworkSecurity.Capture;
using PersonalNetworkSecurity.GeoIP;

internal static class StorageChecks
{
    public static void MeasureArchive(PacketMetadata packet)
    {
        var directory = Directory.CreateTempSubdirectory("pns-size-check-").FullName;
        try
        {
            var path = Path.Combine(directory, "estimate.sqlite3");
            var now = DateTimeOffset.UtcNow;
            var traffic = new TrafficAccumulator(TimeProvider.System);
            for (var index = 1; index <= TrafficAccumulator.HistoryLimit; index++)
                traffic.Add(packet with
                {
                    Timestamp = now, Source = "192.168.1.125", Destination = $"2001:db8::{index:x}",
                    Owner = new PacketOwner(new ProcessIdentity(12345, "ExampleApplication", now.AddHours(-1)),
                        "tcp-tuple", "Established"),
                });
            var (summary, packets) = traffic.ArchiveSnapshot(0, false);
            using (var store = new LocalStore(path))
            {
                for (var session = 0; session < 30; session++)
                    store.Checkpoint(Guid.NewGuid(), "Example Ethernet Adapter", now, summary, packets);
                Require(store.Sessions().Sum(session => session.RetainedPackets) == 300000, "full archive fixture");
            }
            Console.WriteLine($"SQLite archive fixture (300,000 rows): {new FileInfo(path).Length} bytes.");
        }
        finally { Directory.Delete(directory, recursive: true); }
    }

    public static void Run(PacketMetadata packet)
    {
        var directory = Directory.CreateTempSubdirectory("pns-storage-checks-").FullName;
        try
        {
            var path = Path.Combine(directory, "test.sqlite3");
            var clock = new FixtureClock();
            clock.Advance(TimeSpan.FromDays(100));
            var now = clock.GetUtcNow();
            var session = Guid.NewGuid();
            var traffic = new TrafficAccumulator(clock);
            traffic.Add(packet with { Timestamp = now });
            var batch = traffic.PacketsAfter(0);
            var snapshot = traffic.Snapshot(false);
            using var database = new GeoIpDatabase(directory);
            Guid alert;
            using (var store = new LocalStore(path, clock))
            {
                var geography = new CaptureGeography(database, store);
                var security = new SecurityMonitor(geography, store);
                Require(store.Settings.RetentionDays == 7 && !store.SetRetention(new(0)), "default and validation");
                Require(geography.SetOrigin(new("manual", 10, 20, "Test area", null)) is null, "save origin");
                Require(security.SetRules(new(Ports: [443])) && security.SetAddress(new(packet.Destination, "block")), "save rules");
                security.Observe(session, packet with { Timestamp = now });
                alert = security.History().First(item => item.Rule == "blocklisted-address").Id;
                Require(security.SetState(alert, "acknowledged"), "save alert state");
                store.Checkpoint(session, "Fixture adapter", now, snapshot, batch);
                store.Checkpoint(session, "Fixture adapter", now, snapshot, batch);
                Require(store.Sessions().Single().RetainedPackets == 1 && traffic.PacketsAfter(1).Length == 0, "checkpoint replay is idempotent");
            }
            using (var legacy = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = path, Pooling = false }.ToString()))
            {
                legacy.Open();
                using var command = legacy.CreateCommand();
                command.CommandText = "DROP TABLE geo_cache; PRAGMA user_version=1;";
                command.ExecuteNonQuery();
            }
            using (var store = new LocalStore(path, clock))
            {
                Require(new CaptureGeography(database, store).Settings().Origin?.Label == "Test area", "origin survives restart");
                var security = new SecurityMonitor(new CaptureGeography(database, store), store);
                Require(security.Settings().Rules.Ports!.SequenceEqual([443]) && security.Settings().Addresses.Single().List == "block",
                    "rules survive restart");
                Require(security.History().Single(item => item.Id == alert).State == "acknowledged", "alert survives restart");
                Require(store.History(session, packet.Destination, null, 100).Packets.Single().Sequence == 1, "archive search after restart");
                Require(store.History(session, "%", null, 100).Packets.Length == 0, "archive search treats wildcards literally");
                Require(store.Archive(session) is { Summary.RecentPackets.Length: 0 } archive &&
                    archive.Session.SessionBytes == packet.Length, "checkpoint summary excludes packet duplication");
                store.SaveGeoCache(new GeoCacheSnapshot("fixture", []));
                Require(store.ReadGeoCache()?.Version == "fixture", "version 1 migration adds geolocation cache");
                using (var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = path, Pooling = false }.ToString()))
                {
                    connection.Open();
                    using var transaction = connection.BeginTransaction();
                    using var command = connection.CreateCommand();
                    command.Transaction = transaction;
                    command.CommandText = "DELETE FROM sessions;";
                    command.ExecuteNonQuery();
                }
                Require(store.Sessions().Length == 1, "interrupted transaction rolls back");
                clock.Advance(TimeSpan.FromDays(2));
                Require(store.SetRetention(new(1)) && store.Sessions().Length == 0 && store.Alerts().Length == 0
                    && store.History(session, null, null, 100).Retained == 0 && store.ReadGeoCache() is null,
                    "retention prunes sessions, packets, alerts and cache");
                security.Flush();
                Require(security.History().Length == 0, "expired alerts leave the live summary");
            }
            using var reopened = new LocalStore(path, clock);
            Require(reopened.Settings.RetentionDays == 1, "retention survives restart");
            Console.WriteLine("SQLite checks passed for migration, restart, duplicate checkpoint replay, rollback, search and retention.");
        }
        finally { Directory.Delete(directory, recursive: true); }
    }

    private static void Require(bool condition, string label)
    {
        if (!condition) throw new Exception($"Storage check failed: {label}");
    }
}
