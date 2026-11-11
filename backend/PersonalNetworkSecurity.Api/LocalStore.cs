using System.Text.Json;
using Microsoft.Data.Sqlite;
using PersonalNetworkSecurity.Capture;
using PersonalNetworkSecurity.GeoIP;

internal sealed record StorageSettings(int RetentionDays = 7);
internal sealed record ArchivedSession(Guid Id, string Adapter, DateTimeOffset StartedAt, DateTimeOffset CheckpointAt,
    int RetainedPackets, long SessionBytes);
internal sealed record ArchivedCapture(ArchivedSession Session, TrafficSnapshot Summary);

internal sealed class LocalStore : IDisposable
{
    private const int SessionLimit = 30;
    private const int SchemaVersion = 2;
    private readonly string connectionString;
    private readonly object gate = new();
    private readonly TimeProvider time;
    private readonly FileStream lease;
    private StorageSettings retention = new();

    public string Path { get; }
    public string? CheckpointWarning { get; set; }

    public LocalStore(string path, TimeProvider? time = null)
    {
        this.time = time ?? TimeProvider.System;
        Path = System.IO.Path.GetFullPath(path);
        Directory.CreateDirectory(System.IO.Path.GetDirectoryName(Path)!);
        connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = Path, ForeignKeys = true, DefaultTimeout = 2, Pooling = false,
        }.ToString();
        lease = new FileStream(Path + ".lock", FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
        try
        {
            Initialize();
            retention = ReadSetting<StorageSettings>("retention") ?? new();
            Prune();
        }
        catch { lease.Dispose(); throw; }
    }

    private void Initialize()
    {
        using var connection = Open();
        using (var wal = Command(connection, null, "PRAGMA journal_mode=WAL;")) wal.ExecuteScalar();
        using (var transaction = connection.BeginTransaction())
        {
            using var versionCommand = Command(connection, transaction, "PRAGMA user_version;");
            var version = Convert.ToInt32(versionCommand.ExecuteScalar());
            if (version > SchemaVersion)
                throw new InvalidOperationException("The local dashboard database requires a newer application version.");
            if (version == 0)
            {
                using var migrate = Command(connection, transaction, """
                    CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                    CREATE TABLE sessions (
                        id TEXT PRIMARY KEY, adapter TEXT NOT NULL, started_at INTEGER NOT NULL,
                        checkpoint_at INTEGER NOT NULL, session_bytes INTEGER NOT NULL, summary TEXT NOT NULL
                    );
                    CREATE INDEX sessions_by_checkpoint ON sessions(checkpoint_at DESC);
                    CREATE TABLE packets (
                        session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
                        sequence INTEGER NOT NULL, observed_at INTEGER NOT NULL, search TEXT NOT NULL, metadata TEXT NOT NULL,
                        PRIMARY KEY(session_id, sequence)
                    );
                    CREATE INDEX packets_by_age ON packets(observed_at);
                    CREATE TABLE alerts (id TEXT PRIMARY KEY, observed_at INTEGER NOT NULL, metadata TEXT NOT NULL);
                    CREATE INDEX alerts_by_age ON alerts(observed_at DESC);
                    PRAGMA user_version=1;
                    """);
                migrate.ExecuteNonQuery();
            }
            if (version < 2)
            {
                using var migrate = Command(connection, transaction, """
                    CREATE TABLE geo_cache (id INTEGER PRIMARY KEY CHECK(id=1), saved_at INTEGER NOT NULL, metadata TEXT NOT NULL);
                    PRAGMA user_version=2;
                    """);
                migrate.ExecuteNonQuery();
            }
            transaction.Commit();
        }
    }

    public void Dispose() => lease.Dispose();

    public StorageSettings Settings { get { lock (gate) return retention; } }
    public DateTimeOffset Cutoff { get { lock (gate) return time.GetUtcNow().AddDays(-retention.RetentionDays); } }

    public T? ReadSetting<T>(string key) where T : class
    {
        lock (gate)
        {
            using var connection = Open();
            using var command = Command(connection, null, "SELECT value FROM settings WHERE key=$key;", ("$key", key));
            return command.ExecuteScalar() is string json ? JsonSerializer.Deserialize<T>(json) : null;
        }
    }

    public void SaveSetting<T>(string key, T value) => Write((connection, transaction) =>
        WriteSetting(connection, transaction, key, value));

    public bool SetRetention(StorageSettings value)
    {
        if (value.RetentionDays is < 1 or > 90) return false;
        lock (gate)
        {
            Write((connection, transaction) =>
            {
                WriteSetting(connection, transaction, "retention", value);
                Prune(connection, transaction, time.GetUtcNow().AddDays(-value.RetentionDays));
            });
            retention = value;
            return true;
        }
    }

    public void Prune() => Write((connection, transaction) => Prune(connection, transaction, Cutoff));

    public void Checkpoint(Guid id, string adapter, DateTimeOffset startedAt, TrafficSnapshot snapshot, PacketMetadata[] packets)
    {
        Write((connection, transaction) =>
        {
            var cutoff = Cutoff;
            using var session = Command(connection, transaction, """
                INSERT INTO sessions VALUES ($id,$adapter,$started,$checkpoint,$bytes,$summary)
                ON CONFLICT(id) DO UPDATE SET checkpoint_at=excluded.checkpoint_at, session_bytes=excluded.session_bytes,
                    summary=excluded.summary;
                """, ("$id", id.ToString()), ("$adapter", adapter), ("$started", startedAt.ToUnixTimeMilliseconds()),
                ("$checkpoint", time.GetUtcNow().ToUnixTimeMilliseconds()), ("$bytes", snapshot.SessionBytes),
                ("$summary", JsonSerializer.Serialize(snapshot with { RecentPackets = [] })));
            session.ExecuteNonQuery();
            using var insert = Command(connection, transaction, """
                INSERT INTO packets VALUES ($id,$sequence,$observed,$search,$json)
                ON CONFLICT(session_id,sequence) DO NOTHING;
                """, ("$id", id.ToString()), ("$sequence", 0), ("$observed", 0), ("$search", ""), ("$json", ""));
            insert.Prepare();
            foreach (var packet in packets)
            {
                if (packet.Timestamp < cutoff) continue;
                insert.Parameters["$sequence"].Value = packet.Sequence;
                insert.Parameters["$observed"].Value = packet.Timestamp.ToUnixTimeMilliseconds();
                insert.Parameters["$search"].Value = $"{packet.Source} {packet.Destination} {packet.SourcePort} {packet.DestinationPort} {packet.Protocol} {packet.Direction} {packet.Owner?.Process.Name} {packet.Owner?.Process.Pid}";
                insert.Parameters["$json"].Value = JsonSerializer.Serialize(packet);
                insert.ExecuteNonQuery();
            }
            using var cap = Command(connection, transaction, """
                DELETE FROM packets WHERE session_id=$id AND sequence <= (
                    SELECT max(sequence) - $limit FROM packets WHERE session_id=$id
                );
                """, ("$id", id.ToString()), ("$limit", TrafficAccumulator.HistoryLimit));
            cap.ExecuteNonQuery();
            Prune(connection, transaction, cutoff);
        });
    }

    public ArchivedSession[] Sessions()
    {
        using var connection = Open();
        using var command = Command(connection, null, SessionQuery + " ORDER BY checkpoint_at DESC, id DESC;");
        using var reader = command.ExecuteReader();
        var result = new List<ArchivedSession>();
        while (reader.Read()) result.Add(ReadSession(reader));
        return result.ToArray();
    }

    public ArchivedCapture? Archive(Guid id)
    {
        using var connection = Open();
        using var command = Command(connection, null, SessionQuery + " WHERE id=$id;", ("$id", id.ToString()));
        using var reader = command.ExecuteReader();
        return reader.Read() ? new(ReadSession(reader), JsonSerializer.Deserialize<TrafficSnapshot>(reader.GetString(5))!) : null;
    }

    public PacketHistoryPage History(Guid id, string? search, long? before, int limit)
    {
        using var connection = Open();
        using var transaction = connection.BeginTransaction(deferred: true);
        using var count = Command(connection, transaction, "SELECT count(*) FROM packets WHERE session_id=$id;", ("$id", id.ToString()));
        var retained = Convert.ToInt32(count.ExecuteScalar());
        using var command = Command(connection, transaction, """
            SELECT metadata FROM packets WHERE session_id=$id AND sequence<$before AND instr(lower(search),lower($search))>0
            ORDER BY sequence DESC LIMIT $limit;
            """, ("$id", id.ToString()), ("$before", before ?? long.MaxValue), ("$search", search?.Trim() ?? ""), ("$limit", limit + 1));
        using var reader = command.ExecuteReader();
        var packets = new List<PacketMetadata>();
        while (reader.Read()) packets.Add(JsonSerializer.Deserialize<PacketMetadata>(reader.GetString(0))!);
        var next = packets.Count > limit ? (long?)packets[limit - 1].Sequence : null;
        if (next.HasValue) packets.RemoveAt(limit);
        return new(id, packets.ToArray(), next, retained);
    }

    public SecurityAlert[] Alerts()
    {
        using var connection = Open();
        using var command = Command(connection, null, "SELECT metadata FROM alerts ORDER BY observed_at DESC,rowid DESC LIMIT 200;");
        using var reader = command.ExecuteReader();
        var result = new List<SecurityAlert>();
        while (reader.Read()) result.Add(JsonSerializer.Deserialize<SecurityAlert>(reader.GetString(0))!);
        return result.ToArray();
    }

    public void SaveAlerts(IEnumerable<SecurityAlert> alerts) => Write((connection, transaction) =>
    {
        using var delete = Command(connection, transaction, "DELETE FROM alerts;");
        delete.ExecuteNonQuery();
        var cutoff = Cutoff;
        using var insert = Command(connection, transaction, "INSERT INTO alerts VALUES ($id,$observed,$json);",
            ("$id", ""), ("$observed", 0), ("$json", ""));
        insert.Prepare();
        foreach (var alert in alerts.Take(200).Reverse())
        {
            if (alert.ObservedAt < cutoff) continue;
            insert.Parameters["$id"].Value = alert.Id.ToString();
            insert.Parameters["$observed"].Value = alert.ObservedAt.ToUnixTimeMilliseconds();
            insert.Parameters["$json"].Value = JsonSerializer.Serialize(alert);
            insert.ExecuteNonQuery();
        }
    });

    public GeoCacheSnapshot? ReadGeoCache()
    {
        using var connection = Open();
        using var command = Command(connection, null, "SELECT metadata FROM geo_cache WHERE id=1 AND saved_at >= $cutoff;",
            ("$cutoff", Cutoff.ToUnixTimeMilliseconds()));
        return command.ExecuteScalar() is string value ? JsonSerializer.Deserialize<GeoCacheSnapshot>(value) : null;
    }

    public void SaveGeoCache(GeoCacheSnapshot snapshot) => Write((connection, transaction) =>
    {
        using var command = Command(connection, transaction, """
            INSERT INTO geo_cache VALUES (1,$saved,$data)
            ON CONFLICT(id) DO UPDATE SET saved_at=excluded.saved_at, metadata=excluded.metadata;
            """, ("$saved", time.GetUtcNow().ToUnixTimeMilliseconds()), ("$data", JsonSerializer.Serialize(snapshot)));
        command.ExecuteNonQuery();
    });

    private const string SessionQuery = """
        SELECT id,adapter,started_at,checkpoint_at,session_bytes,summary,
            (SELECT count(*) FROM packets WHERE session_id=sessions.id) FROM sessions
        """;

    private static ArchivedSession ReadSession(SqliteDataReader reader) => new(Guid.Parse(reader.GetString(0)),
        reader.GetString(1), DateTimeOffset.FromUnixTimeMilliseconds(reader.GetInt64(2)),
        DateTimeOffset.FromUnixTimeMilliseconds(reader.GetInt64(3)), reader.GetInt32(6), reader.GetInt64(4));

    private static void WriteSetting<T>(SqliteConnection connection, SqliteTransaction transaction, string key, T value)
    {
        using var command = Command(connection, transaction, """
            INSERT INTO settings VALUES ($key,$value) ON CONFLICT(key) DO UPDATE SET value=excluded.value;
            """, ("$key", key), ("$value", JsonSerializer.Serialize(value)));
        command.ExecuteNonQuery();
    }

    private static void Prune(SqliteConnection connection, SqliteTransaction transaction, DateTimeOffset cutoff)
    {
        using var command = Command(connection, transaction, """
            DELETE FROM sessions WHERE checkpoint_at<$cutoff OR id IN (
                SELECT id FROM sessions ORDER BY checkpoint_at DESC,id DESC LIMIT -1 OFFSET $limit
            );
            DELETE FROM packets WHERE observed_at<$cutoff;
            DELETE FROM alerts WHERE observed_at<$cutoff;
            DELETE FROM geo_cache WHERE saved_at<$cutoff;
            """, ("$cutoff", cutoff.ToUnixTimeMilliseconds()), ("$limit", SessionLimit));
        command.ExecuteNonQuery();
    }

    private void Write(Action<SqliteConnection, SqliteTransaction> write)
    {
        lock (gate)
        {
            using var connection = Open();
            using var transaction = connection.BeginTransaction();
            write(connection, transaction);
            transaction.Commit();
        }
    }

    private SqliteConnection Open()
    {
        var connection = new SqliteConnection(connectionString);
        try { connection.Open(); return connection; }
        catch { connection.Dispose(); throw; }
    }

    private static SqliteCommand Command(SqliteConnection connection, SqliteTransaction? transaction, string sql,
        params (string Name, object Value)[] parameters)
    {
        var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = sql;
        foreach (var (name, value) in parameters) command.Parameters.AddWithValue(name, value);
        return command;
    }
}
