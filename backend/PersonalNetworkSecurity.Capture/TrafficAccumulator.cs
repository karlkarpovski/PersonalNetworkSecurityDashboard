namespace PersonalNetworkSecurity.Capture;

public sealed record FlowKey(string LocalIp, ushort? LocalPort, string RemoteIp, ushort? RemotePort, string Protocol)
{
    public static FlowKey ForPacket(PacketMetadata packet) => packet.Direction == TrafficDirection.Inbound
        ? new(packet.Destination, packet.DestinationPort, packet.Source, packet.SourcePort, packet.Protocol)
        : new(packet.Source, packet.SourcePort, packet.Destination, packet.DestinationPort, packet.Protocol);
}
public sealed record FlowSummary(FlowKey Endpoint, long Packets, long SentBytes, long ReceivedBytes,
    DateTimeOffset FirstSeen, DateTimeOffset LastSeen, PacketOwner? Owner = null, bool ConflictingOwners = false);
public sealed record ApplicationTraffic(ProcessIdentity Process, long Packets, long SentBytes, long ReceivedBytes, long LocalBytes,
    int ActiveFlows = 0, long BytesPerSecond = 0);
public sealed record PacketHistoryPage(Guid? SessionId, PacketMetadata[] Packets, long? NextBefore, int Retained);

public sealed record TrafficSnapshot(
    long InboundPackets, long OutboundPackets, long LocalPackets, long UnknownPackets, long SessionBytes,
    long DownloadBytesPerSecond, long UploadBytesPerSecond, int ActiveFlows, int UniqueRemoteIps,
    bool RemoteIpLimitReached, long FlowCapacityMisses, PacketMetadata[] RecentPackets, FlowSummary[] RecentFlows,
    double PacketsPerSecond, ApplicationTraffic[] Applications, long UnattributedBytes);

public sealed class TrafficAccumulator(TimeProvider time)
{
    private const int Capacity = 4096;
    private const int RecentPacketLimit = 200;
    public const int HistoryLimit = 10_000;
    private const int ApplicationLimit = 1024;
    private readonly object gate = new();
    private readonly long start = time.GetTimestamp();
    private readonly Dictionary<FlowKey, FlowSummary> flows = new();
    private readonly HashSet<string> remoteIps = new(StringComparer.Ordinal);
    private readonly PacketMetadata?[] packets = new PacketMetadata[HistoryLimit];
    private readonly Dictionary<ProcessIdentity, ApplicationTraffic> applications = new();
    private readonly Dictionary<ProcessIdentity, (long Second, long Current, long Previous)> applicationRates = new();
    private readonly long[] rateSeconds = [-1, -1, -1];
    private readonly long[] uploads = new long[3];
    private readonly long[] downloads = new long[3];
    private readonly long[] packetCounts = new long[3];
    private long incoming, outgoing, local, unknown, bytes, flowCapacityMisses;
    private bool remoteLimit;
    private long sequence, unattributedBytes;

    public void Add(PacketMetadata packet)
    {
        lock (gate)
        {
            bytes += packet.Length;
            packets[sequence % HistoryLimit] = packet with { Sequence = ++sequence };
            var inbound = packet.Direction == TrafficDirection.Inbound;
            var second = ElapsedSecond();
            AddApplicationTraffic(packet, second);
            var bucket = (int)(second % rateSeconds.Length);
            if (rateSeconds[bucket] != second)
            {
                rateSeconds[bucket] = second;
                uploads[bucket] = downloads[bucket] = packetCounts[bucket] = 0;
            }
            packetCounts[bucket]++;
            switch (packet.Direction)
            {
                case TrafficDirection.Local: local++; return;
                case TrafficDirection.Unknown: unknown++; return;
            }
            if (inbound) { incoming++; downloads[bucket] += packet.Length; }
            else { outgoing++; uploads[bucket] += packet.Length; }

            var key = FlowKey.ForPacket(packet);
            if (remoteIps.Count < Capacity) remoteIps.Add(key.RemoteIp);
            else if (!remoteIps.Contains(key.RemoteIp)) remoteLimit = true;
            if (!flows.TryGetValue(key, out var flow))
            {
                if (flows.Count == Capacity) { flowCapacityMisses++; return; }
                flow = new(key, 0, 0, 0, packet.Timestamp, packet.Timestamp);
            }

            var conflicting = flow.ConflictingOwners || flow.Owner is not null && packet.Owner is not null
                && flow.Owner.Process != packet.Owner.Process;
            flows[key] = flow with
            {
                Packets = flow.Packets + 1,
                SentBytes = flow.SentBytes + (inbound ? 0 : packet.Length),
                ReceivedBytes = flow.ReceivedBytes + (inbound ? packet.Length : 0),
                FirstSeen = packet.Timestamp < flow.FirstSeen ? packet.Timestamp : flow.FirstSeen,
                LastSeen = packet.Timestamp > flow.LastSeen ? packet.Timestamp : flow.LastSeen,
                Owner = conflicting ? null : packet.Owner ?? flow.Owner,
                ConflictingOwners = conflicting
            };
        }
    }

    private void AddApplicationTraffic(PacketMetadata packet, long second)
    {
        if (packet.Owner is not { Process: var process })
        {
            unattributedBytes += packet.Length;
            return;
        }
        if (!applications.TryGetValue(process, out var app))
        {
            if (applications.Count == ApplicationLimit) { unattributedBytes += packet.Length; return; }
            app = new(process, 0, 0, 0, 0);
        }
        applications[process] = app with
        {
            Packets = app.Packets + 1,
            SentBytes = app.SentBytes + (packet.Direction == TrafficDirection.Outbound ? packet.Length : 0),
            ReceivedBytes = app.ReceivedBytes + (packet.Direction == TrafficDirection.Inbound ? packet.Length : 0),
            LocalBytes = app.LocalBytes + (packet.Direction == TrafficDirection.Local ? packet.Length : 0)
        };
        var rate = applicationRates.GetValueOrDefault(process);
        if (rate.Second != second)
            rate = (second, 0, rate.Second == second - 1 ? rate.Current : 0);
        applicationRates[process] = (rate.Second, rate.Current + packet.Length, rate.Previous);
    }

    public PacketHistoryPage History(Guid sessionId, string? search, long? before, int limit)
    {
        lock (gate)
        {
            var query = search?.Trim();
            var matches = ReadPackets(before).Where(packet => string.IsNullOrEmpty(query) || Matches(packet, query))
                .Take(limit + 1).ToArray();
            return new(sessionId, matches.Take(limit).ToArray(), matches.Length > limit ? matches[limit - 1].Sequence : null,
                (int)Math.Min(sequence, HistoryLimit));
        }
    }

    private IEnumerable<PacketMetadata> ReadPackets(long? before = null)
    {
        var newest = before is { } cursor ? Math.Min(sequence, cursor - 1) : sequence;
        var oldest = Math.Max(1, sequence - HistoryLimit + 1);
        for (var index = newest; index >= oldest; index--)
            yield return packets[(index - 1) % HistoryLimit]!;
    }

    private static bool Matches(PacketMetadata packet, string query) =>
        packet.Source.Contains(query, StringComparison.OrdinalIgnoreCase)
        || packet.Destination.Contains(query, StringComparison.OrdinalIgnoreCase)
        || packet.Protocol.Contains(query, StringComparison.OrdinalIgnoreCase)
        || packet.Direction.ToString().Contains(query, StringComparison.OrdinalIgnoreCase)
        || packet.Owner?.Process.Name.Contains(query, StringComparison.OrdinalIgnoreCase) == true
        || packet.Owner?.Process.Pid.ToString() == query
        || packet.SourcePort?.ToString() == query || packet.DestinationPort?.ToString() == query;

    public void ExpireIdleFlows()
    {
        lock (gate)
        {
            var threshold = time.GetUtcNow().AddMinutes(-2);
            foreach (var (key, flow) in flows)
                if (flow.LastSeen < threshold) flows.Remove(key);
        }
    }

    public TrafficSnapshot Snapshot(bool running)
    {
        lock (gate)
        {
            var second = ElapsedSecond();
            long sent = 0, received = 0, count = 0;
            if (running)
            {
                for (var i = 0; i < rateSeconds.Length; i++)
                {
                    if (rateSeconds[i] < 0 || rateSeconds[i] >= second || rateSeconds[i] < second - 2) continue;
                    sent += uploads[i];
                    received += downloads[i];
                    count += packetCounts[i];
                }
            }
            var divisor = Math.Clamp(second, 1, 2);
            var active = running ? flows.Values.Where(flow => flow.Owner is not null)
                .CountBy(flow => flow.Owner!.Process).ToDictionary() : new Dictionary<ProcessIdentity, int>();
            return new(incoming, outgoing, local, unknown, bytes, received / divisor, sent / divisor,
                running ? flows.Count : 0, remoteIps.Count, remoteLimit, flowCapacityMisses, ReadPackets().Take(RecentPacketLimit).ToArray(),
                flows.Values.OrderByDescending(flow => flow.LastSeen).Take(50).ToArray(), (double)count / divisor,
                applications.Values.OrderByDescending(app => app.SentBytes + app.ReceivedBytes + app.LocalBytes).Take(50)
                    .Select(app => app with { ActiveFlows = active.GetValueOrDefault(app.Process),
                        BytesPerSecond = running ? ApplicationRate(app.Process, second) / divisor : 0 }).ToArray(), unattributedBytes);
        }
    }

    private long ElapsedSecond() => (long)time.GetElapsedTime(start).TotalSeconds;

    private long ApplicationRate(ProcessIdentity process, long second)
    {
        var rate = applicationRates[process];
        var elapsed = second - rate.Second;
        return elapsed switch { 0 => rate.Previous, 1 => rate.Current + rate.Previous, 2 => rate.Current, _ => 0 };
    }
}
