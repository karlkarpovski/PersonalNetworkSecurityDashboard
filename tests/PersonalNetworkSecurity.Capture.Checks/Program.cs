using System.Net;
using PacketDotNet;
using PersonalNetworkSecurity.Capture;

var time = new FixtureClock();
var now = time.GetUtcNow();
var addresses = new HashSet<IPAddress> { IPAddress.Parse("192.0.2.10"), IPAddress.Parse("2001:db8::10") };
var ethernet = "00112233445566778899AABB";
var tcp = "C00001BB00000000000000005002000000000000";
var ipv4 = "450000280001000040060000C000020AC6336414";
var udp = "0035C00000080000";
var ipv6 = "600000000008114020010DB800000000000000000000002020010DB8000000000000000000000010";
PacketMetadata Parse(LinkLayers link, string hex, uint length = 900) =>
    PacketMetadataParser.Parse(link, Convert.FromHexString(hex), now, length, addresses)
    ?? throw new Exception("Expected IP metadata.");

var sent = Parse(LinkLayers.Ethernet, ethernet + "0800" + ipv4 + tcp);
Require(sent is { Direction: TrafficDirection.Outbound, Source: "192.0.2.10", SourcePort: 49152,
    Destination: "198.51.100.20", DestinationPort: 443, Protocol: "TCP", Length: 900, Tcp.Flags: 2 },
    "Ethernet IPv4/TCP and original wire length");
var received = Parse(LinkLayers.Raw, ipv6 + udp, 48);
Require(received is { Direction: TrafficDirection.Inbound, Source: "2001:db8::20", SourcePort: 53,
    Destination: "2001:db8::10", DestinationPort: 49152, Protocol: "UDP" }, "raw IPv6/UDP");
var hopByHop = Parse(LinkLayers.Raw, ipv6.Replace("00081140", "00100040") + "1100000000000000" + udp);
Require(hopByHop is { Direction: TrafficDirection.Inbound, Protocol: "UDP", SourcePort: 53 }, "IPv6 extension header");
var ipv6Fragment = Parse(LinkLayers.Raw, ipv6.Replace("00081140", "00102C40") + "1100000800000001" + udp);
Require(ipv6Fragment is { SourcePort: null, DestinationPort: null }, "noninitial IPv6 fragment");
var loopback = Parse(LinkLayers.Null, "18000000" + ipv6.Replace("20010DB8000000000000000000000020", "00000000000000000000000000000001") + udp);
Require(loopback.Direction == TrafficDirection.Local, "Npcap IPv6 loopback header");
var icmp = Parse(LinkLayers.Ethernet, ethernet + "08004500001C0001000040010000CB007101CB0071020800000000000000");
Require(icmp is { Direction: TrafficDirection.Unknown, SourcePort: null, Protocol: "ICMP", IsEchoRequest: true }, "IPv4 ICMP echo request");
var echoV6 = Parse(LinkLayers.Raw, ipv6.Replace("00081140", "00083A40") + "8000000000000000");
Require(echoV6 is { ProtocolNumber: 58, IsEchoRequest: true }, "IPv6 ICMP echo request");
var replyV6 = Parse(LinkLayers.Raw, ipv6.Replace("00081140", "00083A40") + "8100000000000000");
Require(!replyV6.IsEchoRequest, "IPv6 ICMP echo reply");
var fragment = Parse(LinkLayers.Ethernet, ethernet + "0800" + ipv4.Replace("00010000", "00010001") + tcp);
Require(fragment is { Protocol: "TCP", SourcePort: null, DestinationPort: null }, "noninitial IPv4 fragment");
Require(PacketMetadataParser.Parse(LinkLayers.Ethernet, [1, 2], now, 2, addresses) is null, "truncated frame");
Require(PacketMetadataParser.Normalize(IPAddress.Parse("fe80::1234%12")).Equals(IPAddress.Parse("fe80::1234")),
    "scoped IPv6 normalization");

var traffic = new TrafficAccumulator(time);
traffic.Add(sent);
traffic.Add(received);
traffic.Add(icmp);
traffic.Add(loopback);
traffic.Add(sent with
{
    Source = sent.Destination, SourcePort = sent.DestinationPort, Destination = sent.Source,
    DestinationPort = sent.SourcePort, Direction = TrafficDirection.Inbound, Length = 80,
});
time.Advance(TimeSpan.FromSeconds(1));
var snapshot = traffic.Snapshot(true);
Require(snapshot is { ActiveFlows: 2, InboundPackets: 2, OutboundPackets: 1, LocalPackets: 1, UnknownPackets: 1,
    UploadBytesPerSecond: 900, DownloadBytesPerSecond: 128, SessionBytes: 2828 }, "counts, rates and direction buckets");
Require(snapshot.RecentFlows.Single(flow => flow.Endpoint.Protocol == "TCP") is
    { Packets: 2, SentBytes: 900, ReceivedBytes: 80 }, "one normalized bidirectional flow");
Require(traffic.Snapshot(false) is { ActiveFlows: 0, UploadBytesPerSecond: 0, SessionBytes: 2828 },
    "stopped capture retains totals and clears rates");
time.Advance(TimeSpan.FromMinutes(3));
traffic.ExpireIdleFlows();
Require(traffic.Snapshot(true) is { ActiveFlows: 0, UniqueRemoteIps: 2 }, "flow expiry preserves session destination count");

var stress = new TrafficAccumulator(time);
var stressTimer = System.Diagnostics.Stopwatch.StartNew();
for (var i = 0; i < 100_000; i++)
{
    var remote = $"2001:db8::{i:x}";
    stress.Add(sent with { Destination = remote, Timestamp = time.GetUtcNow() });
}
Console.WriteLine($"100,000 metadata updates took {stressTimer.Elapsed.TotalMilliseconds:N0} ms.");
Require(stress.Snapshot(true) is
    { ActiveFlows: 4096, UniqueRemoteIps: 4096, RemoteIpLimitReached: true, FlowCapacityMisses: 95904,
      OutboundPackets: 100000, RecentPackets.Length: 200, RecentFlows.Length: 50 }, "bounded storage at 100,000 frames");
var retained = stress.History(Guid.NewGuid(), null, null, TrafficAccumulator.HistoryLimit);
Require(retained is { Retained: 10000, NextBefore: null }
    && retained.Packets.First().Sequence == 100000 && retained.Packets.Last().Sequence == 90001, "history ring eviction order");
Console.WriteLine("Capture fixtures passed for parsing, direction, flow aggregation, rates, expiry, and capacity.");
GeoChecks.Run();
AnalysisChecks.Run(sent);
SecurityChecks.Run(sent);
ReconChecks.Run(sent);
FloodChecks.Run(sent);
DnsChecks.Run();
OutboundChecks.Run(sent);
LanChecks.Run(sent);
StorageChecks.Run(sent);
if (Environment.GetEnvironmentVariable("PNS_MEASURE_ARCHIVE") == "1") StorageChecks.MeasureArchive(sent);
if (Environment.GetEnvironmentVariable("PNS_TEST_DESKTOP_HOST") == "1") await DesktopChecks.RunAsync();

static void Require(bool condition, string check)
{
    if (!condition) throw new Exception($"Capture check failed: {check}");
}

sealed class FixtureClock : TimeProvider
{
    private TimeSpan elapsed;
    public override DateTimeOffset GetUtcNow() => DateTimeOffset.UnixEpoch.Add(elapsed);
    public override long GetTimestamp() => elapsed.Ticks;
    public override long TimestampFrequency => TimeSpan.TicksPerSecond;
    public void Advance(TimeSpan interval) => elapsed += interval;
}
