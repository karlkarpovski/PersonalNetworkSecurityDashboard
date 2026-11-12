using System.Buffers.Binary;
using System.Net;
using PacketDotNet;
using PersonalNetworkSecurity.Capture;
using PersonalNetworkSecurity.GeoIP;

internal static class LanChecks
{
    public static void Run(PacketMetadata packet)
    {
        var directory = Directory.CreateTempSubdirectory("pns-lan-checks-").FullName;
        try
        {
            using var geo = new GeoIpDatabase(directory);
            using var store = new LocalStore(Path.Combine(directory, "lan.sqlite3"));
            var geography = new CaptureGeography(geo);
            var monitor = new SecurityMonitor(geography, store);
            var rules = new AlertRules(0, 0, 0, 0, Lan: new(true, true,
                ["02:00:00:00:00:01", "02:00:00:00:00:02"], ["192.168.1.2"], 2, 10, [22, 445]));
            Require(!monitor.SetRules(rules with { Lan = rules.Lan! with { TrustedGatewayMacs = ["invalid"] } }),
                "reject invalid trusted MAC");
            Require(monitor.SetRules(rules), "save local network settings");
            Require(new SecurityMonitor(geography, store).Settings().Rules.Lan?.LateralThreshold == 2, "restore local network settings");

            var time = DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 10 * 10);
            var local = new HashSet<IPAddress> { IPAddress.Parse("192.168.1.10") };
            PacketMetadata? Parse(byte[] frame, LinkLayers link = LinkLayers.Ethernet) =>
                PacketMetadataParser.Parse(link, frame, time, (uint)frame.Length, local);
            byte[] Arp(string mac, string sender, string type = "0806") => Convert.FromHexString(
                "020000000010" + mac + type + "0001080006040002" + mac + sender + "020000000010C0A8010A");
            var first = Parse(Arp("020000000001", "C0A80104"));
            var other = Parse(Arp("020000000003", "C0A80104", "810000010806"));
            Require(first?.Arp is { Address: "192.168.1.4", Mac: "020000000001" } &&
                other?.Arp?.Mac == "020000000003", "parse Ethernet and VLAN ARP replies");
            Require(Parse(Arp("020000000001", "C0A80104")[..^1])?.Arp is null, "ignore truncated ARP");

            var session = Guid.NewGuid();
            var gateways = new HashSet<string> { "192.168.1.1" };
            void Observe(PacketMetadata item) => monitor.Observe(session, item, gateways);
            int Count(string rule) => monitor.History().Count(alert => alert.Rule == rule);
            Observe(first!);
            Observe(first!);
            Require(Count("possible-arp-spoofing") == 0, "same ARP mapping");
            Observe(other!);
            Observe(other!);
            Require(Count("possible-arp-spoofing") == 1, "ARP conflict and suppression");
            Observe(Parse(Arp("020000000001", "C0A80101"))!);
            Observe(Parse(Arp("020000000002", "C0A80101"))!);
            Require(Count("gateway-mac-change") == 0, "trusted gateway failover");
            Observe(Parse(Arp("020000000003", "C0A80101"))!);
            Require(Count("gateway-mac-change") == 1, "unexpected gateway MAC");

            byte[] Dhcp(byte server, byte message)
            {
                var raw = new byte[278];
                Convert.FromHexString("450001160001000040110000C0A80102FFFFFFFF0043004401020000").CopyTo(raw, 0);
                raw[28] = 2;
                BinaryPrimitives.WriteUInt32BigEndian(raw.AsSpan(264), 0x63825363);
                byte[] options = [53, 1, message, 54, 4, 192, 168, 1, server, 255];
                options.CopyTo(raw, 268);
                return raw;
            }
            var offer = Parse(Dhcp(2, 2), LinkLayers.Raw);
            var ack = Parse(Dhcp(3, 5), LinkLayers.Raw);
            Require(offer is { Direction: TrafficDirection.Unknown, Dhcp: { Server: "192.168.1.2", MessageType: 2 } }
                && ack?.Dhcp?.MessageType == 5, "parse broadcast DHCP offer and acknowledgment");
            Require(Parse(Dhcp(3, 5)[..^1], LinkLayers.Raw)?.Dhcp is null &&
                Parse(Dhcp(3, 6), LinkLayers.Raw)?.Dhcp is null, "ignore truncated and unrelated DHCP replies");
            Observe(offer!);
            Observe(ack!);
            Observe(ack!);
            Require(Count("unexpected-dhcp-server") == 1, "DHCP allowlist and suppression");

            var syn = packet with { Timestamp = time, Source = "192.168.1.10", Destination = "192.168.1.5",
                Direction = TrafficDirection.Outbound, ProtocolNumber = 6, DestinationPort = 445,
                SourcePort = 50000, Tcp = new(2, 1, 0) };
            Observe(syn);
            Observe(syn);
            Observe(syn with { Destination = "203.0.113.1" });
            Observe(syn with { Destination = "192.168.1.6", DestinationPort = 80 });
            Require(Count("possible-lateral-movement") == 0, "retries, unrelated ports, and non-private targets");
            Observe(syn with { Timestamp = time.AddSeconds(10), Destination = "192.168.1.6" });
            Require(Count("possible-lateral-movement") == 0, "expire internal access observations");
            Observe(syn with { Timestamp = time.AddSeconds(10), DestinationPort = 22 });
            Require(Count("possible-lateral-movement") == 1, "distinct internal sensitive services");
            monitor.Flush();
            Require(new SecurityMonitor(geography, store).History().Any(alert => alert.Rule == "unexpected-dhcp-server"),
                "persist local network alerts");
            Console.WriteLine("Local network checks passed for wire parsing, baselines, failover, DHCP and internal TCP alerts.");
        }
        finally { Directory.Delete(directory, recursive: true); }
    }

    private static void Require(bool condition, string description)
    {
        if (!condition) throw new InvalidOperationException($"Local network check failed: {description}");
    }
}
