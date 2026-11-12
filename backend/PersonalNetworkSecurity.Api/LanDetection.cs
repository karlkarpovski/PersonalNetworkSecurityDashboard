using PersonalNetworkSecurity.Capture;
using PersonalNetworkSecurity.GeoIP;

internal sealed record LanRules(bool ArpChanges = false, bool GatewayChanges = false,
    string[]? TrustedGatewayMacs = null, string[]? TrustedDhcpServers = null,
    int LateralThreshold = 0, int WindowSeconds = 30, int[]? SensitivePorts = null);

internal sealed class LanDetection(LanRules rules)
{
    private const int Capacity = 4096;
    private readonly Dictionary<string, string> arpBindings = new(StringComparer.Ordinal);
    private readonly Dictionary<string, HashSet<(string Target, ushort Port)>> attempts = new(StringComparer.Ordinal);
    private readonly HashSet<string> gatewayMacs = (rules.TrustedGatewayMacs ?? []).Select(NormalizeMac).ToHashSet(StringComparer.Ordinal);
    private readonly HashSet<string> dhcpServers = (rules.TrustedDhcpServers ?? [])
        .Select(server => IpClassifier.Parse(server)?.ToString()).OfType<string>().ToHashSet(StringComparer.Ordinal);
    private long window = long.MinValue;
    private int attemptCount;

    public static bool Valid(LanRules rules) =>
        rules.WindowSeconds is >= 1 and <= 300 && rules.LateralThreshold is >= 0 and <= Capacity
        && (rules.TrustedGatewayMacs is null || rules.TrustedGatewayMacs.Length <= 32 &&
            rules.TrustedGatewayMacs.All(value => value is not null && NormalizeMac(value) is { Length: 12 } mac &&
                mac.All(char.IsAsciiHexDigit) && mac[1] is '0' or '2' or '4' or '6' or '8' or 'A' or 'C' or 'E' &&
                mac.Any(character => character != '0')))
        && (rules.TrustedDhcpServers is null || rules.TrustedDhcpServers.Length <= 32 &&
            rules.TrustedDhcpServers.All(value => IpClassifier.Parse(value) is { } ip &&
                ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork && !ip.Equals(System.Net.IPAddress.Any)))
        && (rules.SensitivePorts is null || rules.SensitivePorts.Length <= 128 &&
            rules.SensitivePorts.All(port => port is >= 1 and <= 65535))
        && (rules.LateralThreshold == 0 || rules.SensitivePorts is { Length: > 0 });

    private static string NormalizeMac(string value) =>
        value.Trim().Replace(":", "").Replace("-", "").ToUpperInvariant();

    public void Reset()
    {
        arpBindings.Clear();
        attempts.Clear();
        window = long.MinValue;
        attemptCount = 0;
    }

    public void Observe(PacketMetadata packet, IReadOnlySet<string>? gateways, Func<string, bool> trusted,
        Action<string, string, string?, string?, string> emit)
    {
        if (packet.Arp is { } arp && !trusted(arp.Address))
        {
            var gateway = rules.GatewayChanges && gateways?.Contains(arp.Address) == true;
            if (!gateway && !rules.ArpChanges) return;
            arpBindings.TryGetValue(arp.Address, out var previous);
            if (previous is not null || arpBindings.Count < Capacity) arpBindings[arp.Address] = arp.Mac;
            if (gateway && gatewayMacs.Count > 0)
            {
                if (!gatewayMacs.Contains(arp.Mac))
                    emit("gateway-mac-change", "high", arp.Address, arp.Mac,
                        $"ARP reply for adapter gateway {arp.Address} advertised {arp.Mac}, outside the trusted gateway MAC list.");
            }
            else if (previous is not null && previous != arp.Mac)
                emit(gateway ? "gateway-mac-change" : "possible-arp-spoofing", "medium", arp.Address, arp.Mac,
                    $"Observed conflicting ARP replies for {arp.Address}. Previous MAC {previous}, latest {arp.Mac}, " +
                    $"reply target {arp.Target}. Device replacement or failover can also cause this change.");
            return;
        }

        if (packet.Dhcp is { } dhcp && dhcpServers.Count > 0 &&
            !dhcpServers.Contains(dhcp.Server) && !trusted(dhcp.Server))
            emit("unexpected-dhcp-server", "medium", dhcp.Server, null,
                $"Observed a DHCPv4 {(dhcp.MessageType == 2 ? "offer" : "acknowledgment")} with unexpected server identifier " +
                $"{dhcp.Server}. Packet source {packet.Source}, destination {packet.Destination}.");

        if (rules.LateralThreshold == 0 || packet.Direction is not (TrafficDirection.Outbound or TrafficDirection.Inbound)
            || packet.ProtocolNumber != 6 || packet.Tcp is not { } tcp || (tcp.Flags & 0x17) != 2
            || packet.SourcePort is not > 0 || packet.DestinationPort is not { } port ||
            rules.SensitivePorts?.Contains(port) != true || trusted(packet.Source) || trusted(packet.Destination)
            || !Internal(packet.Source) || !Internal(packet.Destination)) return;

        var tick = packet.Timestamp.ToUnixTimeSeconds() / rules.WindowSeconds;
        if (tick < window) return;
        if (tick > window)
        {
            attempts.Clear();
            attemptCount = 0;
            window = tick;
        }
        if (attemptCount >= Capacity) return;
        if (!attempts.TryGetValue(packet.Source, out var targets)) attempts.Add(packet.Source, targets = []);
        if (!targets.Add((packet.Destination, port))) return;
        attemptCount++;
        if (targets.Count == rules.LateralThreshold)
            emit("possible-lateral-movement", "medium",
                packet.Direction == TrafficDirection.Inbound ? packet.Source : packet.Destination, packet.Source,
                $"Observed {targets.Count} distinct internal destination and sensitive TCP port combinations from {packet.Source} " +
                $"in a {rules.WindowSeconds}-second window (threshold {rules.LateralThreshold}). " +
                $"Latest destination {packet.Destination}, TCP port {port}.");
    }

    private static bool Internal(string value) =>
        IpClassifier.Parse(value) is { } ip && IpClassifier.Classify(ip) == "private";
}
