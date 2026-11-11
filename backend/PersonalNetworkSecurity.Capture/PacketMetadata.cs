using System.Net;
using PacketDotNet;

namespace PersonalNetworkSecurity.Capture;

public enum TrafficDirection { Unknown, Local, Inbound, Outbound }
public sealed record TcpEvidence(ushort Flags, uint Sequence, uint Acknowledgement);

public sealed record PacketMetadata(
    DateTimeOffset Timestamp, string Source, string Destination, ushort? SourcePort,
    ushort? DestinationPort, string Protocol, int ProtocolNumber, uint Length, TrafficDirection Direction,
    PacketOwner? Owner = null, long Sequence = 0, TcpEvidence? Tcp = null, bool IsEchoRequest = false,
    [property: System.Text.Json.Serialization.JsonIgnore] DnsEvidence? Dns = null);

public static class PacketMetadataParser
{
    public static bool Supports(LinkLayers link) =>
        link is LinkLayers.Ethernet or LinkLayers.Null or LinkLayers.Raw or LinkLayers.RawLegacy;

    public static PacketMetadata? Parse(LinkLayers link, byte[] data, DateTimeOffset timestamp,
        uint length, IReadOnlySet<IPAddress> localAddresses)
    {
        if (!Supports(link)) return null;

        try
        {
            var ip = Packet.ParsePacket(link, data).Extract<IPPacket>();
            if (ip is null) return null;
            var source = Normalize(ip.SourceAddress);
            var destination = Normalize(ip.DestinationAddress);
            var protocol = (int)ip.Protocol;
            // Leave ports blank on fragments without a transport header. For IPv6,
            // conservatively omit ports on any packet carrying a fragment header.
            var fragment = ip is IPv4Packet { FragmentOffset: > 0 }
                || ip is IPv6Packet ipv6 && ipv6.ExtensionHeaders.Any(header =>
                    header.Header == ProtocolType.IPv6FragmentHeader);
            var transport = (protocol is 6 or 17) && !fragment ? ip.PayloadPacket : null;
            var ports = transport switch
                {
                    TcpPacket tcp => (tcp.SourcePort, tcp.DestinationPort),
                    UdpPacket udp => (udp.SourcePort, udp.DestinationPort),
                    _ => ((ushort?)null, (ushort?)null)
                };
            return new(timestamp, source.ToString(), destination.ToString(), ports.Item1, ports.Item2,
                protocol switch { 6 => "TCP", 17 => "UDP", 1 => "ICMP", 58 => "ICMPv6", _ => $"IP {protocol}" },
                protocol, length, Classify(source, destination, localAddresses),
                Tcp: transport is TcpPacket tcpHeader ? new(tcpHeader.Flags, tcpHeader.SequenceNumber, tcpHeader.AcknowledgmentNumber) : null,
                IsEchoRequest: !fragment && (protocol is 1 or 58)
                    && (ip.PayloadPacket?.Bytes ?? ip.PayloadData) is { Length: >= 8 } icmp
                    && icmp[0] == (protocol == 1 ? 8 : 128) && icmp[1] == 0,
                Dns: transport is UdpPacket dns && (dns.SourcePort == 53 || dns.DestinationPort == 53)
                    && dns.Length >= 8 && dns.PayloadData is { } payload && payload.Length >= dns.Length - 8
                    ? DnsMetadataParser.Parse(payload.AsSpan(0, dns.Length - 8)) : null);
        }
        catch (Exception ex) when (ex is ArgumentException or IndexOutOfRangeException or InvalidOperationException
            or NotImplementedException or NotSupportedException or System.IO.IOException)
        {
            // A truncated or unsupported frame must not stop the capture thread.
            return null;
        }
    }

    public static IPAddress Normalize(IPAddress address)
    {
        if (address.IsIPv4MappedToIPv6) return address.MapToIPv4();
        if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 && address.ScopeId != 0)
            return new IPAddress(address.GetAddressBytes());
        return address;
    }

    private static TrafficDirection Classify(IPAddress source, IPAddress destination, IReadOnlySet<IPAddress> addresses)
    {
        var sourceLocal = addresses.Contains(source) || IPAddress.IsLoopback(source);
        var destinationLocal = addresses.Contains(destination) || IPAddress.IsLoopback(destination);
        return (sourceLocal, destinationLocal) switch
        {
            (true, true) => TrafficDirection.Local,
            (true, false) => TrafficDirection.Outbound,
            (false, true) => TrafficDirection.Inbound,
            _ => TrafficDirection.Unknown
        };
    }
}
