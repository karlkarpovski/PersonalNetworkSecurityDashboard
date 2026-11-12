using System.Buffers.Binary;
using System.Net;

namespace PersonalNetworkSecurity.Capture;

public sealed record ApplicationEvidence(string? HttpMethod = null, int? TlsVersion = null, string? HeaderIssue = null);

internal static class ApplicationMetadataParser
{
    public static ApplicationEvidence? Tcp(ReadOnlySpan<byte> payload)
    {
        if (payload.StartsWith("TRACE "u8) || payload.StartsWith("CONNECT "u8))
        {
            var end = payload.IndexOf("\r\n"u8);
            if (end > 0 && (payload[..end].EndsWith(" HTTP/1.1"u8) || payload[..end].EndsWith(" HTTP/1.0"u8)))
                return new(HttpMethod: payload[0] == 'T' ? "TRACE" : "CONNECT");
        }

        if (payload.Length < 47 || payload[0] != 22 || payload[1] != 3 || payload[5] != 2) return null;
        var recordSize = Read16(payload[3..]);
        var helloSize = (payload[6] << 16) | (payload[7] << 8) | payload[8];
        if (recordSize > payload.Length - 5 || helloSize > recordSize - 4 || helloSize < 38) return null;
        var hello = payload.Slice(9, helloSize);
        var version = Read16(hello);
        var offset = 35 + hello[34] + 3;
        if (hello[34] > 32 || offset > hello.Length) return null;
        if (offset < hello.Length)
        {
            if (hello.Length - offset < 2 || Read16(hello[offset..]) != hello.Length - offset - 2) return null;
            offset += 2;
            var selected = false;
            while (offset < hello.Length)
            {
                if (hello.Length - offset < 4) return null;
                var extension = Read16(hello[offset..]);
                var size = Read16(hello[(offset + 2)..]);
                offset += 4;
                if (size > hello.Length - offset) return null;
                if (extension == 43)
                {
                    if (size != 2 || selected) return null;
                    selected = true;
                    version = Read16(hello[offset..]);
                }
                offset += size;
            }
        }
        return version is >= 0x0300 and <= 0x0304 ? new(TlsVersion: version) : null;
    }

    public static PacketMetadata? InvalidIpv4(ReadOnlySpan<byte> frame, bool ethernet, DateTimeOffset time,
        uint wireLength, IReadOnlySet<IPAddress> local)
    {
        var offset = ethernet ? 14 : 0;
        if (frame.Length < offset + 20 || wireLength < offset + 20 ||
            ethernet && Read16(frame[12..]) != 0x0800 || (frame[offset] >> 4) != 4) return null;
        var ip = frame[offset..];
        var headerLength = (ip[0] & 15) * 4;
        var totalLength = Read16(ip[2..]);
        // Check contradictions in the captured header without relying on captured payload length or checksums.
        var issue = headerLength < 20 ? "IPv4 header length below the minimum" :
            totalLength < headerLength ? "IPv4 total length below its declared header length" : null;
        if (issue is null) return null;
        var source = new IPAddress(ip.Slice(12, 4));
        var destination = new IPAddress(ip.Slice(16, 4));
        var direction = (local.Contains(source), local.Contains(destination)) switch
        {
            (true, false) => TrafficDirection.Outbound,
            (false, true) => TrafficDirection.Inbound,
            _ => TrafficDirection.Unknown
        };
        return new(time, source.ToString(), destination.ToString(), null, null, "IPv4", ip[9], wireLength, direction,
            Application: new(HeaderIssue: issue));
    }

    private static int Read16(ReadOnlySpan<byte> data) => BinaryPrimitives.ReadUInt16BigEndian(data);
}
