using System.Buffers.Binary;
using System.Net;

namespace PersonalNetworkSecurity.Capture;

public sealed record ArpClaim(string Address, string Mac, string Target);
public sealed record DhcpClaim(string Server, byte MessageType);

internal static class LanMetadataParser
{
    public static ArpClaim? ArpReply(ReadOnlySpan<byte> frame)
    {
        if (frame.Length < 14) return null;
        var type = BinaryPrimitives.ReadUInt16BigEndian(frame[12..]);
        var offset = 14;
        for (var tags = 0; tags < 2 && (type is 0x8100 or 0x88a8); tags++)
        {
            if (frame.Length < offset + 4) return null;
            type = BinaryPrimitives.ReadUInt16BigEndian(frame[(offset + 2)..]);
            offset += 4;
        }
        if (type != 0x0806 || frame.Length < offset + 28) return null;
        var arp = frame[offset..];
        if (!arp[..8].SequenceEqual(new byte[] { 0, 1, 8, 0, 6, 4, 0, 2 }) ||
            !arp.Slice(8, 6).SequenceEqual(frame.Slice(6, 6)) || (arp[8] & 1) != 0 ||
            arp.Slice(8, 6).IndexOfAnyExcept((byte)0) < 0) return null;
        var address = new IPAddress(arp.Slice(14, 4));
        if (address.Equals(IPAddress.Any) || arp[14] >= 224) return null;
        return new(address.ToString(), Convert.ToHexString(arp.Slice(8, 6)), new IPAddress(arp.Slice(24, 4)).ToString());
    }

    public static DhcpClaim? DhcpReply(ReadOnlySpan<byte> payload)
    {
        if (payload.Length < 241 || payload[0] != 2 ||
            BinaryPrimitives.ReadUInt32BigEndian(payload[236..]) != 0x63825363) return null;
        byte message = 0;
        IPAddress? server = null;
        for (var offset = 240; offset < payload.Length;)
        {
            var option = payload[offset++];
            if (option == 0) continue;
            if (option == 255)
                return (message is 2 or 5) && server is not null && !server.Equals(IPAddress.Any)
                    ? new(server.ToString(), message) : null;
            if (offset == payload.Length) return null;
            var size = payload[offset++];
            if (size > payload.Length - offset) return null;
            if (option == 53)
            {
                if (size != 1 || message != 0) return null;
                message = payload[offset];
            }
            if (option == 54)
            {
                if (size != 4 || server is not null) return null;
                server = new IPAddress(payload.Slice(offset, 4));
            }
            offset += size;
        }
        return null;
    }
}
