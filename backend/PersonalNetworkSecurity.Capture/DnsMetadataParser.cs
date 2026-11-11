using System.Buffers.Binary;
using System.Text;

namespace PersonalNetworkSecurity.Capture;

public sealed record DnsEvidence(ushort Transaction, bool IsResponse, int ResponseCode, string Name, ushort Type);

internal static class DnsMetadataParser
{
    public static DnsEvidence? Parse(ReadOnlySpan<byte> data)
    {
        if (data.Length < 17 || (data[2] & 0x78) != 0 || (data[2] & 0x02) != 0 ||
            BinaryPrimitives.ReadUInt16BigEndian(data[4..]) != 1) return null;

        // The first question name starts directly after the header, with no prior name to reference.
        var name = new StringBuilder();
        var offset = 12;
        while (offset < data.Length)
        {
            var length = data[offset++];
            if (length == 0)
            {
                if (name.Length == 0 || offset + 4 > data.Length ||
                    BinaryPrimitives.ReadUInt16BigEndian(data[(offset + 2)..]) != 1) return null;
                return new(BinaryPrimitives.ReadUInt16BigEndian(data), (data[2] & 0x80) != 0,
                    data[3] & 15, name.ToString(), BinaryPrimitives.ReadUInt16BigEndian(data[offset..]));
            }
            if (length > 63 || offset + length > data.Length || name.Length + length + 1 > 254) return null;
            if (name.Length > 0) name.Append('.');
            foreach (var value in data.Slice(offset, length))
            {
                var character = (char)value;
                if (!(char.IsAsciiLetterOrDigit(character) || character is '-' or '_')) return null;
                name.Append(char.ToLowerInvariant(character));
            }
            offset += length;
        }
        return null;
    }
}
