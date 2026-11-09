using System.Net;
using System.Net.Sockets;

namespace PersonalNetworkSecurity.GeoIP;

public static class IpClassifier
{
    private static readonly (IPNetwork Network, string Kind)[] SpecialV4 =
    [
        (IPNetwork.Parse("0.0.0.0/8"), "reserved"),
        (IPNetwork.Parse("10.0.0.0/8"), "private"),
        (IPNetwork.Parse("100.64.0.0/10"), "shared"),
        (IPNetwork.Parse("169.254.0.0/16"), "link-local"),
        (IPNetwork.Parse("172.16.0.0/12"), "private"),
        (IPNetwork.Parse("192.0.0.0/24"), "reserved"),
        (IPNetwork.Parse("192.0.2.0/24"), "documentation"),
        (IPNetwork.Parse("192.88.99.0/24"), "reserved"),
        (IPNetwork.Parse("192.168.0.0/16"), "private"),
        (IPNetwork.Parse("198.18.0.0/15"), "reserved"),
        (IPNetwork.Parse("198.51.100.0/24"), "documentation"),
        (IPNetwork.Parse("203.0.113.0/24"), "documentation"),
        (IPNetwork.Parse("224.0.0.0/4"), "multicast"),
        (IPNetwork.Parse("240.0.0.0/4"), "reserved"),
    ];
    private static readonly IPNetwork GlobalV6 = IPNetwork.Parse("2000::/3");
    private static readonly IPNetwork UniqueLocalV6 = IPNetwork.Parse("fc00::/7");
    private static readonly IPNetwork ProtocolAssignmentsV6 = IPNetwork.Parse("2001::/23");
    private static readonly IPNetwork SixToFour = IPNetwork.Parse("2002::/16");
    private static readonly IPNetwork DocumentationV6 = IPNetwork.Parse("2001:db8::/32");
    private static readonly IPNetwork NewDocumentationV6 = IPNetwork.Parse("3fff::/20");

    public static IPAddress? Parse(string? text)
    {
        if (string.IsNullOrWhiteSpace(text) || text.Length > 80) return null;
        var input = text.Trim();
        if (!input.Contains(':'))
        {
            var octets = input.Split('.');
            if (octets.Length != 4 || octets.Any(octet => octet.Length is < 1 or > 3
                || octet.Length > 1 && octet[0] == '0' || octet.Any(character => !char.IsAsciiDigit(character))))
                return null;
        }
        if (!IPAddress.TryParse(input, out var address)) return null;
        if (address.IsIPv4MappedToIPv6) return address.MapToIPv4();
        return address.AddressFamily == AddressFamily.InterNetworkV6 && address.ScopeId != 0
            ? new IPAddress(address.GetAddressBytes()) : address;
    }

    public static string Classify(IPAddress address)
    {
        if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
        if (IPAddress.IsLoopback(address)) return "loopback";
        if (address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any)) return "unspecified";
        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            foreach (var (network, kind) in SpecialV4)
                if (network.Contains(address)) return kind;
            return "public";
        }
        if (address.IsIPv6LinkLocal) return "link-local";
        if (address.IsIPv6Multicast) return "multicast";
        if (UniqueLocalV6.Contains(address)) return "private";
        if (DocumentationV6.Contains(address) || NewDocumentationV6.Contains(address)) return "documentation";
        return GlobalV6.Contains(address) && !ProtocolAssignmentsV6.Contains(address) && !SixToFour.Contains(address)
            ? "public" : "reserved";
    }
}
