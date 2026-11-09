using System.Net;
using PersonalNetworkSecurity.GeoIP;

internal static class GeoChecks
{
    public static void Run()
    {
        foreach (var (ip, kind) in new (string, string)[]
        {
            ("10.0.0.8", "private"), ("100.64.0.1", "shared"), ("127.0.0.2", "loopback"),
            ("169.254.0.1", "link-local"), ("224.0.0.1", "multicast"), ("198.51.100.1", "documentation"),
            ("255.255.255.255", "reserved"), ("::", "unspecified"), ("::1", "loopback"),
            ("::ffff:192.168.1.1", "private"), ("fe80::1%12", "link-local"), ("fd00::10", "private"),
            ("ff02::1", "multicast"), ("2001:db8::1", "documentation"), ("3fff::1", "documentation"),
            ("2002::1", "reserved"), ("2606:4700::1111", "public"), ("1.0.0.1", "public"),
        })
            Require(IpClassifier.Classify(IpClassifier.Parse(ip)!) == kind, $"classify {ip}");
        Require(IpClassifier.Parse("012.0.0.1") is null && IpClassifier.Parse("127.1") is null &&
            IpClassifier.Parse("hostname.invalid") is null, "reject ambiguous and invalid addresses");

        var directory = Directory.CreateTempSubdirectory("pns-geo-checks-").FullName;
        try
        {
            using var database = new GeoIpDatabase(directory);
            var london = IPAddress.Parse("81.2.69.142");
            var asnIp = IPAddress.Parse("1.0.0.1");
            var cityPath = Path.Combine(directory, "GeoLite2-City.mmdb");
            var asnPath = Path.Combine(directory, "GeoLite2-ASN.mmdb");
            Require(database.Status.City.State == "missing", "missing City state");
            Require(database.Resolve(london) is { Status: "database-unavailable", Latitude: null }, "missing database fallback");
            Require(database.Resolve(IPAddress.IPv6Loopback) is { Status: "non-public", Latitude: null }, "non-public lookup bypass");
            File.WriteAllText(cityPath, "invalid test database");
            Require(database.Reload().City.State == "invalid", "corrupt file fallback");

            if (Environment.GetEnvironmentVariable("PNS_GEO_TEST_DIR") is { Length: > 0 } fixtures)
            {
                File.Copy(Path.Combine(fixtures, "GeoLite2-ASN.mmdb"), asnPath);
                Require(database.Reload().Asn.State == "ready", "independent ASN load");
                Require(database.Resolve(asnIp) is { Status: "partial", Asn: > 0, Latitude: null }, "ASN-only result");
                File.Copy(Path.Combine(fixtures, "GeoLite2-City.mmdb"), cityPath, overwrite: true);
                Require(database.Reload().City.State == "ready", "City reload");
                Require(database.Resolve(london) is { Status: "located", CountryCode: "GB", City: "London",
                    Latitude: > 50 and < 52, Longitude: > -1 and < 1, AccuracyRadiusKm: > 0 }, "City metadata after cached miss");
                Require(database.Resolve(IPAddress.Parse("2001:218::1")) is { Status: "located", CountryCode: "JP" },
                    "IPv6 City lookup");
                File.Copy(asnPath, cityPath, overwrite: true);
                Require(database.Reload().City is { State: "ready", Warning: not null }, "keep previous reader on wrong database type");
                Require(database.Resolve(london).City == "London", "previous reader survives a failed reload");
                Console.WriteLine("MaxMind fixture checks passed for IPv4, IPv6, ASN-only data, and reader replacement.");
            }
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
        Console.WriteLine("GeoIP classification, missing files and corrupt file checks passed.");
    }

    private static void Require(bool condition, string check)
    {
        if (!condition) throw new Exception($"GeoIP check failed: {check}");
    }
}
