using System.Buffers.Binary;
using System.Net;
using System.Net.Security;
using PacketDotNet;
using PersonalNetworkSecurity.Capture;
using PersonalNetworkSecurity.GeoIP;

internal static class ApplicationChecks
{
    public static void Run()
    {
        var directory = Directory.CreateTempSubdirectory("pns-application-checks-").FullName;
        try
        {
            using var geo = new GeoIpDatabase(directory);
            using var store = new LocalStore(Path.Combine(directory, "app.sqlite3"));
            var geography = new CaptureGeography(geo);
            var monitor = new SecurityMonitor(geography, store);
            var rules = new AlertRules(0, 0, 0, 0, Application: new(true, true, true, true, [23]));
            Require(!monitor.SetRules(rules with { Application = new(DisallowedTcpPorts: [0]) }), "reject invalid port");
            Require(monitor.SetRules(rules), "save application rules");
            Require(new SecurityMonitor(geography, store).Settings().Rules.Application?.DisallowedTcpPorts?.Single() == 23,
                "restore application rules");

            var time = DateTimeOffset.UtcNow;
            var local = new HashSet<IPAddress> { IPAddress.Parse("192.0.2.10") };
            byte[] Frame(ReadOnlySpan<byte> payload)
            {
                var frame = new byte[40 + payload.Length];
                Convert.FromHexString("450000280001000040060000C000020AC6336414C000005000000000000000005018000000000000")
                    .CopyTo(frame, 0);
                BinaryPrimitives.WriteUInt16BigEndian(frame.AsSpan(2), (ushort)frame.Length);
                payload.CopyTo(frame.AsSpan(40));
                return frame;
            }
            PacketMetadata? Parse(byte[] frame, uint? length = null) =>
                PacketMetadataParser.Parse(LinkLayers.Raw, frame, time, length ?? (uint)frame.Length, local);

            var session = Guid.NewGuid();
            void Observe(PacketMetadata packet) => monitor.Observe(session, packet);
            int Count(string rule) => monitor.History().Count(alert => alert.Rule == rule);

            var plain = Parse(Frame("TRACE / HTTP/1.1\r\n"u8));
            Require(plain?.Application?.HttpMethod == "TRACE", "recognize visible TRACE request line");
            Require(Parse(Frame("GET / HTTP/1.1\r\n"u8))?.Application is null &&
                Parse(Frame("TRACE / HTTP/1.1"u8))?.Application is null, "ordinary and incomplete HTTP lines");
            Observe(plain!);
            Observe(plain!);
            Require(Count("suspicious-http-method") == 1, "HTTP duplicate suppression");

            var record = new byte[47];
            Convert.FromHexString("160301002A020000260301").CopyTo(record, 0);
            record[45] = 0x2f;
            var hello = Parse(Frame(record));
            Require(hello?.Application?.TlsVersion == 0x0301, "read ServerHello version");
            Require(Parse(Frame(record.AsSpan(0, 46)))?.Application is null, "ignore incomplete TLS record");
            var modern = new byte[55];
            record.CopyTo(modern, 0);
            modern[4] = 50;
            modern[8] = 46;
            modern[10] = 3;
            Convert.FromHexString("0006002B00020304").CopyTo(modern, 47);
            var modernHello = Parse(Frame(modern));
            Require(modernHello?.Application?.TlsVersion == 0x0304, "respect supported_versions extension");
            Observe(modernHello!);
            Require(Count("weak-protocol") == 0, "modern TLS stays quiet");
            Observe(hello!);
            Observe(plain! with { Application = null, DestinationPort = 23, Tcp = new(2, 100, 0) });
            Require(Count("weak-protocol") == 2, "obsolete TLS and independent port policy");

            var invalid = Frame([]);
            BinaryPrimitives.WriteUInt16BigEndian(invalid.AsSpan(2), 19);
            var malformed = Parse(invalid);
            Require(malformed?.Application?.HeaderIssue is not null, "detect IPv4 length contradiction");
            Observe(malformed!);
            Observe(malformed!);
            var truncated = Frame("ordinary payload"u8);
            Require(Parse(truncated[..40], (uint)truncated.Length)?.Application?.HeaderIssue is null &&
                Count("malformed-network-header") == 1, "distinguish capture truncation and suppress duplicate");

            monitor.ObserveCertificate(time, "example.test", "198.51.100.20", SslPolicyErrors.None, null);
            Require(Count("tls-certificate-anomaly") == 0, "valid certificate policy");
            monitor.ObserveCertificate(time, "example.test", "198.51.100.20", SslPolicyErrors.RemoteCertificateChainErrors, "expired");
            monitor.ObserveCertificate(time, "example.test", "198.51.100.20", SslPolicyErrors.RemoteCertificateChainErrors, "expired");
            Require(Count("tls-certificate-anomaly") == 1 && monitor.History().Any(alert =>
                alert.SessionId == Guid.Empty && alert.Evidence.Contains("expired")), "diagnostic alert attribution and cooldown");
            monitor.Flush();
            Require(new SecurityMonitor(geography, store).History().Any(alert => alert.Rule == "tls-certificate-anomaly"),
                "persist diagnostic alerts");
            Console.WriteLine("Application checks passed for TLS versions, certificate evidence, HTTP, malformed headers, and persistence.");
        }
        finally { Directory.Delete(directory, recursive: true); }
    }

    private static void Require(bool condition, string description)
    {
        if (!condition) throw new InvalidOperationException($"Application check failed: {description}");
    }
}
