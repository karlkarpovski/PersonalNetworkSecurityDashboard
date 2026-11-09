using System.Net;
using System.Net.Sockets;
using PersonalNetworkSecurity.Capture;

internal static class AnalysisChecks
{
    public static void Run(PacketMetadata packet)
    {
        var time = new FixtureClock();
        time.Advance(TimeSpan.FromSeconds(10));
        var now = time.GetUtcNow();
        var process = new ProcessIdentity(42, "fixture", now.AddSeconds(-5));
        var reused = process with { StartedAt = now.AddSeconds(1) };
        var observed = packet with { Timestamp = now };
        var key = FlowKey.ForPacket(observed);
        var tcp = new SocketRow(key, process.Pid, 5);
        var match = new SocketOwners(now, [tcp], _ => process);
        Require(match.Match(observed) is { Method: "tcp-tuple", TcpState: "Established" }, "exact TCP tuple");
        Require(match.Match(observed with { DestinationPort = 444 }) is null, "TCP wrong remote port");
        Require(match.Match(observed with { Timestamp = now.AddSeconds(-1) }) is null, "pre-snapshot packet");
        Require(match.Match(observed with { Timestamp = now.AddSeconds(4) }) is null, "expired snapshot");
        Require(new SocketOwners(now, [tcp], _ => reused).Match(observed) is null, "PID reused after socket snapshot");
        Require(new SocketOwners(now, [tcp, tcp with { Pid = 43 }], _ => process).Match(observed) is null, "conflicting TCP owners");
        Require(new SocketOwners(now, [tcp with { State = 11 }], _ => process).Match(observed) is null, "TCP time-wait");
        var udp = new SocketRow(key with { RemoteIp = "", RemotePort = null, Protocol = "UDP" }, process.Pid);
        var udpPacket = observed with { Protocol = "UDP" };
        Require(new SocketOwners(now, [udp], _ => process).Match(udpPacket)?.Method == "udp-binding", "exact UDP binding");
        var wildcard = new SocketRow(udp.Endpoint with { LocalIp = "::" }, 43);
        Require(new SocketOwners(now, [udp, wildcard], _ => process).Match(udpPacket) is null, "dual-stack wildcard conflict");
        Require(new SocketOwners(now, [wildcard with { Pid = 42 }], _ => process).Match(udpPacket) is null, "wildcard-only UDP");

        var traffic = new TrafficAccumulator(time);
        traffic.Add(observed with { Owner = new(process, "tcp-tuple") });
        traffic.Add(observed with { Owner = new(reused, "tcp-tuple") });
        traffic.Add(observed);
        time.Advance(TimeSpan.FromSeconds(1));
        var snapshot = traffic.Snapshot(true);
        Require(snapshot.Applications.Length == 2 && snapshot.Applications.All(app => app.BytesPerSecond == packet.Length)
            && snapshot.UnattributedBytes == packet.Length && snapshot.PacketsPerSecond == 3, "application totals and packet rate");
        Require(snapshot.RecentFlows.Single() is { ConflictingOwners: true, Owner: null }, "flow ownership conflict");
        var session = Guid.NewGuid();
        var first = traffic.History(session, "fixture", null, 1);
        var second = traffic.History(session, "fixture", first.NextBefore, 1);
        Require(first is { Retained: 3, NextBefore: 2 } && first.Packets.Single().Sequence == 2
            && second.Packets.Single().Sequence == 1 && second.NextBefore is null, "history filters and cursor");
        Console.WriteLine("Phase 7 fixtures passed for ownership, PID reuse, rates and history paging.");
        if (OperatingSystem.IsWindows() && Environment.GetEnvironmentVariable("PNS_TEST_WINDOWS_SOCKETS") == "1")
        {
            CheckWindowsSockets(IPAddress.Loopback);
            if (Socket.OSSupportsIPv6) CheckWindowsSockets(IPAddress.IPv6Loopback);
            Console.WriteLine("Windows TCP and UDP owner tables matched real IPv4 and supported IPv6 loopback sockets.");
        }
    }

    private static void CheckWindowsSockets(IPAddress address)
    {
        using var listener = new TcpListener(address, 0);
        listener.Start();
        using var client = new TcpClient(address.AddressFamily);
        client.Connect((IPEndPoint)listener.LocalEndpoint);
        using var accepted = listener.AcceptTcpClient();
        using var udp = new UdpClient(new IPEndPoint(address, 0));
        var source = (IPEndPoint)client.Client.LocalEndPoint!;
        var destination = (IPEndPoint)client.Client.RemoteEndPoint!;
        var udpSource = (IPEndPoint)udp.Client.LocalEndPoint!;
        var owners = WindowsSocketOwners.Read();
        var tcp = new PacketMetadata(DateTimeOffset.UtcNow, address.ToString(), address.ToString(), (ushort)source.Port,
            (ushort)destination.Port, "TCP", 6, 60, TrafficDirection.Local);
        var datagram = tcp with { Protocol = "UDP", ProtocolNumber = 17, SourcePort = (ushort)udpSource.Port };
        Require(owners.Match(tcp) is { Process.Pid: var tcpPid, TcpState: "Established" }
            && tcpPid == Environment.ProcessId, $"real TCP owner for {address}");
        Require(owners.Match(datagram) is { Process.Pid: var udpPid, Method: "udp-binding" }
            && udpPid == Environment.ProcessId, $"real UDP owner for {address}");
    }

    private static void Require(bool condition, string label)
    {
        if (!condition) throw new Exception($"Analysis check failed: {label}");
    }
}
