using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;

namespace PersonalNetworkSecurity.Capture;

public sealed record ProcessIdentity(uint Pid, string Name, DateTimeOffset StartedAt);
public sealed record PacketOwner(ProcessIdentity Process, string Method, string? TcpState = null);
public sealed record SocketRow(FlowKey Endpoint, uint Pid, uint State = 0);

public sealed class SocketOwners
{
    private readonly DateTimeOffset sampledAt;
    private readonly Func<uint, ProcessIdentity?> identify;
    private readonly Dictionary<FlowKey, (uint Pid, uint State)> tcp = new();
    private readonly Dictionary<(string Ip, ushort Port), uint> udp = new();
    private readonly Dictionary<uint, ProcessIdentity?> identities = new();

    public SocketOwners(DateTimeOffset sampledAt, IEnumerable<SocketRow> rows, Func<uint, ProcessIdentity?> identify)
    {
        this.sampledAt = sampledAt;
        this.identify = identify;
        foreach (var row in rows)
        {
            if (row.Endpoint.Protocol == "TCP" && row.State is >= 3 and <= 10 && row.Endpoint.RemotePort > 0)
            {
                if (!tcp.TryAdd(row.Endpoint, (row.Pid, row.State)) && tcp[row.Endpoint].Pid != row.Pid)
                    tcp[row.Endpoint] = (0, 0);
            }
            else if (row.Endpoint.Protocol == "UDP" && row.Endpoint.LocalPort is { } port)
                Add(udp, (row.Endpoint.LocalIp, port), row.Pid);
        }
    }

    private static void Add<TKey>(Dictionary<TKey, uint> table, TKey key, uint owner) where TKey : notnull
    {
        if (!table.TryAdd(key, owner) && table[key] != owner) table[key] = 0;
    }

    public PacketOwner? Match(PacketMetadata packet)
    {
        if (packet.Direction == TrafficDirection.Unknown || packet.Timestamp < sampledAt
            || packet.Timestamp - sampledAt > TimeSpan.FromSeconds(3)) return null;
        var key = FlowKey.ForPacket(packet);
        if (key.LocalPort is not { } port || key.RemotePort is null
            || IPAddress.TryParse(key.LocalIp, out var local) && local.IsIPv6LinkLocal
            || IPAddress.TryParse(key.RemoteIp, out var remote) && remote.IsIPv6LinkLocal) return null;

        uint pid;
        string method;
        string? state = null;
        if (key.Protocol == "TCP")
        {
            if (!tcp.TryGetValue(key, out var socket) || socket.Pid == 0) return null;
            pid = socket.Pid;
            method = "tcp-tuple";
            state = ((System.Net.NetworkInformation.TcpState)socket.State).ToString();
        }
        else if (key.Protocol == "UDP")
        {
            // Only an exact binding is eligible. Wildcard bindings can make ownership ambiguous.
            if (!udp.TryGetValue((key.LocalIp, port), out pid) || pid == 0
                || udp.TryGetValue(("::", port), out var wildcard6) && wildcard6 != pid
                || !key.LocalIp.Contains(':') && udp.TryGetValue(("0.0.0.0", port), out var wildcard4) && wildcard4 != pid)
                return null;
            method = "udp-binding";
        }
        else return null;

        if (!identities.TryGetValue(pid, out var identity)) identities[pid] = identity = identify(pid);
        return identity is not null && identity.Pid == pid && identity.StartedAt <= sampledAt ? new(identity, method, state) : null;
    }
}

public static class WindowsSocketOwners
{
    private const uint BufferTooSmall = 122;
    private const int MaxBuffer = 16 * 1024 * 1024;

    public static SocketOwners Read()
    {
        var sampledAt = DateTimeOffset.UtcNow;
        var rows = new List<SocketRow>();
        if (OperatingSystem.IsWindows())
        {
            ReadTable(rows, tcp: true, ipv6: false);
            ReadTable(rows, tcp: true, ipv6: true);
            var udp4 = ReadTable(rows, tcp: false, ipv6: false);
            var udp6 = ReadTable(rows, tcp: false, ipv6: true);
            if (!udp4 || !udp6) rows.RemoveAll(row => row.Endpoint.Protocol == "UDP");
        }
        return new(sampledAt, rows, Identify);
    }

    private static bool ReadTable(List<SocketRow> rows, bool tcp, bool ipv6)
    {
        var size = 0;
        var family = ipv6 ? 23 : 2;
        uint Query(IntPtr pointer, ref int length) => tcp
            ? GetExtendedTcpTable(pointer, ref length, false, family, 5, 0)
            : GetExtendedUdpTable(pointer, ref length, false, family, 1, 0);

        if (Query(IntPtr.Zero, ref size) != BufferTooSmall) return false;
        for (var attempt = 0; attempt < 3 && size is >= 4 and <= MaxBuffer; attempt++)
        {
            var allocated = size;
            var buffer = Marshal.AllocHGlobal(allocated);
            try
            {
                var result = Query(buffer, ref size);
                if (result == BufferTooSmall) continue;
                if (result != 0) return false;
                var length = tcp ? (ipv6 ? 56 : 24) : (ipv6 ? 28 : 12);
                var count = Marshal.ReadInt32(buffer);
                if (count < 0 || count > (allocated - 4) / length) return false;
                var bytes = new byte[count * length];
                Marshal.Copy(IntPtr.Add(buffer, 4), bytes, 0, bytes.Length);
                for (var offset = 0; offset < bytes.Length; offset += length)
                    rows.Add(Decode(bytes.AsSpan(offset, length), tcp, ipv6));
                return true;
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }
        return false;
    }

    private static SocketRow Decode(ReadOnlySpan<byte> row, bool tcp, bool ipv6)
    {
        var addressLength = ipv6 ? 16 : 4;
        var localOffset = tcp && !ipv6 ? 4 : 0;
        var localPort = ipv6 ? 20 : localOffset + 4;
        var local = PacketMetadataParser.Normalize(new IPAddress(row.Slice(localOffset, addressLength))).ToString();
        var port = BinaryPrimitives.ReadUInt16BigEndian(row[localPort..]);
        var pid = BinaryPrimitives.ReadUInt32LittleEndian(row[^4..]);
        if (!tcp) return new(new(local, port, "", null, "UDP"), pid);
        var remoteOffset = ipv6 ? 24 : 12;
        var remotePort = ipv6 ? 44 : 16;
        var remote = PacketMetadataParser.Normalize(new IPAddress(row.Slice(remoteOffset, addressLength))).ToString();
        var state = BinaryPrimitives.ReadUInt32LittleEndian(row[(ipv6 ? 48 : 0)..]);
        return new(new(local, port, remote, BinaryPrimitives.ReadUInt16BigEndian(row[remotePort..]), "TCP"), pid, state);
    }

    private static ProcessIdentity? Identify(uint pid)
    {
        if (pid == 0 || pid > int.MaxValue) return null;
        try
        {
            using var process = Process.GetProcessById((int)pid);
            var startedAt = new DateTimeOffset(process.StartTime.ToUniversalTime());
            return process.HasExited ? null : new(pid, process.ProcessName, startedAt);
        }
        catch (Exception error) when (error is ArgumentException or InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            return null;
        }
    }

    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    private static extern uint GetExtendedTcpTable(IntPtr table, ref int size, [MarshalAs(UnmanagedType.Bool)] bool order,
        int family, int tableClass, uint reserved);

    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    private static extern uint GetExtendedUdpTable(IntPtr table, ref int size, [MarshalAs(UnmanagedType.Bool)] bool order,
        int family, int tableClass, uint reserved);
}
