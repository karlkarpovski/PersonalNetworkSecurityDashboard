using System.Net;
using System.Threading.Channels;
using SharpPcap;
using SharpPcap.LibPcap;

namespace PersonalNetworkSecurity.Capture;

public sealed class CaptureSession(ILiveDevice device, HashSet<IPAddress> addresses, int apiPort, int uiPort,
    Action<Guid, PacketMetadata> observe)
{
    private readonly Channel<PacketMetadata> queue = Channel.CreateBounded<PacketMetadata>(
        new BoundedChannelOptions(2048) { SingleReader = true, SingleWriter = true });
    private HashSet<IPAddress> localAddresses = addresses;
    private SocketOwners? socketOwners;
    private Task worker = Task.CompletedTask;
    private int ended;
    private long queueDrops, skipped;

    public TrafficAccumulator Traffic { get; } = new(TimeProvider.System);
    public Guid Id { get; } = Guid.NewGuid();
    public DateTimeOffset StartedAt { get; } = DateTimeOffset.UtcNow;
    public bool Ended => Volatile.Read(ref ended) != 0;
    public long QueueDrops => Interlocked.Read(ref queueDrops);
    public long Skipped => Interlocked.Read(ref skipped);
    public ICaptureStatistics? Statistics => device.Statistics;

    public void Start()
    {
        device.Open(new DeviceConfiguration { ReadTimeout = 250, Snaplen = 512 });
        if (!PacketMetadataParser.Supports(device.LinkType))
            throw new NotSupportedException("This adapter uses an unsupported link-layer format.");
        if (device.Name.EndsWith("NPF_Loopback", StringComparison.OrdinalIgnoreCase))
            device.Filter = $"not (tcp port {apiPort} or tcp port {uiPort})";

        device.OnPacketArrival += OnPacket;
        device.OnCaptureStopped += OnStopped;
        RefreshSocketOwners();
        worker = Task.Run(async () =>
        {
            await foreach (var packet in queue.Reader.ReadAllAsync())
            {
                var attributed = packet with { Owner = Volatile.Read(ref socketOwners)?.Match(packet) };
                if (attributed.Arp is null) Traffic.Add(attributed);
                observe(Id, attributed);
            }
        });
        device.StartCapture();
    }

    public void UpdateAddresses(HashSet<IPAddress> addresses) => Volatile.Write(ref localAddresses, addresses);
    public void RefreshSocketOwners() => Volatile.Write(ref socketOwners, WindowsSocketOwners.Read());

    public async Task CloseAsync()
    {
        try
        {
            if (device.Started) device.StopCapture();
        }
        finally
        {
            device.OnPacketArrival -= OnPacket;
            device.OnCaptureStopped -= OnStopped;
            queue.Writer.TryComplete();
            try { device.Dispose(); }
            finally { await worker; }
        }
    }

    private void OnStopped(object sender, CaptureStoppedEventStatus status)
    {
        Volatile.Write(ref ended, 1);
        queue.Writer.TryComplete();
    }

    private void OnPacket(object sender, PacketCapture capture)
    {
        var header = (PcapHeader)capture.Header;
        var timestamp = new DateTimeOffset(header.Timeval.Date);
        var packet = PacketMetadataParser.Parse(device.LinkType, capture.Data.ToArray(), timestamp,
            header.PacketLength, Volatile.Read(ref localAddresses));
        if (packet is null) Interlocked.Increment(ref skipped);
        else if (!queue.Writer.TryWrite(packet)) Interlocked.Increment(ref queueDrops);
    }
}
