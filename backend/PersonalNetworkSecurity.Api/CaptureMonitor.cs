using System.Net;
using System.Net.NetworkInformation;
using PersonalNetworkSecurity.Capture;
using SharpPcap;
using Microsoft.Data.Sqlite;

internal sealed record AdapterInfo(string Id, string Name, string? LinkStatus);
internal sealed record AdapterResult(AdapterInfo[] Adapters, string? Error);
internal sealed record CaptureView(Guid? SessionId, string State, string? Adapter, string? Message, TrafficSnapshot? Traffic,
    long QueueDrops, long SkippedFrames, uint? DriverDrops);

internal sealed class CaptureMonitor(ILogger<CaptureMonitor> logger, CapturePorts ports, SecurityMonitor security,
    CaptureGeography geography, LocalStore store) : BackgroundService
{
    private const string DriverMissing = "Npcap is unavailable. Install the Windows Npcap driver, then refresh adapters.";
    private readonly SemaphoreSlim gate = new(1, 1);
    private CaptureSession? current;
    private CaptureSession? previous;
    private string? activeAdapter;
    private Guid? interfaceId;
    private string state = DriverAvailable() ? "idle" : "unavailable";
    private string? message;
    private uint? driverDrops;
    private bool shuttingDown;
    private bool archivePending;
    private long savedSequence;
    private DateTimeOffset nextCheckpoint, nextPrune;

    public async Task<AdapterResult> GetAdaptersAsync()
    {
        await gate.WaitAsync();
        try
        {
            var devices = Enumerate();
            var interfaces = NetworkInterface.GetAllNetworkInterfaces();
            var adapters = devices.Select(device =>
            {
                var adapter = FindInterface(interfaces, InterfaceId(device.Name));
                return new AdapterInfo(device.Name, adapter?.Name ?? device.Description ?? device.Name,
                    adapter?.OperationalStatus.ToString());
            }).ToArray();
            if (current is null && state == "unavailable")
            {
                state = previous is null ? "idle" : "stopped";
                message = null;
            }
            return new(adapters, null);
        }
        catch (Exception ex) when (IsCaptureError(ex))
        {
            var error = Explain(ex);
            if (current is null) { state = "unavailable"; message = error; }
            return new([], error);
        }
        finally { gate.Release(); }
    }

    public async Task<(int Code, string? Error)> StartAsync(string? id)
    {
        if (string.IsNullOrWhiteSpace(id) || id.Length > 300)
            return (400, "Select a capture adapter.");
        await gate.WaitAsync();
        CaptureSession? candidate = null;
        try
        {
            if (shuttingDown) return (503, "The local service is shutting down.");
            if (current is not null) return (409, "Stop the current capture before starting another session.");
            if (archivePending)
            {
                Persist(previous, force: true);
                if (archivePending) return (503, "Local storage could not save the previous capture. Retry after checking the database.");
            }
            var device = Enumerate().FirstOrDefault(item => item.Name == id);
            if (device is null) return (404, "That adapter is no longer available. Refresh the adapter list.");

            var interfaces = NetworkInterface.GetAllNetworkInterfaces();
            var adapter = FindInterface(interfaces, InterfaceId(device.Name));
            if (adapter is not null && adapter.OperationalStatus != OperationalStatus.Up)
                return (409, "That adapter is down. Connect it before starting capture.");
            var gateways = adapter?.GetIPProperties().GatewayAddresses
                .Select(gateway => gateway.Address)
                .Where(address => address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork &&
                    !address.Equals(IPAddress.Any))
                .Select(address => address.ToString()).ToHashSet(StringComparer.Ordinal);
            candidate = new CaptureSession(device, LocalAddresses(interfaces), ports.Api, ports.Ui,
                (session, packet) => security.Observe(session, packet, gateways));
            candidate.Start();
            current = candidate;
            previous = null;
            activeAdapter = adapter?.Name ?? device.Description ?? device.Name;
            interfaceId = adapter is null ? null : InterfaceId(device.Name);
            state = "running";
            message = null;
            driverDrops = null;
            savedSequence = 0;
            nextCheckpoint = DateTimeOffset.UtcNow;
            return (204, null);
        }
        catch (Exception ex) when (IsCaptureError(ex))
        {
            if (candidate is not null) await CloseAsync(candidate);
            state = "error";
            message = Explain(ex);
            return (503, message);
        }
        finally { gate.Release(); }
    }

    public async Task StopCaptureAsync()
    {
        await gate.WaitAsync();
        try { await EndAsync(null); }
        finally { gate.Release(); }
    }

    public async Task<CaptureView> GetViewAsync(CancellationToken cancellationToken = default)
    {
        await gate.WaitAsync(cancellationToken);
        try
        {
            var session = current ?? previous;
            return new(session?.Id, state, activeAdapter, message ?? (state == "unavailable" ? DriverMissing : null),
                session?.Traffic.Snapshot(current is not null),
                session?.QueueDrops ?? 0, session?.Skipped ?? 0, driverDrops);
        }
        finally { gate.Release(); }
    }

    public async Task<PacketHistoryPage> GetHistoryAsync(string? search, long? before, int limit, Guid? sessionId,
        CancellationToken cancellationToken)
    {
        await gate.WaitAsync(cancellationToken);
        try
        {
            var session = current ?? previous;
            if (session is not null && (sessionId is null || sessionId == session.Id))
                return session.Traffic.History(session.Id, search, before, limit);
            var archived = sessionId ?? store.Sessions().FirstOrDefault()?.Id;
            return archived is { } id ? store.History(id, search, before, limit) : new(null, [], null, 0);
        }
        finally { gate.Release(); }
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(2));
        try
        {
            while (await timer.WaitForNextTickAsync(stoppingToken))
            {
                await gate.WaitAsync(stoppingToken);
                try
                {
                    Persist(current ?? (archivePending ? previous : null), force: current is null && archivePending);
                    if (current is null) continue;
                    var interfaces = NetworkInterface.GetAllNetworkInterfaces();
                    var adapter = FindInterface(interfaces, interfaceId);
                    if (current.Ended || interfaceId is not null && adapter?.OperationalStatus != OperationalStatus.Up)
                    {
                        await EndAsync("Capture stopped because the adapter disconnected or the driver reported an error.");
                        continue;
                    }
                    current.UpdateAddresses(LocalAddresses(interfaces));
                    current.RefreshSocketOwners();
                    current.Traffic.ExpireIdleFlows();
                    ReadDriverDrops(current);
                }
                catch (Exception ex) when (IsCaptureError(ex))
                {
                    await EndAsync(Explain(ex));
                }
                finally { gate.Release(); }
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { }
        finally
        {
            await gate.WaitAsync();
            try { shuttingDown = true; await EndAsync(null); Persist(archivePending ? previous : null, force: true); }
            finally { gate.Release(); }
        }
    }

    private async Task EndAsync(string? error)
    {
        if (current is not { } session) return;
        ReadDriverDrops(session);
        var closed = await CloseAsync(session);
        Persist(session, force: true);
        current = null;
        previous = session;
        message = error ?? (closed ? null : "The driver reported a problem while closing capture.");
        state = message is null ? "stopped" : "error";
    }

    private void Persist(CaptureSession? capture, bool force)
    {
        var now = DateTimeOffset.UtcNow;
        try
        {
            if (capture is not null && (force || now >= nextCheckpoint))
            {
                if (force) archivePending = true;
                var (summary, packets) = capture.Traffic.ArchiveSnapshot(savedSequence, !force);
                store.Checkpoint(capture.Id, activeAdapter ?? "Adapter", capture.StartedAt, summary, packets);
                if (packets.Length > 0) savedSequence = packets[^1].Sequence;
                archivePending = false;
                nextCheckpoint = now.AddSeconds(10);
            }
            security.Flush();
            if (now >= nextPrune)
            {
                geography.FlushCache();
                store.Prune();
                nextPrune = now.AddMinutes(1);
            }
            else if (force) geography.FlushCache();
            store.CheckpointWarning = null;
        }
        catch (SqliteException error)
        {
            store.CheckpointWarning = "A database write failed. Recent capture data may be missing from the archive.";
            logger.LogWarning("A local storage write failed with SQLite code {Code}.", error.SqliteErrorCode);
        }
    }

    private void ReadDriverDrops(CaptureSession session)
    {
        try { driverDrops = session.Statistics?.DroppedPackets ?? driverDrops; }
        catch (Exception ex) when (IsCaptureError(ex))
        {
            // Statistics are optional and can become unavailable after adapter loss.
            logger.LogDebug("The driver did not return capture statistics.");
        }
    }

    private async Task<bool> CloseAsync(CaptureSession session)
    {
        try { await session.CloseAsync(); return true; }
        catch (Exception ex) when (IsCaptureError(ex))
        {
            logger.LogWarning("The capture driver reported {ErrorType} during shutdown.", ex.GetType().Name);
            return false;
        }
    }

    private static CaptureDeviceList Enumerate()
    {
        if (!DriverAvailable())
            throw new PlatformNotSupportedException();
        var devices = CaptureDeviceList.Instance;
        devices.Refresh();
        return devices;
    }

    private static bool DriverAvailable() =>
        OperatingSystem.IsWindows() && Pcap.Version.Contains("Npcap", StringComparison.OrdinalIgnoreCase);

    private static Guid? InterfaceId(string name)
    {
        var start = name.IndexOf('{');
        return start >= 0 && Guid.TryParse(name[start..], out var id) ? id : null;
    }

    private static NetworkInterface? FindInterface(NetworkInterface[] adapters, Guid? id) => id is null ? null :
        adapters.FirstOrDefault(adapter => Guid.TryParse(adapter.Id, out var adapterId) && adapterId == id);

    private static HashSet<IPAddress> LocalAddresses(NetworkInterface[] interfaces) =>
        interfaces.Where(adapter => adapter.OperationalStatus == OperationalStatus.Up)
            .SelectMany(adapter => adapter.GetIPProperties().UnicastAddresses)
            .Select(address => PacketMetadataParser.Normalize(address.Address)).ToHashSet();

    private static bool IsCaptureError(Exception error) => error is PcapException or DllNotFoundException
        or NotSupportedException or NetworkInformationException or UnauthorizedAccessException or InvalidOperationException
        or TimeoutException or TypeInitializationException or BadImageFormatException;

    private static string Explain(Exception error) => error switch
    {
        PlatformNotSupportedException or DllNotFoundException or BadImageFormatException or TypeInitializationException =>
            DriverMissing,
        UnauthorizedAccessException => "Npcap denied access. Check the driver's administrator-only setting.",
        NotSupportedException => "This adapter uses a link-layer format that this capture engine cannot read.",
        _ => "Npcap could not access the adapter. Check that it is connected and that this process has capture permission."
    };
}
