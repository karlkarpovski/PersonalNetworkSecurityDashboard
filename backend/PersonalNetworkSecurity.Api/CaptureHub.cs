using System.Runtime.CompilerServices;
using Microsoft.AspNetCore.SignalR;

internal sealed record CaptureUpdate(long Sequence, DateTimeOffset SampledAt, CaptureView View, GeoSnapshot Geo, AlertSummary Security);

internal sealed class CaptureHub(CaptureMonitor monitor, CaptureGeography geography, SecurityMonitor security) : Hub
{
    public async IAsyncEnumerable<CaptureUpdate> Watch([EnumeratorCancellation] CancellationToken cancellationToken)
    {
        const string Subscription = "capture-stream";
        lock (Context.Items)
        {
            if (!Context.Items.TryAdd(Subscription, true))
                throw new HubException("This connection already has a capture subscription.");
        }

        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(1));
        using var lifetime = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, Context.ConnectionAborted);
        try
        {
            long sequence = 0;
            do
            {
                var view = await monitor.GetViewAsync(lifetime.Token);
                yield return new(++sequence, DateTimeOffset.UtcNow, view, geography.Snapshot(view), security.Summary());
            }
            while (await timer.WaitForNextTickAsync(lifetime.Token));
        }
        finally
        {
            lock (Context.Items) Context.Items.Remove(Subscription);
        }
    }
}
