using System.Net;
using PersonalNetworkSecurity.Capture;
using PersonalNetworkSecurity.GeoIP;

internal sealed record OutboundRules(int BeaconIntervals = 0, int BeaconJitterPercent = 15,
    int UploadMiB = 0, int UploadRatio = 4, int WindowSeconds = 60,
    int[]? ExpectedPorts = null, string[]? ApprovedApps = null, string[]? ApprovedDestinations = null,
    string[]? Indicators = null, string[]? IndicatorExclusions = null, string? Source = null,
    DateTimeOffset? UpdatedAt = null, int MaxAgeDays = 30);

internal sealed class OutboundDetection(OutboundRules rules)
{
    private const int Capacity = 4096;
    private readonly Dictionary<string, Transfer> transfers = new(StringComparer.Ordinal);
    private readonly HashSet<string> seen = new(StringComparer.Ordinal);
    private readonly Dictionary<(string Ip, ushort Port), Cadence> cadences = new();
    private readonly Indicators intel = new(rules.Indicators);
    private readonly Indicators exclusions = new(rules.IndicatorExclusions);
    private readonly HashSet<string> approvedDestinations = (rules.ApprovedDestinations ?? [])
        .Select(value => IpClassifier.Parse(value)?.ToString()).OfType<string>().ToHashSet(StringComparer.Ordinal);
    private DateTimeOffset nextCadenceCleanup;
    private long window = long.MinValue;

    public static bool Valid(OutboundRules rules) =>
        rules.BeaconIntervals is 0 or >= 3 and <= 32 && rules.BeaconJitterPercent is >= 1 and <= 50
        && rules.UploadMiB is >= 0 and <= 100000 && rules.UploadRatio is >= 1 and <= 100
        && rules.WindowSeconds is >= 1 and <= 300 && rules.MaxAgeDays is >= 1 and <= 365
        && (rules.ExpectedPorts is null || rules.ExpectedPorts.Length <= 256 &&
            rules.ExpectedPorts.All(port => port is >= 1 and <= 65535))
        && ValidList(rules.ApprovedApps, value => value.Length <= 128)
        && ValidList(rules.ApprovedDestinations, value => IpClassifier.Parse(value) is not null)
        && ValidList(rules.Indicators, Indicators.ValidEntry) && ValidList(rules.IndicatorExclusions, Indicators.ValidEntry)
        && (rules.Source is null || rules.Source.Length <= 120 && !rules.Source.Any(char.IsControl))
        && (rules.Indicators is not { Length: > 0 } ||
            !string.IsNullOrWhiteSpace(rules.Source) && rules.UpdatedAt is { } updated && updated <= DateTimeOffset.UtcNow);

    private static bool ValidList(string[]? values, Func<string, bool> valid) =>
        values is null || values.Length <= 256 &&
        values.All(value => !string.IsNullOrWhiteSpace(value) && !value.Any(char.IsControl) && valid(value.Trim()));

    public void Reset()
    {
        transfers.Clear();
        seen.Clear();
        cadences.Clear();
        nextCadenceCleanup = default;
        window = long.MinValue;
    }

    public void Observe(PacketMetadata packet, string ip, Action<string, string, string?, string> emit)
    {
        var outbound = packet.Direction == TrafficDirection.Outbound;
        var syn = outbound && packet.ProtocolNumber == 6 && packet.SourcePort is > 0 &&
            packet.Tcp is { } tcp && (tcp.Flags & 0x17) == 0x02;
        var port = packet.DestinationPort.GetValueOrDefault();

        if (outbound && rules.Indicators is { Length: > 0 } && rules.UpdatedAt is { } updated &&
            packet.Timestamp >= updated && packet.Timestamp - updated <= TimeSpan.FromDays(rules.MaxAgeDays))
        {
            var domain = packet.Dns is { IsResponse: false } question && packet.ProtocolNumber == 17 && port == 53
                ? question.Name : null;
            var address = IpClassifier.Parse(ip);
            if (address is not null && !exclusions.Matches(address) && (domain is null || !exclusions.Matches(domain)))
            {
                var matched = domain is not null && intel.Matches(domain) ? domain : intel.Matches(address) ? ip : null;
                if (matched is not null)
                    emit("threat-intel-match", "high", matched,
                        $"Observed outbound traffic matching indicator {matched}. Source {rules.Source}, snapshot dated {updated:yyyy-MM-dd}. " +
                        (matched == ip ? $"Remote address {ip}." : $"DNS question via resolver {ip}."));
            }
        }

        var approved = approvedDestinations.Contains(ip)
            || packet.Owner is { } owner && rules.ApprovedApps?.Contains(owner.Process.Name, StringComparer.OrdinalIgnoreCase) == true;
        if (approved) return;

        if (port > 0 && (syn || outbound && packet.ProtocolNumber == 17) &&
            rules.ExpectedPorts is { Length: > 0 } expected && !expected.Contains(port))
            emit("unexpected-outbound-service", "low", $"{packet.ProtocolNumber}/{port}",
                $"Observed outbound {packet.Protocol} traffic to {ip} on port {port}, outside the configured expected service ports.");

        if (syn && port > 0 && rules.BeaconIntervals > 0)
            ObserveCadence(packet, ip, port, emit);
        if (rules.UploadMiB > 0) ObserveTransfer(packet, ip, outbound, emit);
    }

    private void ObserveCadence(PacketMetadata packet, string ip, ushort port, Action<string, string, string?, string> emit)
    {
        var key = (ip, port);
        if (!cadences.TryGetValue(key, out var cadence))
        {
            if (cadences.Count >= Capacity && packet.Timestamp >= nextCadenceCleanup)
            {
                nextCadenceCleanup = packet.Timestamp.AddMinutes(1);
                foreach (var entry in cadences)
                    if (packet.Timestamp - entry.Value.Last > TimeSpan.FromHours(1)) cadences.Remove(entry.Key);
            }
            if (cadences.Count >= Capacity) return;
            cadences.Add(key, new(packet.Timestamp, packet.SourcePort!.Value, packet.Tcp!.Sequence));
            return;
        }

        var gap = (packet.Timestamp - cadence.Last).TotalSeconds;
        if (gap <= 0 || (gap <= 3600 && cadence.SourcePort == packet.SourcePort && cadence.Sequence == packet.Tcp!.Sequence)) return;
        cadence.Last = packet.Timestamp;
        cadence.SourcePort = packet.SourcePort!.Value;
        cadence.Sequence = packet.Tcp!.Sequence;
        if (gap is < 2 or > 3600)
        {
            cadence.Count = 0;
            return;
        }

        if (cadence.Count == 0 || Math.Abs(gap - cadence.ReferenceGap) * 100 > cadence.ReferenceGap * rules.BeaconJitterPercent)
        {
            cadence.ReferenceGap = gap;
            cadence.Count = 1;
        }
        else if (cadence.Count <= rules.BeaconIntervals) cadence.Count++;

        if (cadence.Count == rules.BeaconIntervals)
            emit("possible-beaconing", "medium", port.ToString(),
                $"Observed {cadence.Count} regular TCP SYN intervals near {cadence.ReferenceGap:F1} seconds to {ip}:{port}, " +
                $"within {rules.BeaconJitterPercent}% of the reference interval. Legitimate software can connect periodically.");
    }

    private void ObserveTransfer(PacketMetadata packet, string ip, bool outbound, Action<string, string, string?, string> emit)
    {
        var tick = packet.Timestamp.ToUnixTimeSeconds() / rules.WindowSeconds;
        if (tick < window) return;
        if (tick > window)
        {
            transfers.Clear();
            window = tick;
        }
        if (!transfers.TryGetValue(ip, out var transfer))
        {
            if (transfers.Count >= Capacity) return;
            var firstSeen = !seen.Contains(ip) && seen.Count < Capacity;
            if (firstSeen) seen.Add(ip);
            transfers.Add(ip, transfer = new(firstSeen));
        }
        if (outbound) transfer.Sent += packet.Length;
        else transfer.Received += packet.Length;
        if (!outbound || transfer.Reported || transfer.Sent < rules.UploadMiB * 1048576L ||
            transfer.Sent < transfer.Received * rules.UploadRatio) return;

        transfer.Reported = true;
        emit("potential-data-exfiltration", transfer.FirstSeen ? "medium" : "low", null,
            $"Observed {transfer.Sent:N0} outbound and {transfer.Received:N0} inbound bytes for {ip} in a " +
            $"{rules.WindowSeconds}-second window (minimum {rules.UploadMiB} MiB and {rules.UploadRatio}:1 outbound ratio)." +
            (transfer.FirstSeen ? " First observed window for this destination in the current tracking period." : ""));
    }

    private sealed class Transfer(bool firstSeen)
    {
        public bool FirstSeen { get; } = firstSeen;
        public long Sent;
        public long Received;
        public bool Reported;
    }

    private sealed class Cadence(DateTimeOffset last, ushort sourcePort, uint sequence)
    {
        public DateTimeOffset Last = last;
        public ushort SourcePort = sourcePort;
        public uint Sequence = sequence;
        public double ReferenceGap;
        public int Count;
    }

    private sealed class Indicators
    {
        private readonly HashSet<IPAddress> addresses = [];
        private readonly List<IPNetwork> networks = [];
        private readonly HashSet<string> domains = new(StringComparer.Ordinal);

        public Indicators(string[]? values)
        {
            foreach (var entry in values ?? [])
            {
                var value = entry.Trim();
                if (IpClassifier.Parse(value) is { } address) addresses.Add(address);
                else if (IPNetwork.TryParse(value, out var network)) networks.Add(network);
                else domains.Add(NormalizeDomain(value));
            }
        }

        public bool Matches(IPAddress address) => addresses.Contains(address) || networks.Any(network => network.Contains(address));

        public bool Matches(string name)
        {
            while (true)
            {
                if (domains.Contains(name)) return true;
                var dot = name.IndexOf('.');
                if (dot < 0) return false;
                name = name[(dot + 1)..];
            }
        }

        public static bool ValidEntry(string value) => IpClassifier.Parse(value) is not null || IPNetwork.TryParse(value, out _) ||
            NormalizeDomain(value) is { Length: > 0 and <= 253 } domain && domain.Contains('.') &&
            domain.Split('.').All(label => label.Length is > 0 and <= 63 &&
                label.All(character => char.IsAsciiLetterOrDigit(character) || character == '-'));

        private static string NormalizeDomain(string value) => value.TrimEnd('.').ToLowerInvariant();
    }
}
