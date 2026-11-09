using PersonalNetworkSecurity.Capture;
using PersonalNetworkSecurity.GeoIP;

internal sealed record AlertRules(int BandwidthMiB = 50, int Destinations = 50, int SynPackets = 12,
    int RefusedAttempts = 5, int[]? Ports = null, string[]? Countries = null);
internal sealed record AddressRule(string Ip, string List);
internal sealed record SecurityAlert(Guid Id, Guid SessionId, DateTimeOffset ObservedAt, string Rule, string Severity,
    string State, string? RemoteIp, string Evidence);
internal sealed record AlertSummary(long Revision, int Open, SecurityAlert[] Recent, string[] FlaggedIps);
internal sealed record SecuritySettings(AlertRules Rules, AddressRule[] Addresses);

internal sealed class SecurityMonitor(CaptureGeography geography)
{
    private const int WindowSeconds = 10;
    private const int CooldownSeconds = 30;
    private const int CounterLimit = 4096;
    private const int AlertLimit = 200;
    private readonly object gate = new();
    private readonly List<SecurityAlert> alerts = [];
    private readonly Dictionary<string, string> addresses = new(StringComparer.Ordinal);
    private readonly Dictionary<(string Rule, string? Ip), DateTimeOffset> cooldowns = new();
    private readonly HashSet<string> destinations = new(StringComparer.Ordinal);
    private readonly HashSet<string> checkedCountries = new(StringComparer.Ordinal);
    private readonly Dictionary<FlowKey, uint> pendingSyn = new();
    private readonly Dictionary<string, int> synCounts = new(StringComparer.Ordinal);
    private readonly Dictionary<string, int> refusalCounts = new(StringComparer.Ordinal);
    private AlertRules rules = new();
    private Guid session;
    private long window = -1;
    private long bytes;
    private long revision;

    public void Observe(Guid sessionId, PacketMetadata packet)
    {
        if (packet.Direction is not (TrafficDirection.Inbound or TrafficDirection.Outbound)) return;
        var outbound = packet.Direction == TrafficDirection.Outbound;
        var ip = outbound ? packet.Destination : packet.Source;
        var tick = packet.Timestamp.ToUnixTimeSeconds() / WindowSeconds;
        lock (gate)
        {
            if (session != sessionId)
            {
                session = sessionId;
                cooldowns.Clear();
                ResetWindow(tick);
            }
            if (tick < window) return;
            if (tick > window)
            {
                ResetWindow(tick);
                foreach (var entry in cooldowns)
                    if (entry.Value <= packet.Timestamp) cooldowns.Remove(entry.Key);
            }
            addresses.TryGetValue(ip, out var list);
            if (list == "trusted") return;
            if (list is "block" or "watch" && CanEmit(list == "block" ? "blocklisted-address" : "watched-address", ip, packet.Timestamp))
                Emit(packet, list == "block" ? "blocklisted-address" : "watched-address",
                    list == "block" ? "high" : "informational", ip,
                    $"Captured {packet.Direction.ToString().ToLowerInvariant()} {packet.Protocol} traffic with {ip}, an address on your {list} list.");

            bytes += packet.Length;
            var thresholdBytes = rules.BandwidthMiB * 1024L * 1024;
            if (thresholdBytes > 0 && bytes >= thresholdBytes && CanEmit("bandwidth-threshold", null, packet.Timestamp))
                Emit(packet, "bandwidth-threshold", "medium", null,
                    $"Observed {bytes:N0} inbound and outbound bytes in a {WindowSeconds}-second window. Threshold {thresholdBytes:N0} bytes.");

            if (outbound)
            {
                if (destinations.Count < CounterLimit && destinations.Add(ip)
                    && rules.Destinations > 0 && destinations.Count >= rules.Destinations
                    && CanEmit("destination-threshold", null, packet.Timestamp))
                    Emit(packet, "destination-threshold", "medium", null,
                        $"Observed {destinations.Count} distinct outbound addresses in a {WindowSeconds}-second window. Threshold {rules.Destinations}.");
                if (packet.DestinationPort is { } port && rules.Ports?.Contains(port) == true
                    && CanEmit("monitored-port", ip, packet.Timestamp))
                    Emit(packet, "monitored-port", "low", ip, $"Captured outbound {packet.Protocol} traffic to {ip} on configured port {port}.");
                if (rules.Countries is { Length: > 0 } && checkedCountries.Count < CounterLimit && checkedCountries.Add(ip)
                    && CanEmit("monitored-country", ip, packet.Timestamp)
                    && geography.Lookup(ip)?.CountryCode is { } country && rules.Countries.Contains(country))
                    Emit(packet, "monitored-country", "low", ip, $"Local GeoIP associated outbound address {ip} with configured country code {country}. The location is approximate.");
            }

            if (packet.Tcp is not { } tcp || packet.SourcePort is null || packet.DestinationPort is null
                || (rules.SynPackets == 0 && rules.RefusedAttempts == 0)) return;
            var tuple = FlowKey.ForPacket(packet);
            if (outbound && (tcp.Flags & 0x17) == 0x02)
            {
                if (rules.RefusedAttempts > 0 && pendingSyn.Count < CounterLimit) pendingSyn[tuple] = tcp.Sequence;
                var count = Increment(synCounts, ip);
                if (rules.SynPackets > 0 && count >= rules.SynPackets && CanEmit("repeated-tcp-syn", ip, packet.Timestamp))
                    Emit(packet, "repeated-tcp-syn", "medium", ip,
                        $"Observed {count} outbound SYN packets to {ip} in a {WindowSeconds}-second window. Threshold {rules.SynPackets}. Retransmissions can contribute.");
            }
            else if (!outbound && pendingSyn.TryGetValue(tuple, out var sequence)
                && tcp.Acknowledgement == unchecked(sequence + 1))
            {
                if ((tcp.Flags & 0x12) == 0x12) pendingSyn.Remove(tuple);
                if ((tcp.Flags & 0x14) != 0x14 || !pendingSyn.Remove(tuple)) return;
                var count = Increment(refusalCounts, ip);
                if (count >= rules.RefusedAttempts && CanEmit("tcp-attempt-reset", ip, packet.Timestamp))
                    Emit(packet, "tcp-attempt-reset", "medium", ip,
                        $"Observed {count} inbound TCP RST+ACK replies matching outbound SYNs to {ip} in a {WindowSeconds}-second window. Threshold {rules.RefusedAttempts}.");
            }
        }
    }

    public SecuritySettings Settings()
    {
        lock (gate) return new(rules, addresses.OrderBy(pair => pair.Key, StringComparer.Ordinal)
            .Select(pair => new AddressRule(pair.Key, pair.Value)).ToArray());
    }

    public bool SetRules(AlertRules updated)
    {
        if (updated.BandwidthMiB is < 0 or > 100000 || updated.Destinations is < 0 or > CounterLimit
            || updated.SynPackets is < 0 or > 100000 || updated.RefusedAttempts is < 0 or > 100000
            || updated.Ports is { Length: > 32 } || updated.Ports?.Any(port => port is < 1 or > 65535) == true
            || updated.Countries is { Length: > 32 } || updated.Countries?.Any(code =>
                code is null || code.Length != 2 || !code.All(char.IsAsciiLetter)) == true) return false;
        lock (gate)
        {
            rules = updated with { Ports = updated.Ports?.Distinct().ToArray(),
                Countries = updated.Countries?.Select(code => code.ToUpperInvariant()).Distinct().ToArray() };
            ResetWindow(window);
            cooldowns.Clear();
            return true;
        }
    }

    public bool SetAddress(AddressRule entry)
    {
        if (IpClassifier.Parse(entry.Ip) is not { } address || entry.List is not ("trusted" or "watch" or "block" or "none"))
            return false;
        var ip = address.ToString();
        lock (gate)
        {
            if (entry.List == "none") addresses.Remove(ip);
            else if (addresses.Count < 256 || addresses.ContainsKey(ip)) addresses[ip] = entry.List;
            else return false;
            // Do not carry packets counted under a previous trust policy into the next evaluation.
            ResetWindow(window);
            foreach (var cooldown in cooldowns)
                if (cooldown.Key.Ip == ip) cooldowns.Remove(cooldown.Key);
            return true;
        }
    }

    public SecurityAlert[] History()
    {
        lock (gate) return alerts.ToArray();
    }

    public AlertSummary Summary()
    {
        lock (gate) return new(revision, alerts.Count(alert => alert.State == "open"), alerts.Take(10).ToArray(),
            alerts.Where(alert => alert.State == "open" && alert.Severity == "high")
                .Select(alert => alert.RemoteIp).OfType<string>().Distinct(StringComparer.Ordinal).ToArray());
    }

    public bool SetState(Guid id, string? state)
    {
        if (state is not ("acknowledged" or "dismissed")) return false;
        lock (gate)
        {
            var index = alerts.FindIndex(alert => alert.Id == id);
            if (index < 0 || alerts[index].State == "dismissed" && state != "dismissed") return false;
            if (alerts[index].State != state)
            {
                alerts[index] = alerts[index] with { State = state };
                revision++;
            }
            return true;
        }
    }

    private void ResetWindow(long tick)
    {
        window = tick;
        bytes = 0;
        destinations.Clear();
        checkedCountries.Clear();
        pendingSyn.Clear();
        synCounts.Clear();
        refusalCounts.Clear();
    }

    private static int Increment(Dictionary<string, int> counts, string ip)
    {
        if (counts.TryGetValue(ip, out var existing)) return counts[ip] = existing + 1;
        return counts.Count < CounterLimit ? counts[ip] = 1 : 0;
    }

    private bool CanEmit(string rule, string? ip, DateTimeOffset time) =>
        cooldowns.TryGetValue((rule, ip), out var until) ? time >= until : cooldowns.Count < CounterLimit;

    private void Emit(PacketMetadata packet, string rule, string severity, string? ip, string evidence)
    {
        if (!CanEmit(rule, ip, packet.Timestamp)) return;
        cooldowns[(rule, ip)] = packet.Timestamp.AddSeconds(CooldownSeconds);
        if (alerts.Count == AlertLimit) alerts.RemoveAt(AlertLimit - 1);
        alerts.Insert(0, new(Guid.NewGuid(), session, packet.Timestamp, rule, severity, "open", ip, evidence));
        revision++;
    }
}
