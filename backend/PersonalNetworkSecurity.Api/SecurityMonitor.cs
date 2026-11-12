using PersonalNetworkSecurity.Capture;
using PersonalNetworkSecurity.GeoIP;

internal sealed record ApplicationRules(bool CertificateAlerts = false, bool ObsoleteTls = false,
    bool HttpMethods = false, bool MalformedHeaders = false, int[]? DisallowedTcpPorts = null);
internal sealed record AlertRules(int BandwidthMiB = 50, int Destinations = 50, int SynPackets = 12,
    int RefusedAttempts = 5, int[]? Ports = null, string[]? Countries = null,
    int ScanPorts = 0, int SweepHosts = 0, int StealthProbes = 0, int UnexpectedPackets = 0,
    int ReconWindowSeconds = 10, int[]? AllowedProtocols = null,
    int FloodWindowSeconds = 10, int InboundSynRate = 0, int UdpPacketRate = 0,
    int UdpKiBRate = 0, int IcmpPacketRate = 0, int PendingConnections = 0,
    int DnsWindowSeconds = 30, int DnsTunnelingNames = 0, int DnsLabelLength = 30,
    int DnsQueries = 0, int DnsNxDomains = 0, bool DnsConflictingReplies = false,
    string[]? DnsBlockedDomains = null, string[]? DnsExcludedDomains = null, int[]? DnsAllowedTypes = null,
    OutboundRules? Outbound = null, LanRules? Lan = null, ApplicationRules? Application = null);
internal sealed record AddressRule(string Ip, string List);
internal sealed record SecurityAlert(Guid Id, Guid SessionId, DateTimeOffset ObservedAt, string Rule, string Severity,
    string State, string? RemoteIp, string Evidence);
internal sealed record AlertSummary(long Revision, int Open, SecurityAlert[] Recent, string[] FlaggedIps);
internal sealed record SecuritySettings(AlertRules Rules, AddressRule[] Addresses);

internal sealed class SecurityMonitor
{
    private const int WindowSeconds = 10;
    private const int CooldownSeconds = 30;
    private const int CounterLimit = 4096;
    private const int AlertLimit = 200;
    private readonly object gate = new();
    private readonly CaptureGeography geography;
    private readonly LocalStore? store;
    private readonly List<SecurityAlert> alerts = [];
    private readonly Dictionary<string, string> addresses = new(StringComparer.Ordinal);
    private readonly Dictionary<(string Rule, string? Ip, string? Scope), DateTimeOffset> cooldowns = new();
    private readonly HashSet<string> destinations = new(StringComparer.Ordinal);
    private readonly HashSet<string> checkedCountries = new(StringComparer.Ordinal);
    private readonly Dictionary<FlowKey, uint> pendingSyn = new();
    private readonly Dictionary<string, int> synCounts = new(StringComparer.Ordinal);
    private readonly Dictionary<string, int> refusalCounts = new(StringComparer.Ordinal);
    private readonly ReconDetection recon = new();
    private readonly FloodDetection flood = new();
    private readonly DnsDetection dns = new();
    private LanDetection? lanDetection;
    private OutboundDetection? outboundDetection;
    private AlertRules rules = new();
    private Guid session;
    private long window = -1;
    private long bytes;
    private long revision;
    private long savedRevision;

    public SecurityMonitor(CaptureGeography geography, LocalStore? store = null)
    {
        this.geography = geography;
        this.store = store;
        if (store?.ReadSetting<SecuritySettings>("security") is { } settings)
        {
            rules = settings.Rules;
            if (rules.Lan is { } lan) lanDetection = new(lan);
            if (rules.Outbound is { } configured) outboundDetection = new(configured);
            foreach (var address in settings.Addresses) addresses[address.Ip] = address.List;
        }
        if (store is not null) alerts.AddRange(store.Alerts());
    }

    public void ObserveCertificate(DateTimeOffset time, string host, string address, System.Net.Security.SslPolicyErrors errors,
        string? validity)
    {
        if (errors == System.Net.Security.SslPolicyErrors.None && validity is null) return;
        lock (gate)
        {
            if (rules.Application?.CertificateAlerts != true || addresses.GetValueOrDefault(address) == "trusted") return;
            PruneCooldowns(time);
            EmitAt(time, Guid.Empty, "tls-certificate-anomaly", "medium", address,
                $"HTTPS health check for {host} at {address} reported certificate policy status {errors}." +
                (validity is null ? "" : $" Certificate is {validity}."), host);
        }
    }

    public void Observe(Guid sessionId, PacketMetadata packet, IReadOnlySet<string>? gateways = null)
    {
        var directional = packet.Direction is TrafficDirection.Inbound or TrafficDirection.Outbound;
        if (!directional && packet.Arp is null && packet.Dhcp is null) return;
        var outbound = packet.Direction == TrafficDirection.Outbound;
        var ip = outbound ? packet.Destination : packet.Source;
        var tick = packet.Timestamp.ToUnixTimeSeconds() / WindowSeconds;
        lock (gate)
        {
            if (session != sessionId)
            {
                session = sessionId;
                cooldowns.Clear();
                recon.Reset();
                flood.Reset();
                dns.Reset();
                outboundDetection?.Reset();
                lanDetection?.Reset();
                ResetWindow(tick);
            }
            if (tick < window) return;
            if (tick > window)
            {
                ResetWindow(tick);
                PruneCooldowns(packet.Timestamp);
            }
            lanDetection?.Observe(packet, gateways, address => addresses.GetValueOrDefault(address) == "trusted",
                (rule, severity, remote, scope, evidence) => Emit(packet, rule, severity, remote, evidence, scope));
            if (!directional) return;
            addresses.TryGetValue(ip, out var list);
            if (list == "trusted") return;
            if (packet.Application?.HeaderIssue is { } issue)
            {
                if (rules.Application?.MalformedHeaders == true)
                    Emit(packet, "malformed-network-header", "low", ip,
                        $"Captured inconsistent IPv4 header fields from {packet.Source} to {packet.Destination}. {issue}.", issue);
                return;
            }
            if (rules.Application is { } application && packet.ProtocolNumber == 6)
            {
                if (application.ObsoleteTls && packet.Application?.TlsVersion is >= 0x0300 and <= 0x0302)
                    Emit(packet, "weak-protocol", "medium", ip,
                        $"Observed obsolete TLS/SSL version 0x{packet.Application.TlsVersion:X4} selected in a plaintext ServerHello.",
                        "tls");
                if (outbound && packet.Tcp is { } header && (header.Flags & 0x17) == 2 &&
                    packet.DestinationPort is { } port && application.DisallowedTcpPorts?.Contains(port) == true)
                    Emit(packet, "weak-protocol", "low", ip,
                        $"Observed an outbound TCP connection attempt to {ip} on disallowed port {port}.", $"port/{port}");
                if (application.HttpMethods && packet.Application?.HttpMethod is { } method)
                    Emit(packet, "suspicious-http-method", "low", ip,
                        $"Observed plaintext HTTP {method} from {packet.Source} to {packet.Destination}. This method can be legitimate.",
                        method);
            }
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

            recon.Observe(packet, rules, (rule, severity, evidence) => Emit(packet, rule, severity, ip, evidence));

            if (rules is { InboundSynRate: > 0 } or { UdpPacketRate: > 0 } or { UdpKiBRate: > 0 }
                or { IcmpPacketRate: > 0 } or { PendingConnections: > 0 })
                flood.Observe(packet, rules, (rule, severity, scope, evidence) =>
                    Emit(packet, rule, severity, null, evidence, scope));

            if (packet.Dns is { } message)
                dns.Observe(packet, message, rules, (rule, severity, scope, evidence) =>
                    Emit(packet, rule, severity, ip, evidence, scope));

            outboundDetection?.Observe(packet, ip, (rule, severity, scope, evidence) =>
                Emit(packet, rule, severity, rule == "threat-intel-match" && scope != ip ? null : ip, evidence, scope));

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
            || updated.ScanPorts is < 0 or > CounterLimit || updated.SweepHosts is < 0 or > CounterLimit
            || updated.StealthProbes is < 0 or > CounterLimit || updated.UnexpectedPackets is < 0 or > CounterLimit
            || updated.ReconWindowSeconds is < 1 or > 300
            || updated.AllowedProtocols is { Length: > 256 }
            || updated.AllowedProtocols?.Any(protocol => protocol is < 0 or > 255) == true
            || updated.UnexpectedPackets > 0 && updated.AllowedProtocols is not { Length: > 0 }
            || updated.FloodWindowSeconds is < 1 or > 300 || updated.InboundSynRate is < 0 or > 100000
            || updated.UdpPacketRate is < 0 or > 100000 || updated.UdpKiBRate is < 0 or > 1000000
            || updated.IcmpPacketRate is < 0 or > 100000 || updated.PendingConnections is < 0 or > CounterLimit
            || updated.DnsWindowSeconds is < 1 or > 300 || updated.DnsLabelLength is < 12 or > 63
            || updated.DnsTunnelingNames is < 0 or > CounterLimit || updated.DnsQueries is < 0 or > 100000
            || updated.DnsNxDomains is < 0 or > CounterLimit || updated.DnsAllowedTypes is { Length: > 128 }
            || updated.DnsAllowedTypes?.Any(type => type is < 1 or > 65535) == true
            || !DnsDetection.ValidDomains(updated.DnsBlockedDomains) || !DnsDetection.ValidDomains(updated.DnsExcludedDomains)
            || updated.Application?.DisallowedTcpPorts is { Length: > 128 }
            || updated.Application?.DisallowedTcpPorts?.Any(port => port is < 1 or > 65535) == true
            || updated.Lan is { } lan && !LanDetection.Valid(lan)
            || updated.Outbound is { } outbound && !OutboundDetection.Valid(outbound)
            || updated.Ports is { Length: > 32 } || updated.Ports?.Any(port => port is < 1 or > 65535) == true
            || updated.Countries is { Length: > 32 } || updated.Countries?.Any(code =>
                code is null || code.Length != 2 || !code.All(char.IsAsciiLetter)) == true) return false;
        lock (gate)
        {
            var next = updated with { Ports = updated.Ports?.Distinct().ToArray(),
                Countries = updated.Countries?.Select(code => code.ToUpperInvariant()).Distinct().ToArray(),
                AllowedProtocols = updated.AllowedProtocols?.Distinct().ToArray(),
                DnsAllowedTypes = updated.DnsAllowedTypes?.Distinct().ToArray(),
                DnsBlockedDomains = DnsDetection.NormalizeDomains(updated.DnsBlockedDomains),
                DnsExcludedDomains = DnsDetection.NormalizeDomains(updated.DnsExcludedDomains) };
            store?.SaveSetting("security", Settings() with { Rules = next });
            rules = next;
            lanDetection = next.Lan is { } lanRules ? new(lanRules) : null;
            outboundDetection = next.Outbound is { } configured ? new(configured) : null;
            ResetWindow(window);
            recon.Reset();
            flood.Reset();
            dns.Reset();
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
            if (entry.List != "none" && addresses.Count >= 256 && !addresses.ContainsKey(ip)) return false;
            if (store is not null)
            {
                var next = Settings().Addresses.Where(address => address.Ip != ip).ToList();
                if (entry.List != "none") next.Add(new(ip, entry.List));
                store.SaveSetting("security", new SecuritySettings(rules, next.ToArray()));
            }
            if (entry.List == "none") addresses.Remove(ip);
            else addresses[ip] = entry.List;
            recon.Reset();
            flood.Reset();
            dns.Reset();
            outboundDetection?.Reset();
            lanDetection?.Reset();
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
                var changed = alerts[index] with { State = state };
                if (store is not null)
                {
                    var next = alerts.ToArray();
                    next[index] = changed;
                    store.SaveAlerts(next);
                }
                alerts[index] = changed;
                revision++;
                if (store is not null) savedRevision = revision;
            }
            return true;
        }
    }

    public void Flush()
    {
        if (store is null) return;
        lock (gate)
        {
            var cutoff = store.Cutoff;
            if (alerts.RemoveAll(alert => alert.ObservedAt < cutoff) > 0) revision++;
            if (revision == savedRevision) return;
            store.SaveAlerts(alerts);
            savedRevision = revision;
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

    private void PruneCooldowns(DateTimeOffset time)
    {
        foreach (var entry in cooldowns)
            if (entry.Value <= time) cooldowns.Remove(entry.Key);
    }

    private bool CanEmit(string rule, string? ip, DateTimeOffset time, string? scope = null) =>
        cooldowns.TryGetValue((rule, ip, scope), out var until) ? time >= until : cooldowns.Count < CounterLimit;

    private void Emit(PacketMetadata packet, string rule, string severity, string? ip, string evidence, string? scope = null) =>
        EmitAt(packet.Timestamp, session, rule, severity, ip, evidence, scope);

    private void EmitAt(DateTimeOffset time, Guid sessionId, string rule, string severity, string? ip, string evidence, string? scope)
    {
        if (!CanEmit(rule, ip, time, scope)) return;
        cooldowns[(rule, ip, scope)] = time.AddSeconds(CooldownSeconds);
        if (alerts.Count == AlertLimit) alerts.RemoveAt(AlertLimit - 1);
        alerts.Insert(0, new(Guid.NewGuid(), sessionId, time, rule, severity, "open", ip, evidence));
        revision++;
    }
}
