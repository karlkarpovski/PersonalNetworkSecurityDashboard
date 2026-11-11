using PersonalNetworkSecurity.Capture;

internal sealed class DnsDetection
{
    private const int Capacity = 4096;
    private readonly Dictionary<(FlowKey Flow, ushort Id, string Name, ushort Type), int?> transactions = new();
    private readonly Dictionary<string, (int Queries, int NxDomains)> counts = new(StringComparer.Ordinal);
    private readonly Dictionary<(string Resolver, string Suffix), HashSet<string>> labels = new();
    private int labelCount;
    private long window = long.MinValue;

    public void Reset()
    {
        transactions.Clear();
        counts.Clear();
        labels.Clear();
        labelCount = 0;
        window = long.MinValue;
    }

    public void Observe(PacketMetadata packet, DnsEvidence message, AlertRules rules,
        Action<string, string, string?, string> emit)
    {
        var query = packet.Direction == TrafficDirection.Outbound && packet.DestinationPort == 53 && !message.IsResponse;
        var reply = packet.Direction == TrafficDirection.Inbound && packet.SourcePort == 53 && message.IsResponse;
        if ((!query && !reply) || packet.ProtocolNumber != 17 || Matches(message.Name, rules.DnsExcludedDomains)) return;
        if (rules is { DnsTunnelingNames: 0, DnsQueries: 0, DnsNxDomains: 0, DnsConflictingReplies: false }
            && rules.DnsBlockedDomains is not { Length: > 0 } && rules.DnsAllowedTypes is not { Length: > 0 }) return;

        var tick = packet.Timestamp.ToUnixTimeSeconds() / rules.DnsWindowSeconds;
        if (tick < window) return;
        if (tick > window)
        {
            Reset();
            window = tick;
        }

        var resolver = query ? packet.Destination : packet.Source;
        var key = (FlowKey.ForPacket(packet), message.Transaction, message.Name, message.Type);
        var correlated = transactions.TryGetValue(key, out var previousCode);
        string Context() => $"Resolver {resolver}, question {message.Name}, record type {message.Type}.";
        if (query)
        {
            if (correlated) return;
            if (transactions.Count < Capacity) transactions.Add(key, null);

            if (Matches(message.Name, rules.DnsBlockedDomains))
                emit("dns-blocked-domain", "medium", message.Name, $"Outbound DNS lookup matched the local denylist. {Context()}");
            if (rules.DnsAllowedTypes is { Length: > 0 } types && !types.Contains(message.Type))
                emit("dns-query-anomaly", "low", "type",
                    $"Outbound DNS lookup used a record type outside the configured allowlist. {Context()}");

            var separator = message.Name.IndexOf('.');
            if (rules.DnsTunnelingNames > 0 && separator >= rules.DnsLabelLength &&
                labelCount < Capacity && HasHighEntropy(message.Name.AsSpan(0, separator)))
            {
                var suffix = message.Name[(separator + 1)..];
                var group = (resolver, suffix);
                if (!labels.TryGetValue(group, out var distinct)) labels.Add(group, distinct = new(StringComparer.Ordinal));
                if (distinct.Add(message.Name[..separator]))
                {
                    labelCount++;
                    if (distinct.Count == rules.DnsTunnelingNames)
                        emit("dns-tunneling", "medium", suffix,
                            $"Observed {distinct.Count} distinct long, high-entropy labels under {suffix} within " +
                            $"a {rules.DnsWindowSeconds}-second window. Threshold {rules.DnsTunnelingNames}, " +
                            $"minimum label length {rules.DnsLabelLength}. {Context()}");
                }
            }
        }
        else
        {
            if (!correlated) return;
            if (previousCode is { } previous)
            {
                if (rules.DnsConflictingReplies && ((previous == 0 && message.ResponseCode == 3) ||
                    (previous == 3 && message.ResponseCode == 0)))
                    emit("dns-conflicting-replies", "medium", null,
                        $"A captured query received conflicting NOERROR and NXDOMAIN replies for transaction " +
                        $"{message.Transaction} in the same {rules.DnsWindowSeconds}-second window. {Context()}");
                return;
            }
            transactions[key] = message.ResponseCode;
            if (message.ResponseCode != 3) return;
        }

        if (!counts.TryGetValue(resolver, out var count) && counts.Count >= Capacity) return;
        if (query)
        {
            if (rules.DnsQueries == 0) return;
            count.Queries++;
            if (count.Queries == rules.DnsQueries)
                emit("dns-query-anomaly", "low", "queries",
                    $"Observed {count.Queries} DNS queries in a {rules.DnsWindowSeconds}-second window. Threshold {rules.DnsQueries}. {Context()}");
        }
        else
        {
            if (rules.DnsNxDomains == 0) return;
            count.NxDomains++;
            if (count.NxDomains == rules.DnsNxDomains)
                emit("dns-query-anomaly", "low", "nxdomain",
                    $"Observed {count.NxDomains} correlated NXDOMAIN replies in a {rules.DnsWindowSeconds}-second window. " +
                    $"Threshold {rules.DnsNxDomains}. {Context()}");
        }
        counts[resolver] = count;
    }

    public static bool ValidDomains(string[]? domains) => domains is null || domains.Length <= 256 &&
        domains.All(domain => domain is not null && Normalize(domain) is { Length: > 0 and <= 253 } name &&
            name.Split('.').All(label => label.Length is > 0 and <= 63 &&
                label.All(character => char.IsAsciiLetterOrDigit(character) || character is '-' or '_')));

    public static string[]? NormalizeDomains(string[]? domains) =>
        domains?.Select(Normalize).Distinct(StringComparer.Ordinal).ToArray();

    private static string Normalize(string value) => value.Trim().TrimEnd('.').ToLowerInvariant();

    private static bool Matches(string name, string[]? domains)
    {
        if (domains is null) return false;
        foreach (var domain in domains)
        {
            if (name == domain || name.Length > domain.Length && name[^(domain.Length + 1)] == '.' &&
                name.EndsWith(domain, StringComparison.Ordinal)) return true;
        }
        return false;
    }

    private static bool HasHighEntropy(ReadOnlySpan<char> label)
    {
        Span<int> frequencies = stackalloc int[128];
        frequencies.Clear();
        foreach (var value in label)
        {
            if (value >= frequencies.Length) return false;
            frequencies[value]++;
        }
        var entropy = 0.0;
        foreach (var frequency in frequencies)
        {
            if (frequency == 0) continue;
            var probability = (double)frequency / label.Length;
            entropy -= probability * Math.Log2(probability);
        }
        return entropy >= 3.5;
    }
}
