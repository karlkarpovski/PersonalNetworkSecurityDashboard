using PersonalNetworkSecurity.Capture;

internal sealed class ReconDetection
{
    private const int Limit = 4096;
    private readonly Dictionary<(string Source, string? Target, string Rule, int Protocol), Observations> counters = new();
    private long window = long.MinValue;
    private int samples;

    public void Reset()
    {
        window = long.MinValue;
        counters.Clear();
        samples = 0;
    }

    public void Observe(PacketMetadata packet, AlertRules rules, Action<string, string, string> emit)
    {
        if (rules.ScanPorts == 0 && rules.SweepHosts == 0 && rules.StealthProbes == 0 && rules.UnexpectedPackets == 0)
            return;

        var tick = packet.Timestamp.ToUnixTimeSeconds() / rules.ReconWindowSeconds;
        if (tick < window) return;
        if (tick > window)
        {
            Reset();
            window = tick;
        }

        if (packet.ProtocolNumber == 6 && packet.Tcp is { } tcp &&
            packet.SourcePort is { } sourcePort && packet.DestinationPort is > 0)
        {
            var flags = tcp.Flags & 0x3f;
            if (rules.ScanPorts > 0 && (flags & 0x17) == 0x02)
            {
                Count("port-scan", packet.Destination, rules.ScanPorts, "medium",
                    "distinct ports on one destination", new(null, packet.DestinationPort, null, 0));
                Count("port-scan", null, rules.ScanPorts, "medium",
                    "distinct destination and port combinations across multiple hosts", new(packet.Destination, packet.DestinationPort, null, 0),
                    requireMultipleTargets: true);
            }

            if (rules.StealthProbes > 0 && flags is 0x01 or 0x00 or 0x29)
                Count("tcp-stealth-scan", null, rules.StealthProbes, "medium",
                    "distinct probes with FIN, NULL, or XMAS flag patterns",
                    new(packet.Destination, packet.DestinationPort, sourcePort, tcp.Sequence));
        }

        if (rules.SweepHosts > 0 && packet.IsEchoRequest && packet.ProtocolNumber is 1 or 58)
            Count("host-discovery", null, rules.SweepHosts, "low",
                "distinct destinations receiving echo requests", new(packet.Destination, null, null, 0));

        if (rules.UnexpectedPackets > 0 && packet.ProtocolNumber is >= 0 and <= 255 &&
            rules.AllowedProtocols is { Length: > 0 } allowed && !allowed.Contains(packet.ProtocolNumber))
            Count("unusual-protocol", null, rules.UnexpectedPackets, "low",
                "packets outside the configured IP protocol allowlist");

        void Count(string rule, string? target, int threshold, string severity, string description,
            Sample? sample = null, bool requireMultipleTargets = false)
        {
            var key = (packet.Source, target, rule, packet.ProtocolNumber);
            if (!counters.TryGetValue(key, out var counter))
            {
                if (counters.Count >= Limit) return;
                counters.Add(key, counter = new(packet.Timestamp, packet.Destination));
            }

            if (counter.Emitted) return;

            if (sample is { } value)
            {
                counter.Distinct ??= [];
                if (samples >= Limit * 4 || !counter.Distinct.Add(value)) return;
                samples++;
            }

            counter.MultipleTargets |= packet.Destination != counter.FirstTarget;
            if (requireMultipleTargets && !counter.MultipleTargets)
            {
                counter.Count++;
                return;
            }

            if (++counter.Count < threshold) return;
            counter.Emitted = true;
            var port = packet.DestinationPort is { } destinationPort ? $", destination port {destinationPort}" : "";
            emit(rule, severity,
                $"Observed {counter.Count} {description} in a {rules.ReconWindowSeconds}-second window (threshold {threshold}). " +
                $"First observed {counter.FirstSeen:O}; latest {packet.Timestamp:O}. " +
                $"Latest packet: {packet.Source} to {packet.Destination}, IP protocol {packet.ProtocolNumber}{port}.");
        }
    }

    private readonly record struct Sample(string? Destination, ushort? Port, ushort? SourcePort, uint Sequence);

    private sealed class Observations(DateTimeOffset firstSeen, string firstTarget)
    {
        public DateTimeOffset FirstSeen { get; } = firstSeen;
        public string FirstTarget { get; } = firstTarget;
        public HashSet<Sample>? Distinct { get; set; }
        public int Count { get; set; }
        public bool MultipleTargets { get; set; }
        public bool Emitted { get; set; }
    }
}
