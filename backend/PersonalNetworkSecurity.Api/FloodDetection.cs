using PersonalNetworkSecurity.Capture;

internal sealed class FloodDetection
{
    private const int Capacity = 4096;
    private readonly Dictionary<Service, Rate> rates = new();
    private readonly Dictionary<FlowKey, Handshake> pending = new();
    private readonly Dictionary<Service, int> outstanding = new();
    private long window = long.MinValue;

    public void Reset()
    {
        window = long.MinValue;
        rates.Clear();
        pending.Clear();
        outstanding.Clear();
    }

    public void Observe(PacketMetadata packet, AlertRules rules, Action<string, string, string, string> emit)
    {
        var seconds = rules.FloodWindowSeconds;
        var tick = packet.Timestamp.ToUnixTimeSeconds() / seconds;
        if (tick < window) return;
        if (tick > window)
        {
            Reset();
            window = tick;
        }

        var inbound = packet.Direction == TrafficDirection.Inbound;
        if (packet.ProtocolNumber == 6 && packet.Tcp is { } tcp &&
            packet.SourcePort is > 0 && packet.DestinationPort is > 0)
        {
            var service = new Service(inbound ? packet.Destination : packet.Source,
                inbound ? packet.DestinationPort : packet.SourcePort, 6);
            var syn = inbound && (tcp.Flags & 0x17) == 0x02;
            if (syn && rules.InboundSynRate > 0)
                Count(service, "tcp-syn-flood", "TCP SYN", rules.InboundSynRate);
            if (rules.PendingConnections > 0)
                TrackHandshake(service, tcp, inbound, syn);
        }
        else if (inbound && packet.ProtocolNumber == 17 && packet.DestinationPort is > 0 &&
                 (rules.UdpPacketRate > 0 || rules.UdpKiBRate > 0))
            Count(new(packet.Destination, packet.DestinationPort, 17), "udp-flood", "UDP",
                rules.UdpPacketRate, rules.UdpKiBRate);
        else if (inbound && (packet.ProtocolNumber is 1 or 58) && rules.IcmpPacketRate > 0)
            Count(new(packet.Destination, null, packet.ProtocolNumber), "icmp-flood", "ICMP", rules.IcmpPacketRate);

        void Count(Service service, string rule, string protocol, int packetRate, int kibRate = 0)
        {
            if (!rates.TryGetValue(service, out var rate))
            {
                if (rates.Count >= Capacity) return;
                rates.Add(service, rate = new());
            }
            if (rate.Reported) return;

            rate.Packets++;
            rate.Bytes += packet.Length;
            var packetThreshold = (long)packetRate * seconds;
            var byteThreshold = kibRate * 1024L * seconds;
            var packetHit = packetRate > 0 && rate.Packets >= packetThreshold;
            var byteHit = kibRate > 0 && rate.Bytes >= byteThreshold;
            if (!packetHit && !byteHit) return;

            rate.Reported = true;
            var threshold = packetHit ? $"{packetRate:N0} packets/s" : $"{kibRate:N0} KiB/s";
            emit(rule, "medium", service.Scope,
                $"Observed {rate.Packets:N0} inbound {protocol} packets ({rate.Bytes:N0} bytes) toward {service.Scope} " +
                $"in a {seconds}-second window. Reached the {threshold} threshold. Latest source {packet.Source}.");
        }

        void TrackHandshake(Service service, TcpEvidence tcp, bool inbound, bool syn)
        {
            var key = FlowKey.ForPacket(packet);
            if (syn)
            {
                if (pending.TryGetValue(key, out var previous))
                {
                    if (previous.ClientSequence != tcp.Sequence) pending[key] = new(tcp.Sequence, null);
                    return;
                }
                if (pending.Count >= Capacity) return;
                pending.Add(key, new(tcp.Sequence, null));
                var count = outstanding.GetValueOrDefault(service) + 1;
                outstanding[service] = count;
                if (count == rules.PendingConnections)
                    emit("connection-exhaustion", "medium", service.Scope,
                        $"Observed {count:N0} incomplete inbound TCP handshakes for {service.Scope} " +
                        $"in a {seconds}-second window (threshold {rules.PendingConnections:N0}). " +
                        $"Latest source {packet.Source}. This is an estimate from captured packets.");
                return;
            }

            if (!pending.TryGetValue(key, out var attempt)) return;
            if (!inbound && (tcp.Flags & 0x17) == 0x12 &&
                tcp.Acknowledgement == unchecked(attempt.ClientSequence + 1))
            {
                pending[key] = attempt with { ServerSequence = tcp.Sequence };
                return;
            }
            var reset = (tcp.Flags & 0x04) != 0;
            var completed = inbound && (tcp.Flags & 0x16) == 0x10 &&
                attempt.ServerSequence is { } server && tcp.Acknowledgement == unchecked(server + 1) &&
                tcp.Sequence == unchecked(attempt.ClientSequence + 1);
            if (!reset && !completed) return;

            pending.Remove(key);
            if (outstanding[service] == 1) outstanding.Remove(service);
            else outstanding[service]--;
        }
    }

    private readonly record struct Service(string Address, ushort? Port, int Protocol)
    {
        public string Scope => Port is { } port ? $"[{Address}]:{port} (IP {Protocol})" : $"{Address} (IP {Protocol})";
    }

    private readonly record struct Handshake(uint ClientSequence, uint? ServerSequence);

    private sealed class Rate
    {
        public long Packets { get; set; }
        public long Bytes { get; set; }
        public bool Reported { get; set; }
    }
}
