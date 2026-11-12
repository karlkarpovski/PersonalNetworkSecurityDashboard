export type SecurityAlert = {
  id: string;
  sessionId: string;
  observedAt: string;
  rule: string;
  severity: 'informational' | 'low' | 'medium' | 'high' | 'critical';
  state: 'open' | 'acknowledged' | 'dismissed';
  remoteIp: string | null;
  evidence: string;
};

export type AlertSummary = { revision: number; open: number; recent: SecurityAlert[]; flaggedIps: string[] };
export type AddressRule = { ip: string; list: 'watch' | 'trusted' | 'block' };
export type OutboundRules = {
  beaconIntervals: number; beaconJitterPercent: number; uploadMiB: number; uploadRatio: number;
  windowSeconds: number; maxAgeDays: number; expectedPorts: number[] | null;
  approvedApps: string[] | null; approvedDestinations: string[] | null; indicators: string[] | null;
  indicatorExclusions: string[] | null; source: string | null; updatedAt: string | null;
};
export type AlertRules = {
  bandwidthMiB: number; destinations: number; synPackets: number; refusedAttempts: number;
  scanPorts: number; sweepHosts: number; stealthProbes: number; unexpectedPackets: number;
  floodWindowSeconds: number; inboundSynRate: number; udpPacketRate: number; udpKiBRate: number;
  icmpPacketRate: number; pendingConnections: number;
  dnsWindowSeconds: number; dnsTunnelingNames: number; dnsLabelLength: number;
  dnsQueries: number; dnsNxDomains: number; dnsConflictingReplies: boolean;
  dnsBlockedDomains: string[] | null; dnsExcludedDomains: string[] | null; dnsAllowedTypes: number[] | null;
  outbound?: OutboundRules | null;
  reconWindowSeconds: number; allowedProtocols: number[] | null;
  ports: number[] | null; countries: string[] | null;
};
export type SecuritySettings = { rules: AlertRules; addresses: AddressRule[] };

export const ruleNames: Record<string, string> = {
  'blocklisted-address': 'Blocklisted address', 'watched-address': 'Watched address',
  'bandwidth-threshold': 'Bandwidth threshold', 'destination-threshold': 'Distinct destination threshold',
  'monitored-port': 'Monitored port', 'monitored-country': 'Monitored country',
  'possible-beaconing': 'Possible periodic beaconing', 'potential-data-exfiltration': 'Unusual outbound transfer',
  'threat-intel-match': 'Threat intelligence match', 'unexpected-outbound-service': 'Unexpected outbound service',
  'dns-tunneling': 'Possible DNS tunneling', 'dns-blocked-domain': 'DNS denylist match',
  'dns-query-anomaly': 'DNS query anomaly', 'dns-conflicting-replies': 'Conflicting DNS replies',
  'tcp-syn-flood': 'Possible TCP SYN flood', 'udp-flood': 'Possible UDP flood',
  'icmp-flood': 'Possible ICMP flood', 'connection-exhaustion': 'Possible connection exhaustion',
  'port-scan': 'Possible port scan', 'host-discovery': 'Possible ping sweep',
  'tcp-stealth-scan': 'Unusual TCP probe flags', 'unusual-protocol': 'Unexpected IP protocol',
  'repeated-tcp-syn': 'Repeated outbound TCP SYNs', 'tcp-attempt-reset': 'TCP attempt resets',
};
