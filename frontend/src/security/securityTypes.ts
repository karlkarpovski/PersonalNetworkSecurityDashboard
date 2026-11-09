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
export type AlertRules = {
  bandwidthMiB: number; destinations: number; synPackets: number; refusedAttempts: number;
  ports: number[] | null; countries: string[] | null;
};
export type SecuritySettings = { rules: AlertRules; addresses: AddressRule[] };

export const ruleNames: Record<string, string> = {
  'blocklisted-address': 'Blocklisted address', 'watched-address': 'Watched address',
  'bandwidth-threshold': 'Bandwidth threshold', 'destination-threshold': 'Distinct destination threshold',
  'monitored-port': 'Monitored port', 'monitored-country': 'Monitored country',
  'repeated-tcp-syn': 'Repeated outbound TCP SYNs', 'tcp-attempt-reset': 'TCP attempt resets',
};
