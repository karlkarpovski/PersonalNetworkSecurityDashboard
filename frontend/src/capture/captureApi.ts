export type Direction = 'inbound' | 'outbound' | 'local' | 'unknown';
export type ProcessIdentity = { pid: number; name: string; startedAt: string };
export type Owner = { process: ProcessIdentity; method: 'tcp-tuple' | 'udp-binding'; tcpState?: string | null };
export type ApplicationTraffic = {
  process: ProcessIdentity; packets: number; sentBytes: number; receivedBytes: number;
  localBytes: number; activeFlows: number; bytesPerSecond: number;
};
export type Packet = {
  timestamp: string;
  source: string;
  destination: string;
  sourcePort: number | null;
  destinationPort: number | null;
  protocol: string;
  length: number;
  direction: Direction;
  owner?: Owner | null;
  sequence?: number;
};

export type Flow = {
  endpoint: {
    localIp: string;
    localPort: number | null;
    remoteIp: string;
    remotePort: number | null;
    protocol: string;
  };
  packets: number;
  sentBytes: number;
  receivedBytes: number;
  firstSeen: string;
  lastSeen: string;
  owner?: Owner | null;
  conflictingOwners?: boolean;
};

export type PacketHistory = { sessionId: string | null; packets: Packet[]; nextBefore: number | null; retained: number };

export type CaptureView = {
  sessionId: string | null;
  state: 'idle' | 'running' | 'stopped' | 'unavailable' | 'error';
  adapter: string | null;
  message: string | null;
  queueDrops: number;
  skippedFrames: number;
  driverDrops: number | null;
  traffic: {
    inboundPackets: number;
    outboundPackets: number;
    localPackets: number;
    unknownPackets: number;
    sessionBytes: number;
    downloadBytesPerSecond: number;
    uploadBytesPerSecond: number;
    activeFlows: number;
    uniqueRemoteIps: number;
    remoteIpLimitReached: boolean;
    flowCapacityMisses: number;
    recentPackets: Packet[];
    recentFlows: Flow[];
    packetsPerSecond: number;
    applications: ApplicationTraffic[];
    unattributedBytes: number;
  } | null;
};

export type Adapter = { id: string; name: string; linkStatus: string | null };
export type AdapterResult = { adapters: Adapter[]; error: string | null };

export class CaptureAccessDenied extends Error {}

export async function captureRequest<T>(code: string, path: string, options: RequestInit = {}): Promise<T> {
  const response = await fetch(`/api/capture/${path}`, {
    ...options,
    cache: 'no-store',
    signal: options.signal
      ? AbortSignal.any([options.signal, AbortSignal.timeout(8000)])
      : AbortSignal.timeout(8000),
    headers: { Authorization: `Bearer ${code}`, ...options.headers },
  });
  if (response.status === 401) throw new CaptureAccessDenied('The dashboard access code expired or was rejected.');
  if (!response.ok) {
    const result = await response.json().catch(() => null);
    throw new Error(result?.error ?? 'The local capture service could not complete the request.');
  }
  return response.status === 204 ? undefined as T : response.json();
}

export function formatBytes(value: number) {
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let unit = 0;
  while (value >= 1000 && unit < units.length - 1) { value /= 1000; unit++; }
  return `${value.toLocaleString(undefined, { maximumFractionDigits: unit ? 1 : 0 })} ${units[unit]}`;
}
