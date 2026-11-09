import type { Flow } from '../capture/captureApi';
import type { GeoResult } from '../geo/geoTypes';

type LiveEndpoint = {
  ip: string;
  location?: GeoResult;
  inbound: number;
  outbound: number;
  packets: number;
  protocols: Set<string>;
  ports: Set<number>;
};

export function groupEndpoints(flows: Flow[], locations: GeoResult[], protocol: string) {
  const geography = new Map(locations.map(result => [result.ip, result]));
  const endpoints = new Map<string, LiveEndpoint>();
  for (const flow of flows) {
    const { remoteIp: ip, remotePort, protocol: observed } = flow.endpoint;
    if (protocol !== 'all' && observed !== protocol && !(protocol === 'ICMP' && observed === 'ICMPv6')) continue;
    let endpoint = endpoints.get(ip);
    if (!endpoint) {
      endpoint = { ip, location: geography.get(ip), inbound: 0, outbound: 0, packets: 0, protocols: new Set(), ports: new Set() };
      endpoints.set(ip, endpoint);
    }
    endpoint.inbound += flow.receivedBytes;
    endpoint.outbound += flow.sentBytes;
    endpoint.packets += flow.packets;
    endpoint.protocols.add(observed);
    if (remotePort !== null) endpoint.ports.add(remotePort);
  }
  return [...endpoints.values()].sort((left, right) =>
    (right.inbound + right.outbound) - (left.inbound + left.outbound) || left.ip.localeCompare(right.ip));
}
