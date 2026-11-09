export type Location = { lat: number; lng: number };

export type RouteFlow = Location & {
  ip: string;
  city: string;
  country: string;
  protocol: string;
  port: number | null;
  outbound: number;
  inbound: number;
  flagged?: boolean;
};

export const origin = { lat: 51.51, lng: -0.13, city: 'London', country: 'United Kingdom' };

// Documentation-only addresses and fictional traffic. Coordinates are chosen for the demo.
export const demoFlows: readonly RouteFlow[] = [
  { lat: 40.71, lng: -74.01, city: 'New York', country: 'United States', ip: '192.0.2.14', protocol: 'TCP', port: 443, outbound: 190_000, inbound: 780_000 },
  { lat: 50.11, lng: 8.68, city: 'Frankfurt', country: 'Germany', ip: '198.51.100.28', protocol: 'UDP', port: 443, outbound: 370_000, inbound: 950_000 },
  { lat: 35.68, lng: 139.69, city: 'Tokyo', country: 'Japan', ip: '2001:db8::18', protocol: 'TCP', port: 443, outbound: 470_000, inbound: 2_180_000 },
  { lat: 1.35, lng: 103.82, city: 'Singapore', country: 'Singapore', ip: '203.0.113.54', protocol: 'UDP', port: 53, outbound: 18_000, inbound: 65_000 },
  { lat: -23.55, lng: -46.63, city: 'São Paulo', country: 'Brazil', ip: '198.51.100.72', protocol: 'TCP', port: 8443, outbound: 102_000, inbound: 0, flagged: true },
  { lat: -33.87, lng: 151.21, city: 'Sydney', country: 'Australia', ip: '2001:db8::44', protocol: 'ICMP', port: null, outbound: 0, inbound: 9_000 },
];

export type Direction = 'outbound' | 'inbound';
export type VisibleFlow = { flow: RouteFlow; directions: Direction[] };
export const directionColors = { outbound: '#61e8ff', inbound: '#ffad69' };

export function flowDirection(flow: { inbound: number; outbound: number }) {
  if (flow.inbound && flow.outbound) return 'bidirectional';
  return flow.inbound ? 'inbound' : 'outbound';
}
