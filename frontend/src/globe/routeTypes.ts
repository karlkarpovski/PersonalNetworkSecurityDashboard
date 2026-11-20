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

export type Direction = 'outbound' | 'inbound';
export type VisibleFlow = { flow: RouteFlow; directions: Direction[] };
export const directionColors = { outbound: '#61e8ff', inbound: '#ffad69' };

export function flowDirection(flow: { inbound: number; outbound: number }) {
  if (flow.inbound && flow.outbound) return 'bidirectional';
  return flow.inbound ? 'inbound' : 'outbound';
}
