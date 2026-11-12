import type { LanRules } from './securityTypes';

export function lanDraft(rules?: LanRules | null) {
  return {
    arpChanges: rules?.arpChanges ?? false, gatewayChanges: rules?.gatewayChanges ?? false,
    trustedGatewayMacs: rules?.trustedGatewayMacs?.join(', ') ?? '',
    trustedDhcpServers: rules?.trustedDhcpServers?.join(', ') ?? '',
    lateralThreshold: (rules?.lateralThreshold ?? 0) as number | '',
    windowSeconds: (rules?.windowSeconds ?? 30) as number | '',
    sensitivePorts: rules?.sensitivePorts?.join(', ') ?? '',
  };
}

type LanDraft = ReturnType<typeof lanDraft>;

export function lanPayload(draft: LanDraft) {
  const items = (value: string) => value.split(',').map(item => item.trim()).filter(Boolean);
  return { ...draft, trustedGatewayMacs: items(draft.trustedGatewayMacs),
    trustedDhcpServers: items(draft.trustedDhcpServers), sensitivePorts: items(draft.sensitivePorts).map(Number) };
}

export function LanFields({ draft, onChange }: { draft: LanDraft; onChange: (next: LanDraft) => void }) {
  return <fieldset className="security-form security-rule-group">
    <legend>Local network detection</legend>
    <p>Coverage depends on the selected adapter. Enter trusted DHCPv4 server IPs to enable DHCP alerts.
      Gateway monitoring uses the adapter's IPv4 gateway addresses. A blank MAC list uses the first observed ARP reply as a baseline.</p>
    <label><span><input type="checkbox" checked={draft.arpChanges}
      onChange={event => onChange({ ...draft, arpChanges: event.target.checked })} /> Flag conflicting ARP replies</span></label>
    <label><span><input type="checkbox" checked={draft.gatewayChanges}
      onChange={event => onChange({ ...draft, gatewayChanges: event.target.checked })} /> Monitor gateway MAC changes</span></label>
    <label>Trusted gateway MACs<input value={draft.trustedGatewayMacs} placeholder="Comma-separated MAC addresses"
      onChange={event => onChange({ ...draft, trustedGatewayMacs: event.target.value })} /></label>
    <label>Trusted DHCP server IPs<input value={draft.trustedDhcpServers} placeholder="Comma-separated IPv4 addresses"
      onChange={event => onChange({ ...draft, trustedDhcpServers: event.target.value })} /></label>
    <label>Internal host and port threshold<input type="number" required min={0} max={4096} value={draft.lateralThreshold}
      onChange={event => onChange({ ...draft, lateralThreshold: event.target.value === '' ? '' : Number(event.target.value) })} /></label>
    <label>Internal TCP observation window (seconds)<input type="number" required min={1} max={300} value={draft.windowSeconds}
      onChange={event => onChange({ ...draft, windowSeconds: event.target.value === '' ? '' : Number(event.target.value) })} /></label>
    <label>Sensitive TCP ports<input value={draft.sensitivePorts} required={Number(draft.lateralThreshold) > 0} placeholder="Comma-separated, e.g. 22, 445"
      onChange={event => onChange({ ...draft, sensitivePorts: event.target.value })} /></label>
  </fieldset>;
}
