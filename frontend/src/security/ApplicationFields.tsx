import type { ApplicationRules } from './securityTypes';

const flags = [
  { key: 'certificateAlerts', label: 'Certificate validation failures from Network Health checks' },
  { key: 'obsoleteTls', label: 'Obsolete TLS versions in visible ServerHello messages' },
  { key: 'httpMethods', label: 'Plaintext HTTP TRACE or CONNECT requests' },
  { key: 'malformedHeaders', label: 'Inconsistent IPv4 header lengths' },
] as const;

export function applicationDraft(rules?: ApplicationRules | null) {
  return {
    certificateAlerts: rules?.certificateAlerts ?? false, obsoleteTls: rules?.obsoleteTls ?? false,
    httpMethods: rules?.httpMethods ?? false, malformedHeaders: rules?.malformedHeaders ?? false,
    ports: rules?.disallowedTcpPorts?.join(', ') ?? '',
  };
}

type ApplicationDraft = ReturnType<typeof applicationDraft>;

export function applicationPayload({ ports, ...rules }: ApplicationDraft): ApplicationRules {
  return { ...rules, disallowedTcpPorts: ports.split(',').map(value => value.trim()).filter(Boolean).map(Number) };
}

export function ApplicationFields({ draft, onChange }: { draft: ApplicationDraft; onChange: (next: ApplicationDraft) => void }) {
  return <fieldset className="security-form security-rule-group">
    <legend>Application and protocol detection</legend>
    <p>Certificate alerts use the HTTPS check you initiate in Network Health. Packet rules inspect visible headers and plaintext only.</p>
    {flags.map(({ key, label }) => <label key={key}><span><input type="checkbox" checked={draft[key]}
      onChange={event => onChange({ ...draft, [key]: event.target.checked })} /> {label}</span></label>)}
    <label>Disallowed outbound TCP ports<input value={draft.ports} placeholder="Comma-separated ports"
      onChange={event => onChange({ ...draft, ports: event.target.value })} /></label>
  </fieldset>;
}
