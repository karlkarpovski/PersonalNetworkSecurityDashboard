import type { OutboundRules } from './securityTypes';

const numericFields = [
  { key: 'beaconIntervals', label: 'Regular TCP intervals (0 or 3–32)', min: 0, max: 32 },
  { key: 'beaconJitterPercent', label: 'TCP interval tolerance (%)', min: 1, max: 50 },
  { key: 'uploadMiB', label: 'Minimum outbound transfer (MiB)', min: 0, max: 100000 },
  { key: 'uploadRatio', label: 'Minimum outbound to inbound ratio', min: 1, max: 100 },
  { key: 'windowSeconds', label: 'Transfer window (seconds)', min: 1, max: 300 },
  { key: 'maxAgeDays', label: 'Indicator snapshot maximum age (days)', min: 1, max: 365 },
] as const;

const listFields = [
  { key: 'expectedPorts', label: 'Expected remote TCP and UDP ports' },
  { key: 'approvedApps', label: 'Approved process names' },
  { key: 'approvedDestinations', label: 'Approved destination IPs' },
  { key: 'indicators', label: 'Threat indicators (IP, CIDR, or domain)' },
  { key: 'indicatorExclusions', label: 'Indicator exclusions (IP, CIDR, or domain)' },
] as const;

export type OutboundDraft = Record<(typeof listFields)[number]['key'], string> &
  Record<(typeof numericFields)[number]['key'], number | ''> & { source: string; updatedAt: string };

export function outboundDraft(rules?: OutboundRules | null): OutboundDraft {
  return {
    beaconIntervals: rules?.beaconIntervals ?? 0, beaconJitterPercent: rules?.beaconJitterPercent ?? 15,
    uploadMiB: rules?.uploadMiB ?? 0, uploadRatio: rules?.uploadRatio ?? 4, windowSeconds: rules?.windowSeconds ?? 60,
    maxAgeDays: rules?.maxAgeDays ?? 30, expectedPorts: rules?.expectedPorts?.join(', ') ?? '',
    approvedApps: rules?.approvedApps?.join(', ') ?? '', approvedDestinations: rules?.approvedDestinations?.join(', ') ?? '',
    indicators: rules?.indicators?.join(', ') ?? '', indicatorExclusions: rules?.indicatorExclusions?.join(', ') ?? '',
    source: rules?.source ?? '', updatedAt: rules?.updatedAt?.slice(0, 10) ?? '',
  };
}

export function outboundPayload(draft: OutboundDraft) {
  const list = (value: string) => value.split(',').map(item => item.trim()).filter(Boolean);
  return { ...draft, expectedPorts: list(draft.expectedPorts).map(Number),
    approvedApps: list(draft.approvedApps), approvedDestinations: list(draft.approvedDestinations),
    indicators: list(draft.indicators), indicatorExclusions: list(draft.indicatorExclusions),
    source: draft.source.trim() || null, updatedAt: draft.updatedAt ? `${draft.updatedAt}T00:00:00Z` : null };
}

export function OutboundFields({ draft, onChange }: { draft: OutboundDraft; onChange: (next: OutboundDraft) => void }) {
  return <fieldset className="security-form security-rule-group">
    <legend>Outbound traffic and threat intelligence</legend>
    <p>Use 0 to disable interval and transfer alerts. Paste comma-separated values from a trusted indicator snapshot.
      Snapshots expire after the configured age. A blank expected port list disables service alerts.</p>
    {numericFields.map(({ key, label, min, max }) => <label key={key}>{label}
      <input type="number" required min={min} max={max} value={draft[key]}
        onChange={event => onChange({ ...draft, [key]: event.target.value === '' ? '' : Number(event.target.value) })} />
    </label>)}
    {listFields.map(({ key, label }) => <label key={key}>{label}
      <input value={draft[key]} onChange={event => onChange({ ...draft, [key]: event.target.value })} />
    </label>)}
    <label>Indicator source<input value={draft.source} maxLength={120} required={Boolean(draft.indicators.trim())}
      onChange={event => onChange({ ...draft, source: event.target.value })} /></label>
    <label>Indicator snapshot date<input type="date" value={draft.updatedAt} required={Boolean(draft.indicators.trim())}
      onChange={event => onChange({ ...draft, updatedAt: event.target.value })} /></label>
  </fieldset>;
}
