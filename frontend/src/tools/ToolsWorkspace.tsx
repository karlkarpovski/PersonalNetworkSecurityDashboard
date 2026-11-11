import { useEffect, useState } from 'react';
import { captureRequest, formatBytes } from '../capture/captureApi';
import type { CaptureView, Flow } from '../capture/captureApi';
import { downloadText } from '../capture/download';
import type { SecurityAlert } from '../security/securityTypes';
import './tools.css';

type Check = { name: string; result: string; milliseconds: number | null; replies: number | null };
type Change = { at: string; adapter: string; change: string };
type Device = { mac: string; ip: string; firstSeen: string; lastSeen: string; name: string | null };
type Session = { id: string; adapter: string; startedAt: string; checkpointAt: string; sessionBytes: number };
type Archive = { session: Session; summary: NonNullable<CaptureView['traffic']> };
const json = (method: string, body: object): RequestInit => ({
  method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
});
const time = (value: string) => new Date(value).toLocaleString();

function Health({ code }: { code: string }) {
  const [host, setHost] = useState('');
  const [result, setResult] = useState<Check[]>();
  const [pending, setPending] = useState(false);
  const [error, setError] = useState('');
  async function run() {
    setPending(true); setResult(undefined); setError('');
    try { setResult(await captureRequest<Check[]>(code, 'tools/health', json('POST', { host }), 15000)); }
    catch (reason) { setError(reason instanceof Error ? reason.message : 'Check failed.'); }
    finally { setPending(false); }
  }
  return <section className="soft-panel capture-panel" aria-labelledby="health-title">
    <h2 id="health-title">Connection Health</h2>
    <form className="capture-controls" onSubmit={event => { event.preventDefault(); void run(); }}>
      <label>Hostname or IP address<input required maxLength={253} value={host} onChange={event => setHost(event.target.value)} /></label>
      <button type="submit" className="capture-button" disabled={pending}>Run checks</button>
    </form>
    <p>Checks use the system DNS resolver, up to three ICMP probes per target, and one TLS handshake on port 443. Some hosts ignore ICMP.</p>
    {pending && <p role="status">Running connection checks…</p>}
    {error && <p className="capture-warning" role="alert">{error}</p>}
    {result && <dl className="tools-results" aria-live="polite">{result.map(check => <div key={check.name}>
      <dt>{check.name}</dt><dd>{check.result}{check.milliseconds != null ? ` · ${check.milliseconds.toFixed(1)} ms` : ''}</dd>
    </div>)}</dl>}
  </section>;
}

function Activity({ view, advanced }: { view?: CaptureView; advanced: boolean }) {
  const [filter, setFilter] = useState('');
  const [protocol, setProtocol] = useState('');
  const [minutes, setMinutes] = useState(0);
  const query = filter.trim().toLowerCase();
  const apps = (view?.traffic?.applications ?? []).filter(app =>
    `${app.process.name} ${app.process.pid}`.toLowerCase().includes(query));
  const matching = (view?.traffic?.recentFlows ?? []).filter(flow =>
    `${flow.owner?.process.name ?? 'unattributed'} ${flow.owner?.process.pid ?? ''} ${flow.endpoint.remoteIp}`.toLowerCase().includes(query)
      && (!advanced || (!protocol || flow.endpoint.protocol === protocol)
        && (!minutes || Date.now() - Date.parse(flow.lastSeen) <= minutes * 60000)));
  const destinations = new Map<string, Flow>();
  for (const flow of matching) {
    const key = JSON.stringify([flow.owner?.process.pid, flow.owner?.process.startedAt, flow.endpoint.remoteIp]);
    const existing = destinations.get(key);
    if (!existing || flow.firstSeen < existing.firstSeen) destinations.set(key, flow);
  }
  const recent = [...destinations.values()].sort((a, b) => b.firstSeen.localeCompare(a.firstSeen)).slice(0, 12);
  return <section className="soft-panel capture-panel" aria-labelledby="activity-tools-title">
    <h2 id="activity-tools-title">Application Activity</h2>
    <p>{view?.adapter ? `Capture interface ${view.adapter}. ` : ''}Totals use attributed packets from the current capture. Destination times reflect the recent flow sample.</p>
    <div className="capture-controls">
      <label>Find app, PID, or destination<input type="search" value={filter} onChange={event => setFilter(event.target.value)} /></label>
      {advanced && <><label>Protocol<select aria-label="Protocol" value={protocol} onChange={event => setProtocol(event.target.value)}>
        <option value="">All protocols</option><option>TCP</option><option>UDP</option><option>ICMP</option><option>ICMPv6</option>
      </select></label><label>Destination activity<select aria-label="Destination activity" value={minutes} onChange={event => setMinutes(Number(event.target.value))}>
        <option value={0}>All recent flows</option><option value={1}>Last minute</option><option value={5}>Last 5 minutes</option>
      </select></label></>}
    </div>
    <h3>Application totals</h3>
    {apps.length ? <ul className="country-rank">{apps.slice(0, 8).map(app => <li key={`${app.process.pid}/${app.process.startedAt}`}>
      <span>{app.process.name}{advanced && ` · PID ${app.process.pid}`}</span><strong>{formatBytes(app.sentBytes + app.receivedBytes + app.localBytes)}</strong>
    </li>)}</ul> : <p>No attributed applications match.</p>}
    <h3>Recently observed destinations</h3>
    {recent.length ? <div className="capture-table-wrap" tabIndex={0} role="region" aria-label="Observed destinations">
      <table className="capture-table"><thead><tr><th>Process</th><th>Destination</th><th>First observed</th>{advanced && <th>Sampled protocol</th>}</tr></thead>
        <tbody>{recent.map(flow => <tr key={JSON.stringify(flow.endpoint)}>
          <td>{flow.owner?.process.name ?? 'Unattributed'}</td><td>{flow.endpoint.remoteIp}</td><td>{time(flow.firstSeen)}</td>
          {advanced && <td>{flow.endpoint.protocol}</td>}
        </tr>)}</tbody></table></div> : <p>No destinations match.</p>}
    <p><a href="#connections">Inspect captured flows</a></p>
  </section>;
}

function LocalObservations({ code, advanced }: { code: string; advanced: boolean }) {
  const [changes, setChanges] = useState<Change[]>([]);
  const [devices, setDevices] = useState<Device[]>([]);
  const [selected, setSelected] = useState('');
  const [name, setName] = useState('');
  const [error, setError] = useState('');
  const [saved, setSaved] = useState('');
  const [saving, setSaving] = useState(false);
  useEffect(() => {
    const controller = new AbortController();
    async function refresh() {
      try {
        const [timeline, inventory] = await Promise.all([
          captureRequest<Change[]>(code, 'tools/timeline', { signal: controller.signal }),
          captureRequest<Device[]>(code, 'tools/devices', { signal: controller.signal }),
        ]);
        if (!controller.signal.aborted) { setChanges(timeline); setDevices(inventory); setError(''); }
      } catch (reason) { if (!controller.signal.aborted) setError(reason instanceof Error ? reason.message : 'Could not read observations.'); }
    }
    void refresh();
    const timer = window.setInterval(() => void refresh(), 10000);
    return () => { controller.abort(); window.clearInterval(timer); };
  }, [code]);
  async function saveName() {
    setSaving(true); setSaved(''); setError('');
    try {
      setDevices(await captureRequest<Device[]>(code, 'tools/devices', json('PUT', { mac: selected, name })));
      setSaved('Device name saved.');
    } catch (reason) { setError(reason instanceof Error ? reason.message : 'Could not save the name.'); }
    finally { setSaving(false); }
  }
  return <>
    <section className="soft-panel capture-panel" aria-labelledby="timeline-title">
      <h2 id="timeline-title">Network Change Timeline</h2>
      <p>Tracks adapter, gateway, and DNS changes sampled every 10 seconds while the API runs.</p>
      {changes.length ? <ul className="tools-log">{changes.map((change, index) =>
        <li key={`${change.at}/${index}`}><time dateTime={change.at}>{time(change.at)}</time><strong>{change.adapter}</strong><span>{change.change}</span></li>
      )}</ul> : <p>No changes observed yet.</p>}
    </section>
    <section className="soft-panel capture-panel" aria-labelledby="inventory-title">
      <h2 id="inventory-title">Device Inventory</h2>
      <p>Shows IPv4 neighbors Windows has cached. First and last seen refer to this app run. Saved names survive a restart.</p>
      <p role="status">{devices.filter(device => !device.name).length} unlabelled devices observed</p>
      {devices.length > 0 && <>
        <div className="capture-table-wrap" tabIndex={0} role="region" aria-label="Observed devices">
          <table className="capture-table"><thead><tr><th>Name</th><th>IPv4</th>{advanced && <th>MAC</th>}<th>First seen</th><th>Last seen</th></tr></thead>
            <tbody>{devices.map(device => <tr key={device.mac}>
              <td>{device.name ?? 'Unlabelled'}</td><td>{device.ip}</td>{advanced && <td>{device.mac}</td>}
              <td>{time(device.firstSeen)}</td><td>{time(device.lastSeen)}</td>
            </tr>)}</tbody></table></div>
        <form className="capture-controls history-pagination" onSubmit={event => { event.preventDefault(); void saveName(); }}>
          <label>Observed device<select aria-label="Observed device" value={selected} onChange={event => {
            setSelected(event.target.value); setName(devices.find(device => device.mac === event.target.value)?.name ?? ''); setSaved('');
          }}><option value="">Select a device</option>{devices.map(device =>
            <option key={device.mac} value={device.mac}>{device.ip} · {device.name ?? device.mac}</option>)}</select></label>
          <label>Device name<input maxLength={64} value={name} onChange={event => setName(event.target.value)} /></label>
          <button className="capture-button" type="submit" disabled={!selected || saving}>Save name</button>
        </form>
      </>}
      {error && <p className="capture-warning" role="alert">{error}</p>}
      {saved && <p role="status">{saved}</p>}
    </section>
  </>;
}

function Comparison({ code, advanced }: { code: string; advanced: boolean }) {
  const [sessions, setSessions] = useState<Session[]>([]);
  const [first, setFirst] = useState('');
  const [second, setSecond] = useState('');
  const [result, setResult] = useState<[Archive, Archive]>();
  const [alerts, setAlerts] = useState<SecurityAlert[]>([]);
  const [includeDetails, setIncludeDetails] = useState(false);
  const [error, setError] = useState('');
  const [pending, setPending] = useState(false);
  const [revision, setRevision] = useState(0);
  useEffect(() => {
    const controller = new AbortController();
    captureRequest<Session[]>(code, 'storage/sessions', { signal: controller.signal }).then(items => {
      if (controller.signal.aborted) return;
      setSessions(items);
      setFirst(items[1]?.id ?? '');
      setSecond(items[0]?.id ?? '');
      setResult(undefined);
    }).catch(reason => { if (!controller.signal.aborted) setError(reason.message); });
    return () => controller.abort();
  }, [code, revision]);
  async function compare() {
    setPending(true); setError(''); setResult(undefined);
    try {
      const [baseline, comparison, retainedAlerts] = await Promise.all([
        captureRequest<Archive>(code, `storage/sessions/${first}`),
        captureRequest<Archive>(code, `storage/sessions/${second}`),
        captureRequest<SecurityAlert[]>(code, 'security/alerts'),
      ]);
      setAlerts(retainedAlerts);
      setResult([baseline, comparison]);
    }
    catch (reason) { setError(reason instanceof Error ? reason.message : 'Comparison failed.'); }
    finally { setPending(false); }
  }
  const stats = (archive: Archive) => ({
    durationSeconds: Math.max(0, Math.round((Date.parse(archive.session.checkpointAt) - Date.parse(archive.session.startedAt)) / 1000)),
    capturedBytes: archive.summary.sessionBytes,
    packets: archive.summary.inboundPackets + archive.summary.outboundPackets + archive.summary.localPackets + archive.summary.unknownPackets,
    remoteAddresses: archive.summary.uniqueRemoteIps,
    retainedAlerts: alerts.filter(alert => alert.sessionId === archive.session.id).length,
  });
  function report(archive: Archive) {
    const totals = stats(archive);
    if (!advanced || !includeDetails) return totals;
    return {
      ...totals,
      startedAt: archive.session.startedAt,
      checkpointAt: archive.session.checkpointAt,
      sampledFlows: archive.summary.recentFlows.map(flow => ({
        protocol: flow.endpoint.protocol, packets: flow.packets, sentBytes: flow.sentBytes, receivedBytes: flow.receivedBytes,
        firstSeen: flow.firstSeen, lastSeen: flow.lastSeen,
      })),
      alerts: alerts.filter(alert => alert.sessionId === archive.session.id)
        .map(({ rule, severity, state, observedAt }) => ({ rule, severity, state, observedAt })),
    };
  }
  return <section className="soft-panel capture-panel" aria-labelledby="compare-title">
    <h2 id="compare-title">Session Comparison and Reports</h2>
    <p>Compare the latest saved checkpoints from two capture sessions. Reports redact addresses, process names, and adapter names.</p>
    <form className="capture-controls" onSubmit={event => { event.preventDefault(); void compare(); }}>
      {([{ label: 'Baseline session', id: first, change: setFirst }, { label: 'Comparison session', id: second, change: setSecond }]).map(item =>
        <label key={item.label}>{item.label}<select aria-label={item.label} value={item.id} disabled={pending} onChange={event => { item.change(event.target.value); setResult(undefined); }}>
          <option value="">Select a saved session</option>{sessions.map(session =>
            <option value={session.id} key={session.id}>{time(session.startedAt)} · {session.adapter}</option>)}</select></label>)}
      <button className="capture-button" type="submit" disabled={pending || !first || !second || first === second}>Compare</button>
      <button className="capture-button" type="button" disabled={pending} onClick={() => setRevision(value => value + 1)}>Refresh sessions</button>
    </form>
    {sessions.length < 2 && <p>Save at least two capture sessions to compare them.</p>}
    {error && <p role="alert" className="capture-warning">{error}</p>}
    {result && <>
      <dl className="tools-results">{result.map((archive, index) => {
        const values = stats(archive);
        return <div key={archive.session.id}><dt>{index ? 'Comparison' : 'Baseline'}</dt>
          <dd>{formatBytes(values.capturedBytes)} · {values.packets.toLocaleString()} packets · {values.durationSeconds}s</dd>
          {advanced && <dd>{values.remoteAddresses.toLocaleString()} distinct remote addresses · {values.retainedAlerts} retained alerts</dd>}
        </div>;
      })}</dl>
      <p>Traffic difference {result[1].summary.sessionBytes >= result[0].summary.sessionBytes ? '+' : '−'}
        {formatBytes(Math.abs(result[1].summary.sessionBytes - result[0].summary.sessionBytes))}</p>
      <div className="capture-controls tools-export">
        {advanced && <label><input type="checkbox" checked={includeDetails} onChange={event => setIncludeDetails(event.target.checked)} />
          Include timestamps, sampled flows, and alert metadata</label>}
        <button type="button" className="capture-button" onClick={() => downloadText('capture-comparison.json', JSON.stringify({
          baseline: report(result[0]), comparison: report(result[1]),
        }, null, 2), 'application/json')}>Export redacted report</button>
      </div>
    </>}
  </section>;
}

export function ToolsWorkspace({ code, view }: { code: string; view?: CaptureView }) {
  const [advanced, setAdvanced] = useState(false);
  return <div className="dashboard">
    <div className="capture-controls tools-mode" role="group" aria-label="Tools view">
      <button type="button" className="capture-button" aria-pressed={!advanced} onClick={() => setAdvanced(false)}>Home</button>
      <button type="button" className="capture-button" aria-pressed={advanced} onClick={() => setAdvanced(true)}>Advanced</button>
    </div>
    <Health code={code} />
    <Activity view={view} advanced={advanced} />
    <LocalObservations code={code} advanced={advanced} />
    <Comparison code={code} advanced={advanced} />
  </div>;
}
