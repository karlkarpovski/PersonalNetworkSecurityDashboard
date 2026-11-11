import { useEffect, useState } from 'react';
import { captureRequest } from '../capture/captureApi';
import { ruleNames } from './securityTypes';
import type { AddressRule, AlertSummary, SecurityAlert, SecuritySettings } from './securityTypes';
import './security.css';
import { downloadText, encodeCsv } from '../capture/download';

const put = (body: object): RequestInit => ({
  method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
});
const thresholds = [
  { key: 'bandwidthMiB', label: 'Traffic (MiB)', max: 100000 },
  { key: 'destinations', label: 'Distinct destinations', max: 4096 },
  { key: 'synPackets', label: 'Outbound SYNs per IP', max: 100000 },
  { key: 'refusedAttempts', label: 'Matched TCP resets per IP', max: 100000 },
] as const;
const severities = ['informational', 'low', 'medium', 'high', 'critical'];
type ThresholdDraft = Record<(typeof thresholds)[number]['key'], number | ''>;

export function SecurityPanel({ code, summary }: { code: string; summary?: AlertSummary }) {
  const [history, setHistory] = useState<SecurityAlert[]>([]);
  const [settings, setSettings] = useState<SecuritySettings>();
  const [rules, setRules] = useState<ThresholdDraft>();
  const [ports, setPorts] = useState('');
  const [countries, setCountries] = useState('');
  const [ip, setIp] = useState('');
  const [list, setList] = useState<AddressRule['list']>('watch');
  const [state, setState] = useState('open');
  const [severity, setSeverity] = useState('all');
  const [selected, setSelected] = useState<string>();
  const [pending, setPending] = useState(false);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [revision, setRevision] = useState(0);
  const streamRevision = summary?.revision;

  useEffect(() => {
    const controller = new AbortController();
    captureRequest<SecuritySettings>(code, 'security/settings', { signal: controller.signal }).then(result => {
      if (controller.signal.aborted) return;
      setSettings(result);
      setRules(result.rules);
      setPorts(result.rules.ports?.join(', ') ?? '');
      setCountries(result.rules.countries?.join(', ') ?? '');
    }).catch(reason => { if (!controller.signal.aborted) setError(reason.message); });
    return () => controller.abort();
  }, [code]);

  useEffect(() => {
    const controller = new AbortController();
    captureRequest<SecurityAlert[]>(code, 'security/alerts', { signal: controller.signal }).then(result => {
      if (!controller.signal.aborted) setHistory(result);
    }).catch(reason => { if (!controller.signal.aborted) setError(reason.message); });
    return () => controller.abort();
  }, [code, revision, streamRevision]);

  async function update(action: () => Promise<void>, success: string) {
    setPending(true);
    setError('');
    setNotice('');
    try { await action(); setNotice(success); }
    catch (reason) { setError(reason instanceof Error ? reason.message : 'The security request failed.'); }
    finally { setPending(false); }
  }

  function saveAddress(address: string, target: AddressRule['list'] | 'none') {
    void update(async () => {
      setSettings(await captureRequest<SecuritySettings>(code, 'security/address', put({ ip: address, list: target })));
      if (target !== 'none') setIp('');
    }, target === 'none' ? 'Address removed.' : 'Address rule saved.');
  }

  function saveRules() {
    if (!rules) return;
    const items = (value: string) => value.split(',').map(item => item.trim()).filter(Boolean);
    void update(async () => {
      const result = await captureRequest<SecuritySettings>(code, 'security/rules',
        put({ ...rules, ports: items(ports).map(Number), countries: items(countries) }));
      setSettings(result);
      setRules(result.rules);
      setPorts(result.rules.ports?.join(', ') ?? '');
      setCountries(result.rules.countries?.join(', ') ?? '');
    }, 'Alert rules saved.');
  }

  const filtered = history.filter(alert => (state === 'all' || alert.state === state)
    && (severity === 'all' || alert.severity === severity));
  const inspected = filtered.find(alert => alert.id === selected) ?? filtered[0];
  function changeState(alert: SecurityAlert, next: 'acknowledged' | 'dismissed') {
    void update(async () => {
      await captureRequest<void>(code, `security/alerts/${alert.id}`, put({ state: next }));
      setHistory(previous => previous.map(item => item.id === alert.id ? { ...item, state: next } : item));
      setRevision(value => value + 1);
    }, next === 'acknowledged' ? 'Alert acknowledged.' : 'Alert dismissed.');
  }

  return (
    <div className="dashboard">
      {error && <p className="security-warning" role="alert">{error}</p>}
      {notice && <p className="security-notice" role="status">{notice}</p>}
      <section className="soft-panel capture-panel" aria-labelledby="alert-history-title">
        <div className="panel-heading capture-table-heading">
          <h2 id="alert-history-title">Alert history</h2>
          <label>Alert state<select aria-label="Alert state" value={state} onChange={event => setState(event.target.value)}>
            <option value="open">Open</option><option value="acknowledged">Acknowledged</option>
            <option value="dismissed">Dismissed</option><option value="all">All states</option>
          </select></label>
          <label>Severity<select aria-label="Severity" value={severity} onChange={event => setSeverity(event.target.value)}>
            <option value="all">All severities</option>{severities.map(value => <option key={value} value={value}>{value}</option>)}
          </select></label>
        </div>
        <p>Alerts describe observed events and configured rules. Monitoring never changes the firewall.</p>
        <div className="capture-controls history-pagination">
          <button className="capture-button" type="button" disabled={!filtered.length}
            onClick={() => downloadText('security-alerts.json', JSON.stringify(filtered, null, 2), 'application/json')}>Export alerts JSON</button>
          <button className="capture-button" type="button" disabled={!filtered.length} onClick={() =>
            downloadText('security-alerts.csv', encodeCsv([
              ['Observed', 'Rule', 'Severity', 'State', 'Remote IP', 'Evidence'],
              ...filtered.map(alert => [alert.observedAt, alert.rule, alert.severity, alert.state, alert.remoteIp, alert.evidence]),
            ]), 'text/csv;charset=utf-8')}>Export alerts CSV</button>
        </div>
        {inspected ? <div className="security-layout">
          <ul className="security-list">
            {filtered.map(alert => <li key={alert.id}><button className="capture-button security-alert-row"
              type="button" aria-pressed={alert.id === inspected.id} onClick={() => setSelected(alert.id)}>
              <strong>{ruleNames[alert.rule] ?? alert.rule}</strong>
              <small className={`severity-${alert.severity}`}>{alert.severity} · {alert.state}</small>
            </button></li>)}
          </ul>
          <article className="inset-surface security-evidence" aria-label="Alert evidence">
            <h3>{ruleNames[inspected.rule] ?? inspected.rule}</h3>
            <p>{inspected.evidence}</p>
            <p><time dateTime={inspected.observedAt}>{new Date(inspected.observedAt).toLocaleString()}</time>
              {inspected.remoteIp && ` · ${inspected.remoteIp}`}</p>
            <div className="capture-controls">
              <button className="capture-button" type="button" disabled={pending || inspected.state !== 'open'}
                onClick={() => changeState(inspected, 'acknowledged')}>Acknowledge</button>
              <button className="capture-button" type="button" disabled={pending || inspected.state === 'dismissed'}
                onClick={() => changeState(inspected, 'dismissed')}>Dismiss</button>
            </div>
          </article>
        </div> : <p>No alerts match these filters.</p>}
      </section>
      <section className="soft-panel capture-panel" aria-labelledby="rules-title">
        <h2 id="rules-title">Detection rules</h2>
        <p>Thresholds count non-trusted traffic in fixed 10-second windows. Use 0 to disable a threshold. Port and country matches have low severity.</p>
        {rules && <form className="security-form" onSubmit={event => { event.preventDefault(); saveRules(); }}>
          {thresholds.map(({ key, label, max }) => <label key={key}>{label}<input type="number" required min={0} max={max}
            value={rules[key]} onChange={event => setRules({ ...rules, [key]: event.target.value === '' ? '' : Number(event.target.value) })} /></label>)}
          <label>Monitored destination ports<input value={ports} onChange={event => setPorts(event.target.value)} placeholder="Comma-separated, e.g. 23, 445" maxLength={256} /></label>
          <label>Monitored country codes<input value={countries} onChange={event => setCountries(event.target.value)} placeholder="Comma-separated, e.g. GB, JP" maxLength={160} /></label>
          <button className="capture-button" type="submit" disabled={pending}>Save rules</button>
        </form>}
      </section>
      <section className="soft-panel capture-panel" aria-labelledby="address-rules-title">
        <h2 id="address-rules-title">Watchlist and address rules</h2>
        <p>Watched addresses generate informational alerts. Blocklisted addresses generate high alerts. Trusted addresses are excluded from rule evaluation. Each IP belongs to one list.</p>
        <form className="capture-controls" onSubmit={event => { event.preventDefault(); saveAddress(ip, list); }}>
          <label>Remote IP address<input required maxLength={80} value={ip} onChange={event => setIp(event.target.value)} /></label>
          <label>Address list<select aria-label="Address list" value={list} onChange={event => setList(event.target.value as AddressRule['list'])}>
            <option value="watch">Watchlist</option><option value="trusted">Trusted list</option><option value="block">Blocklist (alert only)</option>
          </select></label>
          <button className="capture-button" type="submit" disabled={pending}>Save address</button>
        </form>
        {settings?.addresses.length ? <ul className="security-list address-rule-list">
          {settings.addresses.map(entry => <li key={entry.ip}><span>{entry.ip} · {entry.list}</span>
            <button className="capture-button" type="button" disabled={pending} aria-label={`Remove ${entry.ip}`}
              onClick={() => saveAddress(entry.ip, 'none')}>Remove</button></li>)}
        </ul> : <p>No address rules configured.</p>}
      </section>
    </div>
  );
}
