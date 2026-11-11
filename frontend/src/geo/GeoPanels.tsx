import { useEffect, useState } from 'react';
import { captureRequest, formatBytes } from '../capture/captureApi';
import type { Flow } from '../capture/captureApi';
import type { GeoResult, GeoSettings } from './geoTypes';
import './geo.css';

export function locationStatus(result: GeoResult) {
  switch (result.status) {
    case 'located': return 'Approximate location';
    case 'partial': return 'Partial data · coordinates unavailable';
    case 'non-public': return `Excluded from geolocation · ${result.addressKind}`;
    case 'database-unavailable': return 'GeoIP databases unavailable';
    case 'lookup-error': return 'Local database lookup failed';
    case 'not-found': return 'Address absent from the available databases';
  }
}

export function GeoDetails({ result }: { result: GeoResult }) {
  return (
    <>
      <p>{locationStatus(result)}</p>
      <dl className="geo-details">
        <dt>Address type</dt><dd>{result.ip.includes(':') ? 'IPv6' : 'IPv4'} · {result.addressKind}</dd>
        <dt>Country</dt><dd>{result.country ?? 'Unknown'}{result.countryCode ? ` (${result.countryCode})` : ''}</dd>
        <dt>Region</dt><dd>{result.region ?? 'Unknown'}</dd>
        <dt>City</dt><dd>{result.city ?? 'Unknown'}</dd>
        <dt>Approx. coordinates</dt><dd>{result.latitude === null || result.longitude === null
          ? 'Unavailable' : `${result.latitude.toFixed(2)}°, ${result.longitude.toFixed(2)}°`}</dd>
        <dt>Accuracy radius</dt><dd>{result.accuracyRadiusKm === null ? 'Unavailable' : `${result.accuracyRadiusKm.toLocaleString()} km`}</dd>
        <dt>Network ASN</dt><dd>{result.asn === null ? 'Unknown' : `AS${result.asn}`}</dd>
        <dt>Organization</dt><dd>{result.organization ?? 'Unknown'}</dd>
      </dl>
    </>
  );
}

export function GeoSettingsPanel({ code }: { code: string }) {
  const [settings, setSettings] = useState<GeoSettings>();
  const [mode, setMode] = useState<'manual' | 'public-ip'>('manual');
  const [latitude, setLatitude] = useState('');
  const [longitude, setLongitude] = useState('');
  const [label, setLabel] = useState('');
  const [ip, setIp] = useState('');
  const [pending, setPending] = useState(true);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');

  useEffect(() => {
    const controller = new AbortController();
    captureRequest<GeoSettings>(code, 'geo/settings', { signal: controller.signal }).then(result => {
      if (controller.signal.aborted) return;
      setSettings(result);
      const configuration = result.configuration;
      setMode(configuration?.mode ?? 'manual');
      setLatitude(configuration?.latitude?.toString() ?? '');
      setLongitude(configuration?.longitude?.toString() ?? '');
      setLabel(configuration?.label ?? '');
      setIp(configuration?.ip ?? '');
    }).catch(reason => {
      if (!controller.signal.aborted) setError(reason.message);
    }).finally(() => {
      if (!controller.signal.aborted) setPending(false);
    });
    return () => controller.abort();
  }, [code]);

  async function update(path: 'reload' | 'origin', body?: object) {
    setPending(true);
    setError('');
    setNotice('');
    try {
      const result = await captureRequest<GeoSettings>(code, `geo/${path}`, body ? {
        method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
      } : { method: 'POST' });
      setSettings(result);
      setNotice(path === 'reload' ? 'Database files checked.' : result.origin ? 'Map origin saved.' : 'Map origin cleared.');
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'The GeoIP request failed.');
    } finally {
      setPending(false);
    }
  }

  return (
    <section className="soft-panel capture-panel" aria-labelledby="geo-settings-title">
      <div className="panel-heading">
        <h2 id="geo-settings-title">Offline GeoIP</h2>
        <button type="button" className="capture-button" disabled={pending} onClick={() => void update('reload')}>Reload databases</button>
      </div>
      <p>Put your GeoLite2 City and ASN MMDB files in the database directory. Lookups use only local files.</p>
      {settings && <>
        <p>Database directory <code className="geo-path">{settings.databases.directory}</code></p>
        <ul className="geo-file-list">
          {[settings.databases.city, settings.databases.asn].map(file => (
            <li className="inset-surface" key={file.fileName}>
              <strong>{file.fileName}</strong>
              <span className={file.state === 'ready' ? 'capture-running' : 'capture-warning'}>{file.state}</span>
              {file.warning && <small>{file.state === 'ready' ? 'Previous reader retained. ' : ''}{file.warning}</small>}
            </li>
          ))}
        </ul>
      </>}
      <h3>Approximate map origin</h3>
      <p>{settings?.origin ? `Current origin: ${settings.origin.label} (${settings.origin.latitude.toFixed(2)}°, ${settings.origin.longitude.toFixed(2)}°).`
        : 'Set a coarse location to draw live routes from this device.'} The setting is saved locally.</p>
      <form className="capture-controls geo-origin-form" onSubmit={event => {
        event.preventDefault();
        void update('origin', mode === 'manual'
          ? { mode, latitude: Number(latitude), longitude: Number(longitude), label }
          : { mode, ip });
      }}>
        <label htmlFor="origin-mode">Origin source
          <select id="origin-mode" value={mode} onChange={event => setMode(event.target.value === 'manual' ? 'manual' : 'public-ip')}>
            <option value="manual">Manual coordinates</option><option value="public-ip">Public IP lookup</option>
          </select>
        </label>
        {mode === 'manual' ? <>
          <label>Latitude<input type="number" min={-90} max={90} step="any" required value={latitude} onChange={event => setLatitude(event.target.value)} /></label>
          <label>Longitude<input type="number" min={-180} max={180} step="any" required value={longitude} onChange={event => setLongitude(event.target.value)} /></label>
          <label>Label<input maxLength={80} value={label} onChange={event => setLabel(event.target.value)} placeholder="Optional city or region" /></label>
        </> : <label>Public address<input required maxLength={80} value={ip} onChange={event => setIp(event.target.value)} placeholder="Enter your public IP" /></label>}
        <button type="submit" className="capture-button" disabled={pending}>Save origin</button>
        <button type="button" className="capture-button" disabled={pending || !settings?.configuration}
          onClick={() => void update('origin', { mode: 'none' })}>Clear origin</button>
      </form>
      {notice && <p role="status">{notice}</p>}
      {error && <p className="capture-warning" role="alert">{error}</p>}
    </section>
  );
}

export function IpIntelligence({ code, flows = [] }: { code: string; flows?: Flow[] }) {
  const [ip, setIp] = useState('');
  const [result, setResult] = useState<GeoResult>();
  const [pending, setPending] = useState(false);
  const [error, setError] = useState('');
  const matches = result ? flows.filter(flow => flow.endpoint.remoteIp === result.ip) : [];

  async function lookup() {
    setPending(true);
    setResult(undefined);
    setError('');
    try {
      setResult(await captureRequest<GeoResult>(code, 'geo/lookup', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ip }),
      }));
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'The lookup failed.');
    } finally {
      setPending(false);
    }
  }

  return (
    <section className="soft-panel capture-panel" aria-labelledby="geo-lookup-title">
      <h2 id="geo-lookup-title">Offline address lookup</h2>
      <form className="capture-controls" onSubmit={event => { event.preventDefault(); void lookup(); }}>
        <label>IP address<input required maxLength={80} value={ip} onChange={event => setIp(event.target.value)} placeholder="IPv4 or IPv6" /></label>
        <button type="submit" className="capture-button" disabled={pending}>Look up address</button>
      </form>
      <p>Locations describe approximate network areas. VPN, proxy, and hosting addresses may identify the network exit.</p>
      {error && <p role="alert" className="capture-warning">{error}</p>}
      {result && <div className="geo-result inset-surface" aria-live="polite">
        <h3>{result.ip}</h3>
        <GeoDetails result={result} />
        <p>{matches.length ? `${matches.length} recent flows · ${formatBytes(matches.reduce((sum, flow) => sum + flow.sentBytes + flow.receivedBytes, 0))} transferred`
          : 'No matching flows in the recent capture sample.'}</p>
      </div>}
    </section>
  );
}
