import { useEffect, useState } from 'react';
import { captureRequest } from '../capture/captureApi';
import type { GeoSettings } from './geoTypes';

export function GettingStarted({ code }: { code: string }) {
  const [settings, setSettings] = useState<GeoSettings>();
  const [hidden, setHidden] = useState(() => {
    try { return localStorage.getItem('pns-getting-started-hidden') === 'yes'; }
    catch { return false; }
  });
  useEffect(() => {
    const controller = new AbortController();
    captureRequest<GeoSettings>(code, 'geo/settings', { signal: controller.signal })
      .then(result => { if (!controller.signal.aborted) setSettings(result); }).catch(() => {});
    return () => controller.abort();
  }, [code]);
  if (hidden || !settings || settings.databases.city.state === 'ready' && settings.databases.asn.state === 'ready') return null;
  return <section className="soft-panel capture-panel" aria-labelledby="getting-started-title">
    <h2 id="getting-started-title">Get started with your network</h2>
    <p>You can start monitoring now. GeoIP is optional and adds approximate locations and network ownership.</p>
    <ol className="setup-steps">
      <li><strong>Start a capture.</strong> Open Live Packet Monitor, choose your active Wi-Fi or Ethernet adapter, and select Start capture.</li>
      <li><strong>Explore ordinary activity.</strong> Open a website, then check Applications, Active Connections, and Traffic Analytics.</li>
      <li><strong>Add location details when you are ready.</strong> Import your own GeoLite City and ASN files through the instructions in Settings.</li>
    </ol>
    <div className="capture-controls">
      <a className="capture-button" href="#packets">Open Live Packet Monitor</a>
      <a className="capture-button" href="#settings?setup=geo">Guide me through GeoIP setup</a>
      <button type="button" className="capture-button" onClick={() => {
        setHidden(true);
        try { localStorage.setItem('pns-getting-started-hidden', 'yes'); } catch { /* Dismiss for this visit. */ }
      }}>Hide this guide</button>
    </div>
    <p>Setup instructions remain available under Settings → Offline GeoIP.</p>
  </section>;
}

export function GeoSetupGuide({ settings }: { settings?: GeoSettings }) {
  const [notice, setNotice] = useState('');
  return <div className="inset-surface geo-setup-guide">
    <h3>Optional GeoIP setup</h3>
    <p>Packet capture, application totals, connection lists, traffic charts, history, and most alerts work before you add these files.
      The City database adds approximate locations and country alerts. The ASN database adds network ownership.</p>
    <ol className="setup-steps">
      <li>Create a MaxMind account and follow the GeoLite download instructions.
        <p><a href="https://dev.maxmind.com/geoip/geolite2-free-geolocation-data/" target="_blank" rel="noopener noreferrer">Open MaxMind GeoLite instructions</a></p>
      </li>
      <li>Download GeoLite City and GeoLite ASN in <strong>MMDB format</strong>. Extract the downloaded archives.
        Find <code>GeoLite2-City.mmdb</code> and <code>GeoLite2-ASN.mmdb</code> inside them.</li>
      <li>Copy the two extracted files directly into the database directory shown below. File Explorer can open the path.
        {settings && <p><button type="button" className="capture-button" onClick={async () => {
          try { await navigator.clipboard.writeText(settings.databases.directory); setNotice('Database directory copied. Paste it into File Explorer.'); }
          catch { setNotice('Select the database directory below and copy it into File Explorer.'); }
        }}>Copy database directory</button></p>}
      </li>
      <li>Select <strong>Reload databases</strong>. Confirm each file shows <strong>ready</strong>.
        Missing means the named file was not found. Invalid means the file could not be loaded; check that you extracted the MMDB download.</li>
      <li>For globe routes, save a coarse map origin below. Start capture and open Global Traffic Map.
        Routes appear when both the origin and remote endpoint have coordinates.</li>
    </ol>
    <p>Keep the files updated using your MaxMind account. Private addresses and addresses absent from the database can still have no location.
      No MaxMind account password or license key is needed in this app.</p>
    <p><a href="#packets">Continue with capture</a> · <a href="#map">Open Global Traffic Map</a></p>
    {notice && <p role="status">{notice}</p>}
  </div>;
}
