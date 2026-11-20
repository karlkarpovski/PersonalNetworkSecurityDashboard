import { useEffect, useState } from 'react';
import { captureRequest, formatBytes } from './capture/captureApi';
import type { CaptureView } from './capture/captureApi';

export function CaptureStatus({ view, connected }: { view?: CaptureView; connected: boolean }) {
  const [observedStart, setObservedStart] = useState<{ session: string; at: number }>();
  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    if (view?.sessionId && view.state === 'running')
      setObservedStart(previous => previous?.session === view.sessionId ? previous : { session: view.sessionId!, at: Date.now() });
  }, [view?.sessionId, view?.state]);
  useEffect(() => {
    if (view?.state !== 'running') return;
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, [view?.state]);
  const seconds = observedStart ? Math.max(0, Math.floor((now - observedStart.at) / 1000)) : 0;
  return <aside className="capture-status inset-surface" aria-label="Capture status">
    <strong className={connected && view?.state === 'running' ? 'capture-running' : ''}>
      {connected ? `Capture ${view?.state ?? 'loading'}` : 'Stream disconnected · displayed data may be stale'}
    </strong>
    <span>{view?.adapter ?? 'Select an adapter'}</span>
    {view?.state === 'running' && <span>Observed {Math.floor(seconds / 60)}m {seconds % 60}s</span>}
    {view && <span>Queue drops {view.queueDrops} · Driver drops {view.driverDrops ?? 'unavailable'}</span>}
    <a href="#settings">Capture settings</a>
  </aside>;
}

export function InvestigationPanel({ view }: { view?: CaptureView }) {
  const traffic = view?.traffic;
  const apps = [...(traffic?.applications ?? [])].sort((a, b) => b.bytesPerSecond - a.bytesPerSecond).slice(0, 3);
  const flows = traffic?.recentFlows.slice(0, 3) ?? [];
  return <section className="soft-panel capture-panel">
    <h2>Investigate activity</h2>
    {!traffic && <p>Select your network adapter and start capture to see traffic. <a href="#packets">Start capture</a></p>}
    <div className="investigation-grid">
      <div><h3>Busiest observed applications</h3>
        {apps.length ? <ul>{apps.map(app => <li key={app.process.pid}>
          <a href={`#connections?q=${encodeURIComponent(String(app.process.pid))}`}>{app.process.name}</a> · {formatBytes(app.bytesPerSecond)}/s
        </li>)}</ul> : <p>Waiting for process attribution.</p>}</div>
      <div><h3>Recent destinations</h3>
        {flows.length ? <ul>{flows.map(flow => <li key={JSON.stringify(flow.endpoint)}>
          <a href={`#connections?q=${encodeURIComponent(flow.endpoint.remoteIp)}`}>{flow.endpoint.remoteIp}</a>
        </li>)}</ul> : <p>Waiting for observed connections.</p>}</div>
      <div><h3>Security activity</h3><p><a href="#alerts">Review open alerts and evidence</a></p></div>
    </div>
  </section>;
}

type Diagnostics = { version: string; databasePath: string; captureDriver: boolean; runtime: string };
export function DiagnosticsPanel({ code }: { code: string }) {
  const [data, setData] = useState<Diagnostics>();
  const [notice, setNotice] = useState('');
  useEffect(() => {
    const controller = new AbortController();
    captureRequest<Diagnostics>(code, 'diagnostics', { signal: controller.signal }).then(setData)
      .catch(error => { if (!controller.signal.aborted) setNotice(error.message); });
    return () => controller.abort();
  }, [code]);
  return <section className="soft-panel capture-panel"><h2>About and diagnostics</h2>
    {data && <><dl><dt>Application version</dt><dd>{data.version}</dd><dt>Runtime</dt><dd>{data.runtime}</dd>
      <dt>Capture driver</dt><dd>{data.captureDriver ? 'Npcap available' : 'Npcap unavailable'}</dd>
      <dt>Local database</dt><dd className="diagnostic-path">{data.databasePath}</dd></dl>
      <button type="button" className="capture-button" onClick={async () => {
        try {
          await navigator.clipboard.writeText(JSON.stringify({ version: data.version, runtime: data.runtime, captureDriver: data.captureDriver }, null, 2));
          setNotice('Diagnostics copied. The database path is omitted.');
        } catch { setNotice('Clipboard unavailable. Select and copy the displayed details.'); }
      }}>Copy diagnostics</button></>}
    <p role="status">{notice}</p>
  </section>;
}
