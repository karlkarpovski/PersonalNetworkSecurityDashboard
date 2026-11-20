import { useState } from 'react';
import { LiveTablePages } from './LiveTablePages';
import { formatBytes } from './captureApi';
import type { CaptureView, ProcessIdentity } from './captureApi';

export function processKey(process: ProcessIdentity) {
  return `${process.pid}/${process.startedAt}`;
}

export function ApplicationsPanel({ view }: { view?: CaptureView }) {
  const [search, setSearch] = useState(() => new URLSearchParams(window.location.hash.split('?')[1]).get('q') ?? '');
  const traffic = view?.traffic;
  const query = search.trim().toLowerCase();
  const apps = (traffic?.applications ?? []).filter(app => `${app.process.name} ${app.process.pid}`.toLowerCase().includes(query));
  const destinations = new Map<string, Set<string>>();
  for (const flow of traffic?.recentFlows ?? []) {
    if (!flow.owner) continue;
    const key = processKey(flow.owner.process);
    if (!destinations.has(key)) destinations.set(key, new Set());
    destinations.get(key)!.add(flow.endpoint.remoteIp);
  }
  return (
    <section className="soft-panel capture-panel" aria-labelledby="apps-title">
      <div className="panel-heading capture-table-heading">
        <h2 id="apps-title">Traffic by observed process</h2>
        <label>Find application<input type="search" value={search} onChange={event => setSearch(event.target.value)} /></label>
      </div>
      <p>Totals count packets matched to a sampled TCP connection or an unambiguous exact UDP binding. Short-lived sockets and inaccessible processes can be missed. Local traffic is credited once, to the observed sender.</p>
      {traffic && <p>Bytes outside application totals {formatBytes(traffic.unattributedBytes ?? 0)} · Showing up to 50 processes</p>}
      <LiveTablePages key={JSON.stringify([view?.sessionId, query])} rows={apps} label="Application pages"
        empty={query ? 'No matching applications.' : 'Waiting for process-attributed traffic.'}>
        {page => <div className="capture-table-wrap" tabIndex={0} role="region" aria-label="Application traffic table">
          <table className="capture-table">
            <thead><tr><th>Process</th><th>PID</th><th>Started</th><th>Active flows</th><th>Packets</th><th>Sent</th><th>Received</th><th>Local</th><th>Rate</th><th>Recent destinations</th></tr></thead>
            <tbody>{page.map(app => {
              const key = processKey(app.process);
              const remote = [...(destinations.get(key) ?? [])];
              return <tr key={key}>
                <td><a href={`#connections?q=${encodeURIComponent(String(app.process.pid))}`}>{app.process.name}</a></td><td>{app.process.pid}</td><td>{new Date(app.process.startedAt).toLocaleString()}</td>
                <td>{app.activeFlows.toLocaleString()}</td><td>{app.packets.toLocaleString()}</td>
                <td>{formatBytes(app.sentBytes)}</td><td>{formatBytes(app.receivedBytes)}</td><td>{formatBytes(app.localBytes)}</td>
                <td>{formatBytes(app.bytesPerSecond)}/s</td>
                <td>{remote.slice(0, 3).join(', ') || 'Unavailable'}{remote.length > 3 ? ` +${remote.length - 3}` : ''}</td>
              </tr>;
            })}</tbody>
          </table>
        </div>}
      </LiveTablePages>
    </section>
  );
}
