import { useState } from 'react';
import { RatePlot, TrafficPanels } from '../Dashboard';
import type { GeoSnapshot } from '../geo/geoTypes';
import { formatBytes } from './captureApi';
import type { CaptureView } from './captureApi';
import type { RateSample } from './useCaptureStream';

function Ranking({ title, data }: { title: string; data: Map<string, number> }) {
  const ranked = [...data].sort(([, left], [, right]) => right - left).slice(0, 5);
  return (
    <section className="soft-panel activity-panel">
      <h2>{title}</h2>
      {ranked.length ? <ol className="country-rank">
        {ranked.map(([label, value]) => <li key={label}><span>{label}</span><strong>{formatBytes(value)}</strong></li>)}
      </ol> : <p>Waiting for captured data.</p>}
    </section>
  );
}

export function TrafficAnalytics({ view, samples, geo }: {
  view?: CaptureView; samples: RateSample[]; geo?: GeoSnapshot;
}) {
  const [seconds, setSeconds] = useState(60);
  const traffic = view?.traffic;
  const end = Date.parse(samples.at(-1)?.at ?? '');
  const timeline = samples.filter(sample => end - Date.parse(sample.at) <= seconds * 1000);
  const locations = new Map(geo?.endpoints.map(endpoint => [endpoint.ip, endpoint.country]));
  const countries = new Map<string, number>();
  const addresses = new Map<string, number>();
  const ports = new Map<string, number>();
  const apps = new Map<string, number>();
  const add = (table: Map<string, number>, key: string, amount: number) =>
    table.set(key, (table.get(key) ?? 0) + amount);
  for (const flow of traffic?.recentFlows ?? []) {
    const { remoteIp, remotePort, protocol } = flow.endpoint;
    const bytes = flow.sentBytes + flow.receivedBytes;
    add(addresses, remoteIp, bytes);
    if (remotePort !== null) add(ports, `${protocol} ${remotePort}`, bytes);
    add(countries, locations.get(remoteIp) ?? 'Unknown', bytes);
  }
  for (const app of traffic?.applications ?? [])
    add(apps, app.process.name, app.sentBytes + app.receivedBytes + app.localBytes);

  return (
    <div className="dashboard">
      <section className="soft-panel capture-panel">
        <div className="panel-heading capture-table-heading"><h2>Live analysis window</h2>
          <label>Timeline range<select aria-label="Timeline range" value={seconds} onChange={event => setSeconds(Number(event.target.value))}>
            <option value={60}>Last minute</option><option value={300}>Last 5 minutes</option>
          </select></label>
        </div>
        <p>Timeline shows samples received since the current stream connected. Protocols use recent packets. Country, IP, and port rankings use up to 50 recent flows, while application rankings use attributed session totals.</p>
      </section>
      <TrafficPanels samples={timeline} packets={traffic?.recentPackets} seconds={seconds} />
      <section className="soft-panel capture-panel" aria-labelledby="packet-rate-title">
        <h2 id="packet-rate-title">Packets per second</h2>
        {timeline.length ? <div className="plot plot-with-data inset-surface">
          <RatePlot samples={timeline} seconds={seconds} packetRate />
        </div> : <p>Packet rate appears after capture starts.</p>}
      </section>
      <div className="analytics-rankings">
        <Ranking title="Traffic by country" data={countries} />
        <Ranking title="Traffic by application" data={apps} />
        <Ranking title="Most active remote IPs" data={addresses} />
        <Ranking title="Most active remote ports" data={ports} />
      </div>
    </div>
  );
}
