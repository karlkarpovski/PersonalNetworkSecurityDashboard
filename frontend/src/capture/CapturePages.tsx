import { useEffect, useState } from 'react';
import { captureRequest, formatBytes } from './captureApi';
import type { Adapter, AdapterResult, CaptureView, Packet } from './captureApi';
import type { GeoSnapshot } from '../geo/geoTypes';
import './capture.css';

const labels = {
  idle: 'Ready to select an adapter',
  running: 'Capturing',
  stopped: 'Capture stopped',
  unavailable: 'Capture unavailable',
  error: 'Capture error',
};

function endpoint(ip: string, port: number | null) {
  if (port === null) return ip;
  return ip.includes(':') ? `[${ip}]:${port}` : `${ip}:${port}`;
}

export function CaptureAccessForm({ rejected, unlock }: { rejected: boolean; unlock: (code: string) => void }) {
  const [input, setInput] = useState('');
  const code = input.trim().toUpperCase();
  return (
    <section className="soft-panel capture-panel access-panel" aria-labelledby="access-title">
      <h2 id="access-title">Unlock live monitoring</h2>
      <p>Paste the dashboard access code shown in the local API terminal.</p>
      {rejected && <p className="capture-warning" role="alert">The access code was rejected. Use the code from the current API session.</p>}
      <form className="capture-controls" onSubmit={event => {
        event.preventDefault();
        if (/^[0-9A-F]{48}$/.test(code)) unlock(code);
      }}>
        <label htmlFor="dashboard-code">Dashboard access code
          <input id="dashboard-code" type="password" value={input} autoComplete="off" spellCheck={false}
            onChange={event => setInput(event.target.value)} />
        </label>
        <button className="capture-button" type="submit" disabled={!/^[0-9A-F]{48}$/.test(code)}>Unlock</button>
      </form>
    </section>
  );
}

export function CaptureControls({ view, offline, code }: {
  view?: CaptureView;
  offline: boolean;
  code: string;
}) {
  const [adapters, setAdapters] = useState<Adapter[]>([]);
  const [selected, setSelected] = useState('');
  const [error, setError] = useState('');
  const [pending, setPending] = useState(false);
  const [listVersion, setListVersion] = useState(0);
  const running = view?.state === 'running';

  useEffect(() => {
    if (offline) return;
    const controller = new AbortController();
    setPending(true);
    setError('');
    captureRequest<AdapterResult>(code, 'adapters', { signal: controller.signal }).then(result => {
      if (controller.signal.aborted) return;
      setAdapters(result.adapters);
      setSelected(previous => result.adapters.some(adapter => adapter.id === previous) ? previous : '');
      setError(result.error ?? '');
    }).catch(reason => {
      if (!controller.signal.aborted) setError(reason.message);
    }).finally(() => {
      if (!controller.signal.aborted) setPending(false);
    });
    return () => controller.abort();
  }, [code, listVersion, offline]);

  async function changeCapture() {
    setPending(true);
    setError('');
    try {
      if (running) await captureRequest<void>(code, 'stop', { method: 'POST' });
      else await captureRequest<void>(code, 'start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ adapterId: selected }),
      });
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'Capture request failed.');
    } finally {
      setPending(false);
    }
  }

  const message = error || view?.message;
  return (
    <section className="soft-panel capture-panel" aria-labelledby="capture-title">
      <div className="panel-heading">
        <h2 id="capture-title">Windows capture</h2>
        <span className={`panel-chip ${running ? 'capture-running' : ''}`} role="status">
          {offline ? 'Waiting for live stream' : view ? labels[view.state] : 'Checking capture service'}
        </span>
      </div>
      {view?.adapter && <p>Session adapter <strong>{view.adapter}</strong></p>}
      <p>Choose an adapter you own or are authorized to monitor. This session keeps IP and transport metadata in memory.</p>
      <div className="capture-controls">
        <label htmlFor="capture-adapter">Capture adapter
          <select id="capture-adapter" value={selected} onChange={event => setSelected(event.target.value)}
            disabled={running || offline || pending}>
            <option value="">Select an adapter</option>
            {adapters.map(adapter => (
              <option value={adapter.id} key={adapter.id} disabled={adapter.linkStatus !== null && adapter.linkStatus !== 'Up'}>
                {adapter.name}{adapter.linkStatus ? ` · ${adapter.linkStatus}` : ''}
              </option>
            ))}
          </select>
        </label>
        <button type="button" className="capture-button" disabled={offline || pending}
          onClick={() => setListVersion(value => value + 1)}>Refresh adapters</button>
        <button type="button" className="capture-button" disabled={offline || pending || !view || (!running && !selected)}
          onClick={() => void changeCapture()}>{running ? 'Stop capture' : 'Start capture'}</button>
      </div>
      {message && <p className="capture-warning" role="alert">{message}</p>}
    </section>
  );
}

export function PacketPanel({ view }: { view?: CaptureView }) {
  const [search, setSearch] = useState('');
  const query = search.trim().toLowerCase();
  const packets = view?.traffic?.recentPackets ?? [];
  const matching = packets.filter(packet =>
    `${endpoint(packet.source, packet.sourcePort)} ${endpoint(packet.destination, packet.destinationPort)} ${packet.protocol} ${packet.direction} ${packet.owner?.process.name ?? ''} ${packet.owner?.process.pid ?? ''}`
      .toLowerCase().includes(query));
  return (
    <section className="soft-panel capture-panel" aria-labelledby="recent-packets-title">
      <div className="panel-heading capture-table-heading">
        <h2 id="recent-packets-title">Recent packets</h2>
        <label>Filter packets <input type="search" value={search} onChange={event => setSearch(event.target.value)} /></label>
      </div>
      {view?.traffic && (
        <p>Queue drops {view.queueDrops.toLocaleString()} · Driver drops {view.driverDrops?.toLocaleString() ?? 'unavailable'} · Skipped frames {view.skippedFrames.toLocaleString()} · Local {view.traffic.localPackets.toLocaleString()} · Unknown {view.traffic.unknownPackets.toLocaleString()}</p>
      )}
      {matching.length === 0 ? <p>{packets.length ? 'No packets match this filter.' : 'Waiting for captured IP metadata.'}</p> : (
        <PacketTable packets={matching} />
      )}
    </section>
  );
}

export function PacketTable({ packets }: { packets: Packet[] }) {
  return (
    <div className="capture-table-wrap" tabIndex={0} role="region" aria-label="Packet metadata table">
      <table className="capture-table">
        <thead><tr><th>Time</th><th>Direction</th><th>Source</th><th>Destination</th><th>Protocol</th><th>Size</th><th>Observed process</th></tr></thead>
        <tbody>{packets.map((packet, index) => (
          <tr key={packet.sequence ?? `${packet.timestamp}-${index}`}>
            <td><time dateTime={packet.timestamp} title={packet.timestamp}>{new Date(packet.timestamp).toLocaleTimeString()}</time></td>
            <td className={`capture-direction ${packet.direction}`}>{packet.direction}</td>
            <td>{endpoint(packet.source, packet.sourcePort)}</td><td>{endpoint(packet.destination, packet.destinationPort)}</td>
            <td>{packet.protocol}</td><td>{formatBytes(packet.length)}</td>
            <td>{packet.owner ? `${packet.owner.process.name} · ${packet.owner.process.pid}` : 'Unattributed'}</td>
          </tr>
        ))}</tbody>
      </table>
    </div>
  );
}

export function FlowPanel({ view, geo }: { view?: CaptureView; geo?: GeoSnapshot }) {
  const [search, setSearch] = useState('');
  const [sort, setSort] = useState('recent');
  const flows = view?.traffic?.recentFlows ?? [];
  const query = search.trim().toLowerCase();
  const countries = new Map(geo?.endpoints.map(result => [result.ip, result.country]));
  const matching = flows.filter(flow =>
    `${flow.endpoint.localIp} ${flow.endpoint.remoteIp} ${flow.endpoint.protocol} ${flow.owner?.process.name ?? ''} ${flow.owner?.process.pid ?? ''}`.toLowerCase().includes(query));
  if (sort === 'bytes') matching.sort((left, right) => (right.sentBytes + right.receivedBytes) - (left.sentBytes + left.receivedBytes));
  const misses = view?.traffic?.flowCapacityMisses ?? 0;
  return (
    <section className="soft-panel capture-panel" aria-labelledby="flow-title">
      <div className="panel-heading capture-table-heading"><h2 id="flow-title">Observed IP flows</h2>
        <label>Filter flows<input type="search" value={search} onChange={event => setSearch(event.target.value)} /></label>
        <label>Sort flows<select aria-label="Sort flows" value={sort} onChange={event => setSort(event.target.value)}>
          <option value="recent">Last seen</option><option value="bytes">Transferred bytes</option>
        </select></label>
      </div>
      <p>Showing up to 50 recent flows. Owner labels describe sampled Windows socket matches. Flow totals include unattributed packets.</p>
      {misses > 0 && <p className="capture-warning">{misses.toLocaleString()} packets could not be grouped because the flow table reached capacity.</p>}
      {matching.length === 0 ? <p>{flows.length ? 'No flows match this filter.' : 'Waiting for packets with an attributable direction.'}</p> : (
        <div className="capture-table-wrap" tabIndex={0} role="region" aria-label="Observed flow table">
          <table className="capture-table">
            <thead><tr><th>Local endpoint</th><th>Remote endpoint</th><th>Protocol</th><th>Sampled TCP state</th><th>Observed process</th><th>Country</th><th>Packets</th><th>Sent</th><th>Received</th><th>First seen</th><th>Last seen</th></tr></thead>
            <tbody>{matching.map(({ endpoint: pair, packets, sentBytes, receivedBytes, firstSeen, lastSeen, owner, conflictingOwners }) => (
              <tr key={JSON.stringify(pair)}>
                <td>{endpoint(pair.localIp, pair.localPort)}</td><td>{endpoint(pair.remoteIp, pair.remotePort)}</td>
                <td>{pair.protocol}</td><td>{owner?.tcpState ?? 'Unavailable'}</td>
                <td>{conflictingOwners ? 'Multiple observed owners' : owner ? `${owner.process.name} · ${owner.process.pid}` : 'Unattributed'}</td>
                <td>{countries.get(pair.remoteIp) ?? 'Unknown'}</td><td>{packets.toLocaleString()}</td><td>{formatBytes(sentBytes)}</td>
                <td>{formatBytes(receivedBytes)}</td><td>{new Date(firstSeen).toLocaleTimeString()}</td><td>{new Date(lastSeen).toLocaleTimeString()}</td>
              </tr>
            ))}</tbody>
          </table>
        </div>
      )}
    </section>
  );
}
