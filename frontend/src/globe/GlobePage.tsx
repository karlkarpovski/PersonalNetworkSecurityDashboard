import { useEffect, useMemo, useRef, useState } from 'react';
import { Minus, Plus, RotateCcw } from 'lucide-react';
import { flowDirection } from './routeTypes';
import type { RouteFlow, VisibleFlow } from './routeTypes';
import { formatBytes } from '../capture/captureApi';
import type { Flow } from '../capture/captureApi';
import { GeoDetails, locationStatus } from '../geo/GeoPanels';
import type { GeoSnapshot } from '../geo/geoTypes';
import { groupEndpoints } from './liveEndpoints';
import { renderGlobe } from './renderGlobe';
import './globe.css';

const noFlows: Flow[] = [];
const noFlags: string[] = [];

export default function GlobePage({ flows = noFlows, geo, flaggedIps = noFlags }: {
  flows?: Flow[]; geo?: GeoSnapshot; flaggedIps?: string[];
}) {
  const host = useRef<HTMLDivElement>(null);
  const engine = useRef<ReturnType<typeof renderGlobe>>(null);
  const [error, setError] = useState('');
  const [selectedIp, setSelectedIp] = useState<string>();
  const [direction, setDirection] = useState('all');
  const [protocol, setProtocol] = useState('all');
  const [family, setFamily] = useState('all');
  const [risk, setRisk] = useState('all');
  const [search, setSearch] = useState('');
  const [limit, setLimit] = useState(6);
  const [lowDetail, setLowDetail] = useState(false);
  const [speed, setSpeed] = useState(1);
  const [rotate, setRotate] = useState(false);
  const [animate, setAnimate] = useState(() => !window.matchMedia('(prefers-reduced-motion: reduce)').matches);

  const { visible, liveEndpoints } = useMemo(() => {
    const query = search.trim().toLowerCase();
    function matches(flow: { ip: string; inbound: number; outbound: number }, geography: string) {
      if (family !== 'all' && flow.ip.includes(':') !== (family === '6')) return false;
      if (direction === 'bidirectional' && flowDirection(flow) !== direction) return false;
      if (direction === 'inbound' && !flow.inbound) return false;
      if (direction === 'outbound' && !flow.outbound) return false;
      return `${flow.ip} ${geography}`.toLowerCase().includes(query);
    }
    function route(flow: RouteFlow): VisibleFlow {
      return { flow, directions: [
        ...(flow.outbound && direction !== 'inbound' ? ['outbound' as const] : []),
        ...(flow.inbound && direction !== 'outbound' ? ['inbound' as const] : []),
      ] };
    }
    const liveEndpoints = groupEndpoints(flows, geo?.endpoints ?? [], protocol).filter(endpoint =>
      (risk !== 'flagged' || flaggedIps.includes(endpoint.ip)) &&
        matches(endpoint, `${endpoint.location?.city ?? ''} ${endpoint.location?.region ?? ''} ${endpoint.location?.country ?? ''}`));
    const visible = geo?.origin ? liveEndpoints.flatMap(endpoint => {
      const result = endpoint.location;
      if (result?.latitude == null || result.longitude == null) return [];
      return [route({
        ip: endpoint.ip, lat: result.latitude, lng: result.longitude, city: result.city ?? '',
        country: result.country ?? '', protocol: [...endpoint.protocols].join(', '), port: null,
        inbound: endpoint.inbound, outbound: endpoint.outbound, flagged: flaggedIps.includes(endpoint.ip),
      })];
    }).slice(0, limit) : [];
    return { visible, liveEndpoints };
  }, [direction, family, flows, geo, limit, protocol, risk, search, flaggedIps]);
  const selectedLive = liveEndpoints.find(endpoint => endpoint.ip === selectedIp);
  const liveOrigin = geo?.origin;

  useEffect(() => {
    if (!host.current) return;
    try {
      const instance = renderGlobe(host.current, setSelectedIp, setError);
      engine.current = instance;
      return () => {
        engine.current = null;
        instance.dispose();
      };
    } catch {
      setError('3D graphics are unavailable in this environment. You can still browse endpoints.');
    }
  }, []);

  useEffect(() => {
    const source = liveOrigin ? { lat: liveOrigin.latitude, lng: liveOrigin.longitude } : null;
    engine.current?.setFlows(visible, source, selectedLive?.ip, lowDetail);
  }, [visible, liveOrigin, selectedLive?.ip, lowDetail]);

  useEffect(() => {
    engine.current?.setMotion(animate, rotate, speed);
  }, [animate, rotate, speed]);

  return (
    <section className="soft-panel globe-panel" aria-labelledby="globe-title">
      <div className="panel-heading globe-heading">
        <h2 id="globe-title">Global traffic globe</h2>
      </div>
      <p className="globe-mode" role="status">
        {liveOrigin ? `Capture view · origin near ${liveOrigin.label}` : 'Capture view · approximate origin required'}
      </p>
      {!liveOrigin && <p className="globe-note"><a href="#settings">Configure an approximate origin</a> to draw live routes.</p>}
      {liveOrigin?.accuracyRadiusKm != null && <p className="globe-note">Origin accuracy radius {liveOrigin.accuracyRadiusKm.toLocaleString()} km</p>}
      <fieldset className="globe-filters" disabled={!flows.length}>
        <legend className="sr-only">Filter traffic endpoints</legend>
        <label>Direction<select aria-label="Direction" value={direction} onChange={event => setDirection(event.target.value)}>
          <option value="all">All directions</option><option value="outbound">Outbound</option>
          <option value="inbound">Inbound</option><option value="bidirectional">Bidirectional only</option>
        </select></label>
        <label>Protocol<select aria-label="Protocol" value={protocol} onChange={event => setProtocol(event.target.value)}>
          <option value="all">All protocols</option><option>TCP</option><option>UDP</option><option>ICMP</option>
        </select></label>
        <label>Address family<select aria-label="Address family" value={family} onChange={event => setFamily(event.target.value)}>
          <option value="all">IPv4 and IPv6</option><option value="4">IPv4</option><option value="6">IPv6</option>
        </select></label>
        <label>Risk<select aria-label="Risk" value={risk} onChange={event => setRisk(event.target.value)}>
          <option value="all">All endpoints</option><option value="flagged">Open high alert</option>
        </select></label>
        <label>Find endpoint<input type="search" value={search} placeholder="IP, city, or country"
          onChange={event => setSearch(event.target.value)} /></label>
      </fieldset>
      <div className="globe-layout">
        <div className="globe-visualization">
          <div className="globe-stage inset-surface">
            <div className="globe-canvas" ref={host} tabIndex={0} role="region"
              aria-label="Interactive globe" aria-describedby="globe-controls-hint" onKeyDown={event => {
                const movement = {
                  ArrowLeft: [-0.17, 0], ArrowRight: [0.17, 0],
                  ArrowUp: [0, -0.17], ArrowDown: [0, 0.17],
                }[event.key];
                if (!movement || !engine.current) return;
                event.preventDefault();
                engine.current.rotate(movement[0], movement[1]);
              }} />
            {error && <p className="globe-error" role="alert">{error}</p>}
            <div className="globe-camera" aria-label="Camera controls">
              <button className="icon-button" type="button" aria-label="Zoom in" title="Zoom in"
                onClick={() => engine.current?.zoom(0.82)}><Plus size={18} aria-hidden="true" /></button>
              <button className="icon-button" type="button" aria-label="Zoom out" title="Zoom out"
                onClick={() => engine.current?.zoom(1.22)}><Minus size={18} aria-hidden="true" /></button>
              <button className="icon-button" type="button" aria-label="Reset camera" title="Reset camera"
                onClick={() => engine.current?.reset()}><RotateCcw size={16} aria-hidden="true" /></button>
            </div>
            <span className="panel-chip globe-caption" id="globe-controls-hint">Drag or use arrow keys to rotate · Scroll to zoom · Double-click to focus</span>
          </div>
          <ul className="legend globe-legend" aria-label="Route legend">
            <li><i className="dot outbound" /> Outbound</li>
            <li><i className="dot inbound" /> Inbound</li>
            <li><i className="dot flagged" /> Open high alert</li>
          </ul>
          <p className="globe-note">Arcs show communication between approximate endpoint locations. Physical network paths are unknown.</p>
          <div className="globe-controls" aria-label="Globe performance and motion">
            <label><input type="checkbox" checked={animate} onChange={event => setAnimate(event.target.checked)} /> Animate particles</label>
            <label><input type="checkbox" checked={rotate} onChange={event => setRotate(event.target.checked)} /> Auto-rotate</label>
            <label><input type="checkbox" checked={lowDetail} onChange={event => setLowDetail(event.target.checked)} /> Performance mode</label>
            <label>Speed<select aria-label="Speed" value={speed} onChange={event => setSpeed(Number(event.target.value))}>
              <option value={0.5}>0.5×</option><option value={1}>1×</option><option value={2}>2×</option>
            </select></label>
            <label>Endpoint limit<select aria-label="Endpoint limit" value={limit} onChange={event => setLimit(Number(event.target.value))}>
              <option value={2}>2</option><option value={4}>4</option><option value={6}>6</option>
              <option value={12}>12</option><option value={24}>24</option>
            </select></label>
          </div>
        </div>
        <aside className="globe-inspector inset-surface" aria-labelledby="endpoints-title">
          <h3 id="endpoints-title">Recent captured endpoints</h3>
          {liveEndpoints.length ? (
            <>
              <p>{visible.length} mapped {visible.length === 1 ? 'destination' : 'destinations'} · {liveEndpoints.length} matching captured addresses</p>
              <ul className="endpoint-list live-endpoint-list">
                {liveEndpoints.map(endpoint => {
                  const point = endpoint.location;
                  return <li key={endpoint.ip}>
                    <button type="button" className="endpoint-button" aria-pressed={selectedLive?.ip === endpoint.ip} onClick={() => {
                      setSelectedIp(endpoint.ip);
                      if (point?.latitude != null && point.longitude != null) engine.current?.focusOn({ lat: point.latitude, lng: point.longitude });
                    }}>
                      <span><strong>{point?.city ?? point?.country ?? endpoint.ip}</strong>
                        <small>{point?.status === 'located' ? endpoint.ip : point ? locationStatus(point) : 'Location unavailable'}</small></span>
                      <small>{formatBytes(endpoint.inbound + endpoint.outbound)}</small>
                    </button>
                  </li>;
                })}
              </ul>
            </>
          ) : <p>{flows.length ? 'No captured endpoints match these filters.'
            : 'Waiting for captured flows.'}</p>}
          {selectedLive && (
            <div className="endpoint-details">
              <h3>{selectedLive.ip}</h3>
              {flaggedIps.includes(selectedLive.ip) && <p className="flagged"><a href="#alerts">Review open high alert</a></p>}
              {selectedLive.location && <GeoDetails result={selectedLive.location} />}
              <dl>
                <dt>Protocols</dt><dd>{[...selectedLive.protocols].join(', ')}</dd>
                <dt>Remote ports</dt><dd>{[...selectedLive.ports].sort((left, right) => left - right).join(', ') || 'Unavailable'}</dd>
                <dt>Direction</dt><dd className="direction-value">{flowDirection(selectedLive)}</dd>
                <dt>Packets</dt><dd>{selectedLive.packets.toLocaleString()}</dd>
                <dt>Sent</dt><dd>{formatBytes(selectedLive.outbound)}</dd>
                <dt>Received</dt><dd>{formatBytes(selectedLive.inbound)}</dd>
              </dl>
              <a href="#connections">View captured flows</a>
            </div>
          )}
        </aside>
      </div>
    </section>
  );
}
