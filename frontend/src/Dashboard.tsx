import {
  Activity, ArrowDown, ArrowUp, ArrowUpRight, Boxes, ChartNoAxesColumn,
  CircleAlert, Globe2, Network, Radio, ShieldAlert, Wifi,
} from 'lucide-react';
import { formatBytes } from './capture/captureApi';
import type { CaptureView, Packet } from './capture/captureApi';
import type { RateSample } from './capture/useCaptureStream';
import type { GeoSnapshot } from './geo/geoTypes';
import { ruleNames } from './security/securityTypes';
import type { AlertSummary } from './security/securityTypes';

const metrics = [
  { label: 'Download speed', icon: ArrowDown, tone: 'inbound' },
  { label: 'Upload speed', icon: ArrowUp, tone: 'outbound' },
  { label: 'Packets received', icon: ArrowDown, tone: 'inbound' },
  { label: 'Packets sent', icon: ArrowUp, tone: 'outbound' },
  { label: 'Active IP flows', icon: Network, tone: 'neutral' },
  { label: 'Unique remote IPs', icon: Globe2, tone: 'neutral' },
  { label: 'Open security alerts', icon: ShieldAlert, tone: 'neutral' },
  { label: 'Session usage', icon: Activity, tone: 'neutral' },
] as const;

function Metrics({ traffic, openAlerts }: { traffic?: CaptureView['traffic']; openAlerts?: number }) {
  const values = traffic ? [
    `${formatBytes(traffic.downloadBytesPerSecond)}/s`, `${formatBytes(traffic.uploadBytesPerSecond)}/s`,
    traffic.inboundPackets.toLocaleString(), traffic.outboundPackets.toLocaleString(),
    traffic.activeFlows.toLocaleString(), `${traffic.uniqueRemoteIps.toLocaleString()}${traffic.remoteIpLimitReached ? '+' : ''}`,
    null, formatBytes(traffic.sessionBytes),
  ] : [];
  return (
    <dl className="metrics" aria-label="Session metrics">
      {metrics.map(({ label, icon: Icon, tone }, index) => (
        <div className="metric soft-panel" key={label}>
          <dt>{label}<span className={`metric-icon ${tone}`}><Icon size={17} aria-hidden="true" /></span></dt>
          <dd>{(label === 'Open security alerts' ? openAlerts?.toLocaleString() : values[index]) ??
            <><span aria-hidden="true">—</span><span className="sr-only">Unavailable</span></>}</dd>
        </div>
      ))}
    </dl>
  );
}

const protocolColors = { TCP: '#5faeff', UDP: '#9d95ff', ICMP: '#88e8b6', Other: '#b2bed3' } as const;

export function RatePlot({ samples, seconds = 60, packetRate = false }: {
  samples: RateSample[]; seconds?: number; packetRate?: boolean;
}) {
  const width = 600, height = 168;
  const series = packetRate ? ['packets'] as const : ['inbound', 'outbound'] as const;
  const maximum = Math.max(0, ...samples.flatMap(sample => series.map(key => sample[key] ?? 0)));
  const peak = packetRate ? `${maximum.toLocaleString()} packets/s` : `${formatBytes(maximum)}/s`;
  const end = Date.parse(samples.at(-1)!.at);
  const coordinates = (sample: RateSample, key: (typeof series)[number]) => {
    const x = Math.max(3, width - 3 - (end - Date.parse(sample.at)) / (seconds * 1000) * (width - 6));
    return [x, height - 3 - (height - 6) * (sample[key] ?? 0) / Math.max(1, maximum)] as const;
  };
  return (
    <div className="rate-chart">
      <span>{peak} peak</span>
      <svg viewBox={`0 0 ${width} ${height}`} preserveAspectRatio="none" role="img"
        aria-label={`${packetRate ? 'Packet rate' : 'Download and upload rates'} across ${samples.length} samples, peak ${peak}`}>
        {series.map(direction => (
          <g className={direction === 'packets' ? 'packet-rate-series' : direction} key={direction}>
            <polyline points={samples.map(sample => coordinates(sample, direction).join(',')).join(' ')}
              fill="none" stroke="currentColor" strokeWidth={2} vectorEffect="non-scaling-stroke" />
            {samples.length === 1 && <circle cx={coordinates(samples[0], direction)[0]} cy={coordinates(samples[0], direction)[1]} r={3} fill="currentColor" />}
          </g>
        ))}
      </svg>
      <span>{seconds === 60 ? 'Last minute' : 'Last 5 minutes'}</span>
    </div>
  );
}

export function TrafficPanels({ samples, packets = [], seconds = 60 }: {
  samples: RateSample[]; packets?: Packet[]; seconds?: number;
}) {
  const counts = { TCP: 0, UDP: 0, ICMP: 0, Other: 0 };
  for (const { protocol } of packets) {
    if (protocol === 'TCP' || protocol === 'UDP') counts[protocol]++;
    else if (protocol === 'ICMP' || protocol === 'ICMPv6') counts.ICMP++;
    else counts.Other++;
  }
  const entries = Object.entries(counts) as [keyof typeof counts, number][];
  let offset = 0;
  const slices = packets.length ? entries.filter(([, count]) => count > 0).map(([protocol, count]) => {
    const start = offset;
    offset += count;
    return `${protocolColors[protocol]} ${start / packets.length * 100}% ${offset / packets.length * 100}%`;
  }) : [];
  return (
    <div className="chart-row">
      <section className="soft-panel chart-panel" aria-labelledby="throughput-title">
        <div className="panel-heading">
          <h2 id="throughput-title">Traffic overview</h2>
          <span className="panel-chip">Current session</span>
        </div>
        <ul className="legend" aria-label="Traffic directions">
          <li><i className="dot inbound" /> Download</li>
          <li><i className="dot outbound" /> Upload</li>
        </ul>
        <div className={`plot inset-surface ${samples.length ? 'plot-with-data' : ''}`}>
          {samples.length ? <RatePlot samples={samples} seconds={seconds} /> : <div className="empty-plot">
            <ChartNoAxesColumn size={24} aria-hidden="true" />
            <strong>No traffic samples</strong>
            <span>Throughput history appears after capture starts.</span>
          </div>}
        </div>
      </section>
      <section className="soft-panel chart-panel" aria-labelledby="protocol-title">
        <div className="panel-heading"><h2 id="protocol-title">Protocol distribution</h2></div>
        <div className="protocol-body">
          <div className={`protocol-ring ${packets.length ? 'protocol-ring-data' : ''}`}
            style={slices.length ? { background: `conic-gradient(${slices.join(', ')})` } : undefined}>
            <div><Activity size={20} aria-hidden="true" /><span>{packets.length ? `${packets.length} packets` : 'No samples'}</span></div>
          </div>
          <ul className="protocol-list" aria-label="Tracked protocol categories">
            {entries.map(([protocol, count]) => (
              <li key={protocol}><span><i className="dot" style={{ color: protocolColors[protocol] }} /> {protocol}</span>
                <span aria-label={packets.length ? undefined : 'Unavailable'}>{packets.length ? count : '—'}</span></li>
            ))}
          </ul>
        </div>
      </section>
    </div>
  );
}

function GeographyPanel({ capture, geo }: { capture?: CaptureView; geo?: GeoSnapshot }) {
  const resolved = new Map(geo?.endpoints.map(result => [result.ip, result]));
  const totals = new Map<string, { country: string; volume: number }>();
  for (const flow of capture?.traffic?.recentFlows ?? []) {
    const result = resolved.get(flow.endpoint.remoteIp);
    if (!result?.country) continue;
    const key = result.countryCode ?? result.country;
    const volume = (totals.get(key)?.volume ?? 0) + flow.sentBytes + flow.receivedBytes;
    totals.set(key, { country: result.country, volume });
  }
  const countries = [...totals.values()].sort((left, right) => right.volume - left.volume).slice(0, 5);
  return (
    <section className="soft-panel geography" aria-labelledby="geography-title">
      <div className="panel-heading">
        <h2 id="geography-title">Global traffic</h2>
        <a className="panel-link" href="#map">Open map <ArrowUpRight size={15} aria-hidden="true" /></a>
      </div>
      <div className="geography-body">
        <div className="basemap inset-surface">
          <img src={`${import.meta.env.BASE_URL}world-land.svg`} alt="" width={720} height={320} />
          <span className="panel-chip map-caption">Basemap · open globe for routes</span>
        </div>
        <div className="country-list inset-surface">
          <h3>Top destination countries</h3>
          {countries.length ? <>
            <p>By transferred bytes in recent captured flows.</p>
            <ol className="country-rank">
              {countries.map(({ country, volume }) => <li key={country}><span>{country}</span><strong>{formatBytes(volume)}</strong></li>)}
            </ol>
          </> : <p>Countries will appear when captured endpoints have location data.</p>}
        </div>
      </div>
    </section>
  );
}

const activityPanels = [
  { title: 'Top applications', page: 'applications', icon: Boxes, empty: 'Waiting for process-attributed traffic.' },
  { title: 'Recent alerts', page: 'alerts', icon: CircleAlert, empty: 'Alert monitoring is unavailable.' },
  { title: 'Live activity', page: 'packets', icon: Radio, empty: 'Waiting for packet capture.' },
];

export function Dashboard({ capture, geo, security, samples, streamLabel }: {
  capture?: CaptureView; geo?: GeoSnapshot; security?: AlertSummary; samples: RateSample[]; streamLabel: string;
}) {
  const running = capture?.state === 'running';
  const applications = capture?.traffic?.applications?.slice(0, 3) ?? [];
  const captureLabel = !capture ? streamLabel
    : running ? 'Capture running'
    : capture?.state === 'unavailable' ? 'Capture unavailable'
    : capture?.state === 'error' ? 'Capture error'
    : capture?.state === 'stopped' ? 'Capture stopped'
    : 'Capture idle';
  return (
    <div className="dashboard">
      <div className={`capture-note inset-surface ${running ? 'capture-running' : ''}`}>
        <Wifi size={18} aria-hidden="true" />
        <p><strong>{captureLabel}</strong>
          <span>{capture?.message ?? (running ? capture.adapter : 'Select a Windows adapter to start monitoring.')}</span>
          <a href="#packets">Open packet monitor</a>
        </p>
      </div>
      <Metrics traffic={capture?.traffic} openAlerts={security?.open} />
      <TrafficPanels samples={samples.slice(-60)} packets={capture?.traffic?.recentPackets} />
      <GeographyPanel capture={capture} geo={geo} />
      <div className="activity-row">
        {activityPanels.map(({ title, page, icon: Icon, empty }) => (
          <section className="soft-panel activity-panel" key={page}>
            <div className="panel-heading">
              <h2><Icon size={17} aria-hidden="true" />{title}</h2>
              <a className="panel-link" href={`#${page}`} aria-label={`Open ${title.toLowerCase()}`}>
                <ArrowUpRight size={17} aria-hidden="true" />
              </a>
            </div>
            {page === 'applications' && applications.length ? <ol className="country-rank">
              {applications.map(({ process, sentBytes, receivedBytes, localBytes }) =>
                <li key={`${process.pid}/${process.startedAt}`}><span>{process.name} · {process.pid}</span>
                  <strong>{formatBytes(sentBytes + receivedBytes + localBytes)}</strong></li>)}
            </ol> : page === 'alerts' && security ? (
              security.recent.length ? <ol className="country-rank">
                {security.recent.slice(0, 3).map(alert => <li key={alert.id}>
                  <span>{ruleNames[alert.rule] ?? alert.rule}</span>
                  <strong className={`severity-${alert.severity}`}>{alert.severity}</strong>
                </li>)}
              </ol> : <p>No alerts recorded.</p>
            ) : <p>{empty}</p>}
          </section>
        ))}
      </div>
    </div>
  );
}
