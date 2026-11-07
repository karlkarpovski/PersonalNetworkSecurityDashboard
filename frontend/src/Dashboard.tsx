import {
  Activity, ArrowDown, ArrowUp, ArrowUpRight, Boxes, ChartNoAxesColumn,
  CircleAlert, Globe2, Network, Radio, ShieldAlert, Wifi,
} from 'lucide-react';

const metrics = [
  { label: 'Download speed', icon: ArrowDown, tone: 'inbound' },
  { label: 'Upload speed', icon: ArrowUp, tone: 'outbound' },
  { label: 'Packets received', icon: ArrowDown, tone: 'inbound' },
  { label: 'Packets sent', icon: ArrowUp, tone: 'outbound' },
  { label: 'Active connections', icon: Network, tone: 'neutral' },
  { label: 'Unique remote IPs', icon: Globe2, tone: 'neutral' },
  { label: 'Security alerts', icon: ShieldAlert, tone: 'neutral' },
  { label: 'Session usage', icon: Activity, tone: 'neutral' },
] as const;

function Metrics() {
  return (
    <dl className="metrics" aria-label="Session metrics">
      {metrics.map(({ label, icon: Icon, tone }) => (
        <div className="metric soft-panel" key={label}>
          <dt>{label}<span className={`metric-icon ${tone}`}><Icon size={17} aria-hidden="true" /></span></dt>
          <dd><span aria-hidden="true">—</span><span className="sr-only">Unavailable</span></dd>
        </div>
      ))}
    </dl>
  );
}

export function TrafficPanels() {
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
        <div className="plot inset-surface">
          <div className="empty-plot">
            <ChartNoAxesColumn size={24} aria-hidden="true" />
            <strong>No traffic samples</strong>
            <span>Throughput will appear when capture is available.</span>
          </div>
        </div>
      </section>
      <section className="soft-panel chart-panel" aria-labelledby="protocol-title">
        <div className="panel-heading"><h2 id="protocol-title">Protocol distribution</h2></div>
        <div className="protocol-body">
          <div className="protocol-ring">
            <div><Activity size={20} aria-hidden="true" /><span>No samples</span></div>
          </div>
          <ul className="protocol-list" aria-label="Tracked protocol categories">
            {['TCP', 'UDP', 'ICMP', 'Other'].map(protocol => (
              <li key={protocol}>{protocol}<span aria-label="Unavailable">—</span></li>
            ))}
          </ul>
        </div>
      </section>
    </div>
  );
}

export function GeographyPanel({ showLink = false }: { showLink?: boolean }) {
  return (
    <section className="soft-panel geography" aria-labelledby="geography-title">
      <div className="panel-heading">
        <h2 id="geography-title">Global traffic</h2>
        {showLink && <a className="panel-link" href="#map">Open map <ArrowUpRight size={15} aria-hidden="true" /></a>}
      </div>
      <div className="geography-body">
        <div className="basemap inset-surface">
          <img src={`${import.meta.env.BASE_URL}world-land.svg`} alt="" width={720} height={320} />
          <span className="panel-chip map-caption">Basemap · no endpoints</span>
        </div>
        <div className="country-list inset-surface">
          <h3>Top destination countries</h3>
          <p>Countries will appear when captured endpoints have location data.</p>
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

export function Dashboard() {
  return (
    <div className="dashboard">
      <div className="capture-note inset-surface">
        <Wifi size={18} aria-hidden="true" />
        <p><strong>Capture unavailable</strong><span>Traffic panels will populate after adapter monitoring is available.</span></p>
      </div>
      <Metrics />
      <TrafficPanels />
      <GeographyPanel showLink />
      <div className="activity-row">
        {activityPanels.map(({ title, page, icon: Icon, empty }) => (
          <section className="soft-panel activity-panel" key={page}>
            <div className="panel-heading">
              <h2><Icon size={17} aria-hidden="true" />{title}</h2>
              <a className="panel-link" href={`#${page}`} aria-label={`Open ${title.toLowerCase()}`}>
                <ArrowUpRight size={17} aria-hidden="true" />
              </a>
            </div>
            <p>{empty}</p>
          </section>
        ))}
      </div>
    </div>
  );
}
