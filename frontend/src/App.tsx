import { useEffect, useState } from 'react';
import {
  Activity, Boxes, Cable, ChartNoAxesColumn, Globe2, History, LayoutDashboard,
  RefreshCw, Search, Settings, Shield, ShieldAlert,
} from 'lucide-react';
import { Dashboard, GeographyPanel, TrafficPanels } from './Dashboard';

const pages = [
  { id: 'overview', title: 'Overview', detail: 'Traffic, destinations, and security activity for this device.', icon: LayoutDashboard },
  { id: 'map', title: 'Global Traffic Map', detail: 'Explore approximate locations of observed network endpoints.', icon: Globe2 },
  { id: 'packets', title: 'Live Packet Monitor', detail: 'Packet metadata will appear here after adapter capture is available.', icon: Activity },
  { id: 'connections', title: 'Active Connections', detail: 'This view will group captured packets by local and remote endpoint.', icon: Cable },
  { id: 'applications', title: 'Applications', detail: 'Traffic will appear by process where Windows can identify the owning socket.', icon: Boxes },
  { id: 'analytics', title: 'Traffic Analytics', detail: 'Review throughput and protocol usage over the current session.', icon: ChartNoAxesColumn },
  { id: 'alerts', title: 'Security Alerts', detail: 'Configured rules will produce alerts with evidence from observed traffic.', icon: ShieldAlert },
  { id: 'intelligence', title: 'IP Intelligence', detail: 'Offline City and ASN lookups will appear here once GeoIP is configured.', icon: Search },
  { id: 'history', title: 'Packet History', detail: 'Recorded metadata and export controls will be available here.', icon: History },
  { id: 'settings', title: 'Settings', detail: 'Adapter, retention and GeoIP controls will be added in their respective phases.', icon: Settings },
];

type Health = 'checking' | 'ready' | 'offline';

function currentPage() {
  return pages.find(page => `#${page.id}` === window.location.hash) ?? pages[0];
}

export function App() {
  const [page, setPage] = useState(currentPage);
  const [health, setHealth] = useState<Health>('checking');
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    const onHashChange = () => setPage(currentPage());
    window.addEventListener('hashchange', onHashChange);
    return () => window.removeEventListener('hashchange', onHashChange);
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    const timeout = window.setTimeout(() => controller.abort('timeout'), 3000);

    async function checkHealth() {
      try {
        const response = await fetch('/api/health', { signal: controller.signal, cache: 'no-store' });
        if (!response.ok) throw new Error('Health endpoint unavailable');
        const result = await response.json();
        if (result?.status !== 'ready' || result?.capture !== 'unavailable') {
          throw new Error('Unexpected health response');
        }
        if (!controller.signal.aborted) setHealth('ready');
      } catch {
        if (controller.signal.reason !== 'unmounted') setHealth('offline');
      } finally {
        window.clearTimeout(timeout);
      }
    }

    void checkHealth();
    return () => {
      window.clearTimeout(timeout);
      controller.abort('unmounted');
    };
  }, [attempt]);

  const status = { checking: 'Checking API', ready: 'Local API ready', offline: 'Local API unavailable' }[health];

  return (
    <div className="shell">
      <a className="skip" href="#workspace" onClick={event => {
        event.preventDefault();
        document.getElementById('workspace')?.focus();
      }}>Skip to workspace</a>
      <header className="topbar soft-panel">
        <a className="brand" href="#overview">
          <span className="monogram"><Shield size={21} aria-hidden="true" /></span>
          Personal Network Security
        </a>
        <div className="service-controls">
          <span className={`status inset-surface ${health}`} role="status"><i className="dot" />{status}</span>
          <button className="icon-button" type="button" title="Check connection" aria-label="Check connection"
            disabled={health === 'checking'} onClick={() => {
              setHealth('checking');
              setAttempt(previous => previous + 1);
            }}><RefreshCw size={17} aria-hidden="true" /></button>
        </div>
        <nav className="navigation" aria-label="Workspace">
          {pages.map(({ id, title, icon: Icon }) => (
            <a key={id} href={`#${id}`} aria-current={page.id === id ? 'page' : undefined}>
              <Icon size={16} aria-hidden="true" />{title}
            </a>
          ))}
        </nav>
      </header>
      <main id="workspace" tabIndex={-1}>
        <p className="eyebrow">Network operations</p>
        <h1>{page.title}</h1>
        <p className="description">{page.detail}</p>
        {health === 'offline' && <p className="offline-message">Start the local API, then use Check connection to retry.</p>}
        <div className="page-content">
          {page.id === 'overview' && <Dashboard />}
          {page.id === 'analytics' && <TrafficPanels />}
          {page.id === 'map' && <GeographyPanel />}
          {!['overview', 'analytics', 'map'].includes(page.id) && (
            <section className="soft-panel feature-empty" aria-label="Feature status">
              <page.icon size={25} aria-hidden="true" />
              <h2>Coming in a later phase</h2>
              <a href="#overview">Return to overview</a>
            </section>
          )}
        </div>
      </main>
    </div>
  );
}
