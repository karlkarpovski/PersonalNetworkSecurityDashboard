import { lazy, Suspense, useEffect, useState } from 'react';
import {
  Activity, Boxes, Cable, ChartNoAxesColumn, Globe2, History, LayoutDashboard,
  RefreshCw, Search, Settings, Shield, ShieldAlert, Wrench,
} from 'lucide-react';
import { Dashboard } from './Dashboard';
import { CaptureAccessForm, CaptureControls, FlowPanel, PacketPanel } from './capture/CapturePages';
import { useCaptureStream } from './capture/useCaptureStream';
import { GeoSettingsPanel, IpIntelligence } from './geo/GeoPanels';
import { ApplicationsPanel } from './capture/ApplicationsPanel';
import { HistoryWorkspace, StorageSettingsPanel } from './capture/StoragePanels';
import { TrafficAnalytics } from './capture/TrafficAnalytics';
import { SecurityPanel } from './security/SecurityPanel';

const GlobePage = lazy(() => import('./globe/GlobePage'));
const ToolsWorkspace = lazy(() => import('./tools/ToolsWorkspace').then(module => ({ default: module.ToolsWorkspace })));

const pages = [
  { id: 'overview', title: 'Overview', detail: 'Traffic, destinations, and security activity for this device.', icon: LayoutDashboard },
  { id: 'map', title: 'Global Traffic Map', detail: 'Explore approximate locations of observed network endpoints.', icon: Globe2 },
  { id: 'packets', title: 'Live Packet Monitor', detail: 'Start Windows capture and inspect recent IP packet metadata.', icon: Activity },
  { id: 'connections', title: 'Active Connections', detail: 'Inspect observed traffic grouped by local and remote endpoint.', icon: Cable },
  { id: 'applications', title: 'Applications', detail: 'Review captured traffic attributed to Windows processes.', icon: Boxes },
  { id: 'analytics', title: 'Traffic Analytics', detail: 'Review throughput and protocol usage over the current session.', icon: ChartNoAxesColumn },
  { id: 'alerts', title: 'Security Alerts', detail: 'Investigate observed events and configure detection rules.', icon: ShieldAlert },
  { id: 'intelligence', title: 'IP Intelligence', detail: 'Look up approximate locations and network ownership using local GeoIP files.', icon: Search },
  { id: 'history', title: 'Packet History', detail: 'Search and export retained packet metadata from the latest capture session.', icon: History },
  { id: 'settings', title: 'Settings', detail: 'Manage the local capture adapter.', icon: Settings },
  { id: 'tools', title: 'Tools', detail: 'Diagnose connections, track local network changes, and compare captures.', icon: Wrench },
];

type Health = 'checking' | 'ready' | 'offline';

function currentPage() {
  return pages.find(page => `#${page.id}` === window.location.hash) ?? pages[0];
}

export function App() {
  const [page, setPage] = useState(currentPage);
  const [health, setHealth] = useState<Health>('checking');
  const [attempt, setAttempt] = useState(0);
  const capture = useCaptureStream();
  const liveStatus = {
    locked: 'Live stream locked', connecting: 'Connecting live stream',
    connected: 'Live stream connected', reconnecting: 'Reconnecting live stream',
  }[capture.status];
  const captureControls = capture.code && <CaptureControls code={capture.code}
    view={capture.view} offline={capture.status !== 'connected'} />;

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
        if (result?.status !== 'ready') {
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
          <span className={`status inset-surface ${capture.status === 'connected' ? 'ready' : ''}`} role="status">{liveStatus}</span>
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
          {capture.status === 'locked' &&
            <CaptureAccessForm rejected={capture.rejected} unlock={capture.unlock} />}
          {page.id === 'overview' && <Dashboard capture={capture.view} geo={capture.geo} security={capture.security}
            samples={capture.samples} streamLabel={liveStatus} />}
          {page.id === 'packets' && <>{captureControls}<PacketPanel view={capture.view} /></>}
          {page.id === 'connections' && <FlowPanel view={capture.view} geo={capture.geo} />}
          {page.id === 'applications' && <ApplicationsPanel view={capture.view} />}
          {page.id === 'history' && capture.code && <HistoryWorkspace
            code={capture.code} currentSession={capture.view?.sessionId ?? null} />}
          {page.id === 'settings' && <>{captureControls}{capture.code && <>
            <StorageSettingsPanel code={capture.code} /><GeoSettingsPanel code={capture.code} />
          </>}</>}
          {page.id === 'intelligence' && capture.code && <IpIntelligence code={capture.code} flows={capture.view?.traffic?.recentFlows} />}
          {page.id === 'analytics' && <TrafficAnalytics view={capture.view} geo={capture.geo} samples={capture.samples} />}
          {page.id === 'map' && (
            <Suspense fallback={<p role="status">Loading the globe…</p>}>
              <GlobePage flows={capture.view?.traffic?.recentFlows} geo={capture.geo} flaggedIps={capture.security?.flaggedIps} />
            </Suspense>
          )}
          {page.id === 'alerts' && capture.code && <SecurityPanel code={capture.code} summary={capture.security} />}
          {page.id === 'tools' && capture.code && <Suspense fallback={<p role="status">Loading tools…</p>}>
            <ToolsWorkspace code={capture.code} view={capture.view} />
          </Suspense>}
        </div>
      </main>
    </div>
  );
}
