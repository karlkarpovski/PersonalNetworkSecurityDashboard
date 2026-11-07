import { useEffect, useState } from 'react';

const pages = [
  { id: 'overview', title: 'Overview', detail: 'Monitor the status of your local network workspace.' },
  { id: 'map', title: 'Global Traffic Map', detail: 'Endpoint geography and directional traffic routes arrive with the globe.' },
  { id: 'packets', title: 'Live Packet Monitor', detail: 'Packet metadata will appear here after adapter capture is available.' },
  { id: 'connections', title: 'Active Connections', detail: 'This view will group captured packets by local and remote endpoint.' },
  { id: 'applications', title: 'Applications', detail: 'Traffic will appear by process where Windows can identify the owning socket.' },
  { id: 'analytics', title: 'Traffic Analytics', detail: 'Charts will use recorded traffic once capture and aggregation are available.' },
  { id: 'alerts', title: 'Security Alerts', detail: 'Configured rules will produce alerts with evidence from observed traffic.' },
  { id: 'intelligence', title: 'IP Intelligence', detail: 'Offline City and ASN lookups will appear here once GeoIP is configured.' },
  { id: 'history', title: 'Packet History', detail: 'Recorded metadata and export controls will be available here.' },
  { id: 'settings', title: 'Settings', detail: 'Adapter, retention and GeoIP controls will be added in their respective phases.' },
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
      <aside className="sidebar">
        <a className="brand" href="#overview"><span className="monogram" aria-hidden="true">NS</span> Personal Network Security</a>
        <nav aria-label="Workspace">
          {pages.map(item => (
            <a key={item.id} href={`#${item.id}`} aria-current={page.id === item.id ? 'page' : undefined}>
              {item.title}
            </a>
          ))}
        </nav>
      </aside>
      <div className="workspace">
        <header className="topbar">
          <span>LOCAL WORKSPACE</span>
          <span className={`status ${health}`} role="status">{status}</span>
        </header>
        <main id="workspace" tabIndex={-1}>
          <p className="eyebrow">PHASE 01 / FOUNDATION</p>
          <h1>{page.title}</h1>
          <p className="description">{page.detail}</p>
          {page.id === 'overview' ? (
            <section className="panels" aria-label="System status">
              <article>
                <p className="eyebrow">01 / SERVICE</p>
                <h2>{status}</h2>
                <p>{health === 'offline' ? 'Start the backend, then retry the connection.' : 'The local service reports startup health.'}</p>
                <button disabled={health === 'checking'} onClick={() => {
                  setHealth('checking');
                  setAttempt(previous => previous + 1);
                }}>Check connection</button>
              </article>
              <article>
                <p className="eyebrow">02 / MONITORING</p>
                <h2>Capture unavailable</h2>
                <p>Adapter selection and live monitoring arrive in Phase 4.</p>
              </article>
            </section>
          ) : (
            <section className="panels" aria-label="Feature status">
              <article>
                <h2>Coming in a later phase</h2>
                <a href="#overview">Return to overview</a>
              </article>
            </section>
          )}
        </main>
      </div>
    </div>
  );
}
