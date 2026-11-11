import { useEffect, useState } from 'react';
import { captureRequest, formatBytes } from './captureApi';
import { downloadText } from './download';
import { PacketHistoryPanel } from './PacketHistoryPanel';

type Settings = { path: string; retentionDays: number; warning: string | null };
type Archive = { id: string; adapter: string; startedAt: string; checkpointAt: string; retainedPackets: number; sessionBytes: number };

export function StorageSettingsPanel({ code }: { code: string }) {
  const [settings, setSettings] = useState<Settings>();
  const [days, setDays] = useState('');
  const [pending, setPending] = useState(false);
  const [notice, setNotice] = useState('');
  const [error, setError] = useState('');
  useEffect(() => {
    const controller = new AbortController();
    captureRequest<Settings>(code, 'storage/settings', { signal: controller.signal }).then(result => {
      if (controller.signal.aborted) return;
      setSettings(result);
      setDays(String(result.retentionDays));
    }).catch(reason => { if (!controller.signal.aborted) setError(reason.message); });
    return () => controller.abort();
  }, [code]);
  async function save() {
    setPending(true);
    setError('');
    setNotice('');
    try {
      const next = await captureRequest<Settings>(code, 'storage/settings', {
        method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ retentionDays: Number(days) }),
      });
      setSettings(next);
      setNotice('Retention saved and expired history removed.');
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'Storage settings could not be saved.');
    } finally { setPending(false); }
  }
  return (
    <section className="soft-panel capture-panel" aria-labelledby="storage-title">
      <h2 id="storage-title">Local storage</h2>
      {settings && <p>SQLite database <code className="geo-path">{settings.path}</code></p>}
      <p>Retain up to 30 capture sessions, 10,000 packet metadata rows per session, and 200 alerts. Shortening retention immediately removes expired archive records.</p>
      <form className="capture-controls" onSubmit={event => { event.preventDefault(); void save(); }}>
        <label>Retention days<input required type="number" min={1} max={90} step={1} value={days}
          onChange={event => setDays(event.target.value)} /></label>
        <button className="capture-button" type="submit" disabled={pending || !settings}>Apply retention</button>
      </form>
      {settings?.warning && <p className="capture-warning" role="alert">{settings.warning}</p>}
      {error && <p className="capture-warning" role="alert">{error}</p>}
      {notice && <p role="status">{notice}</p>}
    </section>
  );
}

export function HistoryWorkspace({ code, currentSession }: { code: string; currentSession: string | null }) {
  const [archives, setArchives] = useState<Archive[]>([]);
  const [selection, setSelection] = useState('');
  const [revision, setRevision] = useState(0);
  const [error, setError] = useState('');
  const [exporting, setExporting] = useState(false);
  const selectedArchive = archives.find(archive => archive.id === selection);
  const sessionId = selectedArchive?.id ?? currentSession ?? archives[0]?.id ?? null;
  const checkpoint = archives.find(archive => archive.id === sessionId);
  useEffect(() => {
    const controller = new AbortController();
    setError('');
    captureRequest<Archive[]>(code, 'storage/sessions', { signal: controller.signal }).then(result => {
      if (controller.signal.aborted) return;
      setArchives(result);
      setSelection(previous => result.some(archive => archive.id === previous) ? previous : '');
    }).catch(reason => { if (!controller.signal.aborted) setError(reason.message); });
    return () => controller.abort();
  }, [code, currentSession, revision]);

  async function exportSummary(id: string) {
    setExporting(true);
    setError('');
    try {
      const archive = await captureRequest<unknown>(code, `storage/sessions/${id}`);
      downloadText(`capture-${id}.json`, JSON.stringify(archive, null, 2), 'application/json');
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'The capture summary could not be exported.');
    } finally { setExporting(false); }
  }

  return <>
    <section className="soft-panel capture-panel" aria-labelledby="archive-title">
      <h2 id="archive-title">Capture archive</h2>
      <div className="capture-controls">
        <label htmlFor="history-session">Capture session
          <select id="history-session" value={selection} onChange={event => setSelection(event.target.value)}>
            <option value="">Current or latest session</option>
            {archives.map(archive => <option key={archive.id} value={archive.id}>
              {new Date(archive.startedAt).toLocaleString()} · {archive.adapter}
            </option>)}
          </select>
        </label>
        <button className="capture-button" type="button" onClick={() => setRevision(value => value + 1)}>Refresh sessions</button>
        <button className="capture-button" type="button" disabled={!checkpoint || exporting}
          onClick={() => checkpoint && void exportSummary(checkpoint.id)}>Export checkpoint JSON</button>
      </div>
      {checkpoint && <p>Saved {new Date(checkpoint.checkpointAt).toLocaleString()} · {checkpoint.retainedPackets.toLocaleString()} archived packets · {formatBytes(checkpoint.sessionBytes)} captured</p>}
      {error && <p className="capture-warning" role="alert">{error}</p>}
    </section>
    <PacketHistoryPanel key={sessionId ?? 'latest'} code={code} sessionId={sessionId} />
  </>;
}
