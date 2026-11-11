import { useEffect, useState } from 'react';
import { captureRequest } from './captureApi';
import type { Packet, PacketHistory } from './captureApi';
import { PacketTable } from './CapturePages';
import { downloadText, encodeCsv } from './download';

function toCsv(packets: Packet[]) {
  const rows = packets.map(packet => [
    packet.timestamp, packet.direction, packet.source, packet.sourcePort, packet.destination, packet.destinationPort,
    packet.protocol, packet.length, packet.owner?.process.name, packet.owner?.process.pid, packet.owner?.method,
  ]);
  return 'Timestamp,Direction,Source,Source port,Destination,Destination port,Protocol,Bytes,Process,PID,Attribution\r\n' + encodeCsv(rows);
}

export function PacketHistoryPanel({ code, sessionId }: { code: string; sessionId: string | null }) {
  const [input, setInput] = useState('');
  const [search, setSearch] = useState('');
  const [cursors, setCursors] = useState<number[]>([]);
  const [version, setVersion] = useState(0);
  const [result, setResult] = useState<PacketHistory>();
  const [loading, setLoading] = useState(true);
  const [exporting, setExporting] = useState(false);
  const [error, setError] = useState('');
  const before = cursors.at(-1);

  function parameters(limit: number) {
    const query = new URLSearchParams({ search, limit: String(limit) });
    if (sessionId) query.set('sessionId', sessionId);
    return query;
  }

  useEffect(() => {
    const controller = new AbortController();
    const query = new URLSearchParams({ search, limit: '100' });
    if (sessionId) query.set('sessionId', sessionId);
    if (before !== undefined) query.set('before', String(before));
    setLoading(true);
    setError('');
    captureRequest<PacketHistory>(code, `history?${query}`, { signal: controller.signal }).then(data => {
      if (!controller.signal.aborted) setResult(data);
    }).catch(reason => {
      if (!controller.signal.aborted) { setResult(undefined); setError(reason.message); }
    }).finally(() => {
      if (!controller.signal.aborted) setLoading(false);
    });
    return () => controller.abort();
  }, [before, code, search, sessionId, version]);

  async function download(format: 'csv' | 'json') {
    setExporting(true);
    setError('');
    try {
      const history = await captureRequest<PacketHistory>(code, `history?${parameters(10000)}`);
      if (!history.packets.length) { setError('No retained packets match the export filter.'); return; }
      const csv = format === 'csv';
      downloadText(`packet-metadata.${format}`, csv ? toCsv(history.packets) : JSON.stringify(history, null, 2),
        csv ? 'text/csv;charset=utf-8' : 'application/json');
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'Export failed.');
    } finally {
      setExporting(false);
    }
  }

  return (
    <section className="soft-panel capture-panel" aria-labelledby="history-title">
      <h2 id="history-title">Retained packet metadata</h2>
      <p>Browse the last 10,000 captured IP packets in this session. Export includes all retained rows matching the applied filter.</p>
      <form className="capture-controls" onSubmit={event => {
        event.preventDefault();
        setSearch(input.trim()); setCursors([]); setVersion(value => value + 1);
      }}>
        <label>History filter<input type="search" maxLength={100} value={input} onChange={event => setInput(event.target.value)}
          placeholder="IP, port, protocol, direction, or process" /></label>
        <button className="capture-button" type="submit" disabled={loading || exporting}>Apply / refresh</button>
        <button className="capture-button" type="button" disabled={loading || exporting || !result?.packets.length}
          onClick={() => void download('csv')}>Export CSV</button>
        <button className="capture-button" type="button" disabled={loading || exporting || !result?.packets.length}
          onClick={() => void download('json')}>Export JSON</button>
      </form>
      {error && <p className="capture-warning" role="alert">{error}</p>}
      {loading ? <p role="status">Loading packet history…</p>
        : result?.packets.length ? <PacketTable packets={result.packets} /> : <p>No retained packets on this page.</p>}
      <div className="capture-controls history-pagination">
        <button className="capture-button" type="button" disabled={loading || !cursors.length}
          onClick={() => setCursors(value => value.slice(0, -1))}>Newer page</button>
        <button className="capture-button" type="button" disabled={loading || result?.nextBefore == null}
          onClick={() => setCursors(value => [...value, result!.nextBefore!])}>Older page</button>
        {result && <span>Page {cursors.length + 1} · {result.retained.toLocaleString()} retained in session</span>}
      </div>
    </section>
  );
}
