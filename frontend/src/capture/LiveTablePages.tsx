import { useState } from 'react';
import type { ReactNode } from 'react';

const rowsPerPage = 10;

export function LiveTablePages<T>({ rows, empty, label, children }: {
  rows: T[];
  empty: string;
  label: string;
  children: (page: T[]) => ReactNode;
}) {
  const [selectedPage, setSelectedPage] = useState(1);
  const [frozen, setFrozen] = useState<T[] | null>(null);
  const displayed = frozen ?? rows;
  const pageCount = Math.max(1, Math.ceil(displayed.length / rowsPerPage));
  const page = Math.min(selectedPage, pageCount);
  if (page !== selectedPage) setSelectedPage(page);

  if (!displayed.length) return <p>{empty} <a href="#packets">Open capture controls</a></p>;
  const offset = (page - 1) * rowsPerPage;
  return <div className={pageCount > 1 ? 'live-table-pages multiple-pages' : 'live-table-pages'}>
    <div className="capture-controls">
      <button type="button" className="capture-button" aria-pressed={frozen !== null}
        onClick={() => setFrozen(frozen ? null : [...rows])}>{frozen ? 'Resume display' : 'Pause display'}</button>
      <span>{frozen ? 'Display paused · capture continues' : 'Live display'} · {displayed.length} rows</span>
    </div>
    {children(displayed.slice(offset, offset + rowsPerPage))}
    {pageCount > 1 && <nav className="live-table-pagination" aria-label={label}>
      <button type="button" className="capture-button" aria-disabled={page === 1}
        onClick={() => setSelectedPage(Math.max(1, page - 1))}>Previous</button>
      <span>Page {page} of {pageCount}</span>
      <button type="button" className="capture-button" aria-disabled={page === pageCount}
        onClick={() => setSelectedPage(Math.min(pageCount, page + 1))}>Next</button>
    </nav>}
  </div>;
}
