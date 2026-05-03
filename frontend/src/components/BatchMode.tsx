'use client';

import { useEffect, useRef, useState } from 'react';
import {
  buildCountQueue,
  buildTableQueue,
  parseCSV,
  setQueueStatement,
} from '@/lib/submitFile';

type Mode = 'count' | 'table' | 'csv';

interface BatchModeProps {
  text: string;
  onChange: (text: string) => void;
  // Reported up so the page can disable the Submit button when the
  // batch spec is invalid (e.g. empty table).
  onValidityChange?: (ok: boolean, message?: string) => void;
}

const MODES: { id: Mode; label: string; hint: string }[] = [
  { id: 'count', label: 'Count', hint: 'Submit N copies; vary by $(ProcId).' },
  { id: 'table', label: 'Table', hint: 'Per-row variables filled by hand.' },
  { id: 'csv', label: 'CSV upload', hint: 'First row is the column headers.' },
];

export function BatchMode({ text, onChange, onValidityChange }: BatchModeProps) {
  const [mode, setMode] = useState<Mode>('count');
  const [count, setCount] = useState(1);
  const [columns, setColumns] = useState<string[]>(['name']);
  const [rows, setRows] = useState<string[][]>([['alice'], ['bob']]);
  const [csvName, setCsvName] = useState<string | null>(null);
  const [csvParsed, setCsvParsed] = useState<{
    columns: string[];
    rows: string[][];
  } | null>(null);
  const [error, setError] = useState<string | null>(null);

  // We're the source of truth for the trailing `queue ...` line — keep
  // it in sync with whichever mode is currently active. We hold the
  // generated queue line in a ref so we only push an update to the
  // parent when it actually changes (avoids a render loop where the
  // parent's text update re-triggers our effect).
  const lastWritten = useRef<string>('');
  const text_ = text; // capture for effect closure
  useEffect(() => {
    let queueLine = '';
    let validity: { ok: boolean; message?: string } = { ok: true };
    try {
      if (mode === 'count') {
        queueLine = buildCountQueue(count);
      } else if (mode === 'table') {
        queueLine = buildTableQueue(columns, rows);
      } else if (mode === 'csv') {
        if (!csvParsed) {
          throw new Error('Upload a CSV file first.');
        }
        queueLine = buildTableQueue(csvParsed.columns, csvParsed.rows);
      }
      setError(null);
    } catch (e) {
      validity = { ok: false, message: (e as Error).message };
      setError((e as Error).message);
      onValidityChange?.(false, (e as Error).message);
      return;
    }
    onValidityChange?.(true);
    if (queueLine && queueLine !== lastWritten.current) {
      lastWritten.current = queueLine;
      onChange(setQueueStatement(text_, queueLine));
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [mode, count, columns, rows, csvParsed]);

  return (
    <div className="rounded border border-gray-200 bg-white p-4 space-y-3">
      <div className="text-sm font-medium text-gray-700">Batch mode</div>
      <div className="flex flex-wrap gap-2">
        {MODES.map((m) => (
          <button
            key={m.id}
            type="button"
            onClick={() => setMode(m.id)}
            className={`text-xs px-3 py-1.5 rounded border transition ${
              mode === m.id
                ? 'border-brand-400 bg-brand-50 text-brand-800'
                : 'border-gray-300 bg-white text-gray-700 hover:bg-gray-50'
            }`}
          >
            {m.label}
          </button>
        ))}
      </div>
      <p className="text-xs text-gray-500">
        {MODES.find((m) => m.id === mode)?.hint}
      </p>

      {mode === 'count' && (
        <CountInput count={count} setCount={setCount} />
      )}

      {mode === 'table' && (
        <TableEditor
          columns={columns}
          rows={rows}
          setColumns={setColumns}
          setRows={setRows}
        />
      )}

      {mode === 'csv' && (
        <CSVUploader
          fileName={csvName}
          parsed={csvParsed}
          onUpload={(name, parsed) => {
            setCsvName(name);
            setCsvParsed(parsed);
          }}
          onClear={() => {
            setCsvName(null);
            setCsvParsed(null);
          }}
        />
      )}

      {error && (
        <p className="text-xs text-red-600">{error}</p>
      )}

      <div className="text-[11px] text-gray-400">
        Variables available in the submit file: {availableVars(mode, columns, csvParsed)}
      </div>
    </div>
  );
}

function availableVars(
  mode: Mode,
  columns: string[],
  csv: { columns: string[]; rows: string[][] } | null,
): string {
  const base = ['ProcId', 'ClusterId', 'ItemIndex', 'Step'];
  let extra: string[] = [];
  if (mode === 'table') extra = columns;
  else if (mode === 'csv') extra = csv?.columns ?? [];
  const all = [...new Set([...extra, ...base])];
  return all.map((n) => `$(${n})`).join(', ');
}

function CountInput({
  count,
  setCount,
}: {
  count: number;
  setCount: (n: number) => void;
}) {
  return (
    <div className="flex items-center gap-3">
      <label className="text-xs text-gray-600">Number of jobs</label>
      <input
        type="number"
        min={1}
        max={100000}
        value={count}
        onChange={(e) => {
          const n = parseInt(e.target.value, 10);
          if (!Number.isNaN(n) && n > 0) setCount(n);
        }}
        className="w-24 rounded border border-gray-300 px-2 py-1 text-sm"
      />
    </div>
  );
}

function TableEditor({
  columns,
  rows,
  setColumns,
  setRows,
}: {
  columns: string[];
  rows: string[][];
  setColumns: (c: string[]) => void;
  setRows: (r: string[][]) => void;
}) {
  const setColumn = (i: number, name: string) => {
    const next = [...columns];
    next[i] = name;
    setColumns(next);
  };
  const setCell = (r: number, c: number, v: string) => {
    const next = rows.map((row) => [...row]);
    while (next[r].length < columns.length) next[r].push('');
    next[r][c] = v;
    setRows(next);
  };

  return (
    <div className="space-y-2">
      <div className="overflow-x-auto rounded border border-gray-200">
        <table className="min-w-full text-xs">
          <thead className="bg-gray-50">
            <tr>
              {columns.map((c, i) => (
                <th key={i} className="px-1 py-1">
                  <input
                    value={c}
                    onChange={(e) => setColumn(i, e.target.value)}
                    className="w-28 rounded border border-gray-300 px-1 py-0.5 font-mono text-xs"
                    placeholder="var"
                  />
                </th>
              ))}
              <th className="px-1 py-1 w-8"></th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-100">
            {rows.map((row, r) => (
              <tr key={r}>
                {columns.map((_, c) => (
                  <td key={c} className="px-1 py-1">
                    <input
                      value={row[c] ?? ''}
                      onChange={(e) => setCell(r, c, e.target.value)}
                      className="w-28 rounded border border-gray-200 px-1 py-0.5 font-mono text-xs"
                    />
                  </td>
                ))}
                <td className="px-1 py-1 text-right">
                  <button
                    type="button"
                    onClick={() => setRows(rows.filter((_, i) => i !== r))}
                    className="text-xs text-red-600 hover:text-red-800"
                    title="Remove row"
                  >
                    ✕
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="flex flex-wrap gap-2">
        <button
          type="button"
          onClick={() => setRows([...rows, columns.map(() => '')])}
          className="text-xs rounded border border-gray-300 px-2 py-1 text-gray-700 hover:bg-gray-50"
        >
          + row
        </button>
        <button
          type="button"
          onClick={() => {
            const newCol = `var${columns.length + 1}`;
            setColumns([...columns, newCol]);
            setRows(rows.map((row) => [...row, '']));
          }}
          className="text-xs rounded border border-gray-300 px-2 py-1 text-gray-700 hover:bg-gray-50"
        >
          + column
        </button>
        {columns.length > 1 && (
          <button
            type="button"
            onClick={() => {
              const next = columns.slice(0, -1);
              setColumns(next);
              setRows(rows.map((row) => row.slice(0, next.length)));
            }}
            className="text-xs rounded border border-gray-300 px-2 py-1 text-gray-700 hover:bg-gray-50"
          >
            − column
          </button>
        )}
      </div>
    </div>
  );
}

function CSVUploader({
  fileName,
  parsed,
  onUpload,
  onClear,
}: {
  fileName: string | null;
  parsed: { columns: string[]; rows: string[][] } | null;
  onUpload: (name: string, parsed: { columns: string[]; rows: string[][] }) => void;
  onClear: () => void;
}) {
  const [uploadError, setUploadError] = useState<string | null>(null);

  return (
    <div className="space-y-2">
      <div className="flex items-center gap-3">
        <input
          type="file"
          accept=".csv,text/csv"
          onChange={async (e) => {
            const f = e.target.files?.[0];
            if (!f) return;
            try {
              const txt = await f.text();
              const p = parseCSV(txt);
              if (!p) {
                setUploadError('CSV is empty.');
                return;
              }
              setUploadError(null);
              onUpload(f.name, p);
            } catch (err) {
              setUploadError((err as Error).message);
            } finally {
              e.target.value = '';
            }
          }}
          className="text-xs"
        />
        {fileName && (
          <>
            <span className="text-xs text-gray-600 font-mono">{fileName}</span>
            <button
              type="button"
              onClick={onClear}
              className="text-xs text-red-600 hover:text-red-800"
            >
              Clear
            </button>
          </>
        )}
      </div>

      {uploadError && (
        <p className="text-xs text-red-600">{uploadError}</p>
      )}

      {parsed && (
        <div className="overflow-x-auto rounded border border-gray-200 max-h-48">
          <table className="min-w-full text-xs">
            <thead className="bg-gray-50 sticky top-0">
              <tr>
                {parsed.columns.map((c) => (
                  <th key={c} className="px-2 py-1 text-left font-mono">{c}</th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {parsed.rows.slice(0, 50).map((row, i) => (
                <tr key={i}>
                  {parsed.columns.map((_, c) => (
                    <td key={c} className="px-2 py-1 font-mono">
                      {row[c] ?? ''}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
          {parsed.rows.length > 50 && (
            <div className="bg-gray-50 px-2 py-1 text-[10px] text-gray-500">
              ...and {parsed.rows.length - 50} more rows
            </div>
          )}
        </div>
      )}
    </div>
  );
}
