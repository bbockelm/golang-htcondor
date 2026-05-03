'use client';

import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { api, type LogEntry } from '@/lib/api';

const LEVEL_COLORS: Record<string, string> = {
  ERROR: 'text-red-700',
  WARN: 'text-amber-700',
  INFO: 'text-gray-700',
  DEBUG: 'text-gray-400',
};

export default function AdminLogsPage() {
  const [filter, setFilter] = useState('');
  const [level, setLevel] = useState<string>('');

  const { data, isLoading, error } = useQuery({
    queryKey: ['admin', 'logs'],
    queryFn: () => api.admin.logs(1000),
    refetchInterval: 5_000,
  });

  const entries = filterEntries(data?.entries ?? null, filter, level);

  return (
    <div className="space-y-4 max-w-6xl">
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Logs</h1>
        <p className="text-sm text-gray-500">
          Recent log entries from the in-process ring buffer. Refreshes every
          5s. The on-disk log file remains the durable source of truth.
        </p>
      </div>

      {data && !data.enabled && (
        <p className="text-sm text-amber-700">
          Log buffer is not initialized.
        </p>
      )}

      <div className="flex flex-wrap items-center gap-3">
        <input
          type="text"
          placeholder="Filter (substring match)"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          className="flex-1 max-w-md rounded border border-gray-300 px-2 py-1 text-sm"
        />
        <select
          value={level}
          onChange={(e) => setLevel(e.target.value)}
          className="rounded border border-gray-300 px-2 py-1 text-sm"
        >
          <option value="">All levels</option>
          <option value="ERROR">Error</option>
          <option value="WARN">Warn</option>
          <option value="INFO">Info</option>
          <option value="DEBUG">Debug</option>
        </select>
        <span className="text-xs text-gray-400">
          {entries.length} {entries.length === 1 ? 'entry' : 'entries'}
        </span>
      </div>

      {isLoading && <p className="text-gray-400">Loading...</p>}
      {error && (
        <p className="text-red-600 text-sm">{(error as Error).message}</p>
      )}

      <div className="rounded border border-gray-200 bg-white font-mono text-xs">
        <ul className="divide-y divide-gray-100">
          {entries.length === 0 && (
            <li className="px-3 py-2 text-gray-400">No matching entries.</li>
          )}
          {entries
            .slice()
            .reverse()
            .map((e, i) => (
              <LogRow key={i} entry={e} />
            ))}
        </ul>
      </div>
    </div>
  );
}

function LogRow({ entry }: { entry: LogEntry }) {
  const cls = LEVEL_COLORS[entry.level] ?? 'text-gray-700';
  return (
    <li className="px-3 py-1.5 flex flex-wrap gap-x-3 gap-y-0.5">
      <span className="text-gray-400 shrink-0">
        {new Date(entry.time).toLocaleTimeString()}
      </span>
      <span className={`shrink-0 ${cls}`}>{entry.level.padEnd(5)}</span>
      {entry.destination && (
        <span className="text-gray-400 shrink-0">[{entry.destination}]</span>
      )}
      <span className={`flex-1 min-w-0 break-words ${cls}`}>
        {entry.message}
      </span>
      {entry.fields && Object.keys(entry.fields).length > 0 && (
        <span className="text-gray-400 break-all">
          {Object.entries(entry.fields)
            .map(([k, v]) => `${k}=${v}`)
            .join(' ')}
        </span>
      )}
    </li>
  );
}

function filterEntries(
  entries: LogEntry[] | null,
  search: string,
  level: string,
): LogEntry[] {
  if (!entries) return [];
  const s = search.trim().toLowerCase();
  return entries.filter((e) => {
    if (level && e.level !== level) return false;
    if (s) {
      const blob = `${e.message} ${e.destination ?? ''} ${
        e.fields ? Object.entries(e.fields).map(([k, v]) => `${k}=${v}`).join(' ') : ''
      }`.toLowerCase();
      if (!blob.includes(s)) return false;
    }
    return true;
  });
}
