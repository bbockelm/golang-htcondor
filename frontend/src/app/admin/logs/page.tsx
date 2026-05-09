'use client';

import { useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { api, type LogEntry } from '@/lib/api';

// Level colors are applied to both the level pill (in the filter
// row) and the rendered text on each row, so a quick scroll
// highlights ERROR/WARN by hue without parsing the level string.
const LEVEL_COLORS: Record<string, string> = {
  ERROR: 'text-red-700',
  WARN: 'text-amber-700',
  INFO: 'text-gray-700',
  DEBUG: 'text-gray-400',
};

// All known levels in display order (highest severity first). Used
// to seed the multi-select default ("everything visible") and to
// render the toggle pills.
const ALL_LEVELS = ['ERROR', 'WARN', 'INFO', 'DEBUG'] as const;
type Level = (typeof ALL_LEVELS)[number];

export default function AdminLogsPage() {
  const [filter, setFilter] = useState('');
  // Multi-select instead of the previous single-pick dropdown — an
  // operator typically wants "WARN and above" or "everything except
  // DEBUG", which the old UI couldn't express. Default = all
  // levels enabled (the empty-set case is treated as "show none"
  // for the user's sanity, see filterEntries).
  const [enabledLevels, setEnabledLevels] = useState<Set<Level>>(
    () => new Set<Level>(ALL_LEVELS),
  );

  const { data, isLoading, error } = useQuery({
    queryKey: ['admin', 'logs'],
    queryFn: () => api.admin.logs(1000),
    refetchInterval: 5_000,
  });

  const entries = useMemo(
    () => filterEntries(data?.entries ?? null, filter, enabledLevels),
    [data, filter, enabledLevels],
  );

  const toggleLevel = (lvl: Level) =>
    setEnabledLevels((prev) => {
      const next = new Set(prev);
      if (next.has(lvl)) next.delete(lvl);
      else next.add(lvl);
      return next;
    });

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
          placeholder="Filter (substring match across time, level, destination, message, fields)"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          className="flex-1 min-w-[20rem] max-w-md rounded border border-gray-300 px-2 py-1 text-sm"
        />
        <div className="flex items-center gap-1.5">
          {ALL_LEVELS.map((lvl) => {
            const on = enabledLevels.has(lvl);
            return (
              <button
                key={lvl}
                type="button"
                aria-pressed={on}
                onClick={() => toggleLevel(lvl)}
                className={`rounded border px-2 py-0.5 text-xs font-medium transition-colors ${
                  on
                    ? `border-gray-300 bg-white ${LEVEL_COLORS[lvl] ?? 'text-gray-700'}`
                    : 'border-gray-200 bg-gray-50 text-gray-400 line-through'
                }`}
                title={
                  on ? `Hide ${lvl} entries` : `Show ${lvl} entries`
                }
              >
                {lvl}
              </button>
            );
          })}
          {/* Quick "everything" reset since multi-toggle UX makes
              "did I uncheck WARN?" easy to lose track of. */}
          <button
            type="button"
            onClick={() => setEnabledLevels(new Set(ALL_LEVELS))}
            className="ml-1 text-xs text-gray-500 hover:text-gray-700"
            title="Re-enable all levels"
          >
            all
          </button>
        </div>
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
              // Stable identity from time+message+level+destination
              // — the in-memory ring buffer doesn't expose a server-
              // side id, but this triple is unique enough for
              // expansion state to survive a 5-second refresh.
              <LogRow
                key={`${e.time}|${e.level}|${e.destination ?? ''}|${i}`}
                entry={e}
              />
            ))}
        </ul>
      </div>
    </div>
  );
}

function LogRow({ entry }: { entry: LogEntry }) {
  const [open, setOpen] = useState(false);
  const cls = LEVEL_COLORS[entry.level] ?? 'text-gray-700';
  const hasFields = !!entry.fields && Object.keys(entry.fields).length > 0;

  return (
    <li>
      {/* Single-line summary. Hover highlights so the user can track
          which line they're scanning; click toggles the expanded
          view below. cursor-pointer hints at the click affordance. */}
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className={`flex w-full items-baseline gap-x-3 px-3 py-1.5 text-left hover:bg-gray-50 ${
          open ? 'bg-gray-50' : ''
        }`}
        aria-expanded={open}
      >
        <span aria-hidden className="shrink-0 text-gray-300 select-none">
          {open ? '▾' : '▸'}
        </span>
        <span className="shrink-0 text-gray-400">
          {new Date(entry.time).toLocaleTimeString()}
        </span>
        <span className={`shrink-0 ${cls}`}>{entry.level.padEnd(5)}</span>
        {entry.destination && (
          <span className="shrink-0 text-gray-400">[{entry.destination}]</span>
        )}
        {/* min-w-0 + break-words so a long message wraps inside the
            flex row instead of pushing the trailing fields off the
            right edge. The user explicitly wanted the WHOLE line
            visible, so no truncation. */}
        <span className={`min-w-0 flex-1 break-words ${cls}`}>
          {entry.message}
        </span>
        {hasFields && (
          <span className="min-w-0 text-gray-400 break-all">
            {fieldsAsString(entry.fields)}
          </span>
        )}
      </button>

      {open && <ExpandedDetail entry={entry} />}
    </li>
  );
}

// ExpandedDetail renders the full structured view of a log entry
// when the row is open. Two parts:
//   - a key/value table for the discrete fields (timestamp,
//     destination, level, plus the structured `fields` map)
//   - a copy button that produces a single-line plain-text form
//     suitable for pasting into a ticket or shell.
function ExpandedDetail({ entry }: { entry: LogEntry }) {
  const [copied, setCopied] = useState(false);

  const onCopy = async () => {
    try {
      await navigator.clipboard.writeText(formatLineForCopy(entry));
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      // Browsers without clipboard permission (older Safari, some
      // headless contexts) silently fail; we don't want to crash
      // the page over a copy failure. The button stays clickable.
    }
  };

  const rows: { label: string; value: string }[] = [
    { label: 'time', value: entry.time },
    { label: 'level', value: entry.level },
    { label: 'destination', value: entry.destination ?? '' },
    { label: 'message', value: entry.message },
  ];
  const fieldEntries = entry.fields
    ? Object.entries(entry.fields).sort(([a], [b]) => a.localeCompare(b))
    : [];

  return (
    <div className="border-t border-gray-100 bg-gray-50 px-3 py-2 space-y-2">
      <div className="flex items-baseline justify-between gap-3">
        <span className="text-[10px] uppercase tracking-wide text-gray-500">
          Entry detail
        </span>
        <button
          type="button"
          onClick={onCopy}
          className="rounded border border-gray-300 bg-white px-2 py-0.5 text-[11px] text-gray-700 hover:bg-gray-100"
          title="Copy this entry as a single-line plain-text record"
        >
          {copied ? 'Copied' : 'Copy'}
        </button>
      </div>
      <table className="text-[11px]">
        <tbody className="align-top">
          {rows.map(
            (r) =>
              r.value !== '' && (
                <tr key={r.label}>
                  <td className="pr-3 py-0.5 text-gray-500 whitespace-nowrap">
                    {r.label}
                  </td>
                  <td className="py-0.5 break-all">{r.value}</td>
                </tr>
              ),
          )}
          {fieldEntries.map(([k, v]) => (
            <tr key={`f:${k}`}>
              <td className="pr-3 py-0.5 text-gray-500 whitespace-nowrap">
                {k}
              </td>
              <td className="py-0.5 break-all">{v}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// formatLineForCopy returns the entry as a single line:
//   2026-05-09T14:39:39Z INFO [http] message key1=val1 key2=val2
// Picked to round-trip with the on-disk log format users grep
// already, so paste-into-ticket reads the same as paste-from-grep.
function formatLineForCopy(entry: LogEntry): string {
  const parts = [entry.time, entry.level];
  if (entry.destination) parts.push(`[${entry.destination}]`);
  parts.push(entry.message);
  if (entry.fields) {
    const fields = fieldsAsString(entry.fields);
    if (fields) parts.push(fields);
  }
  return parts.join(' ');
}

function fieldsAsString(fields: Record<string, string> | undefined): string {
  if (!fields) return '';
  return Object.entries(fields)
    .map(([k, v]) => `${k}=${v}`)
    .join(' ');
}

function filterEntries(
  entries: LogEntry[] | null,
  search: string,
  enabledLevels: Set<Level>,
): LogEntry[] {
  if (!entries) return [];
  // Empty enabled-set means the user has unchecked every level —
  // treat as "show none" rather than "show all" so the UI matches
  // the toggles literally. The "all" reset button restores the
  // default if they want everything back.
  const s = search.trim().toLowerCase();
  return entries.filter((e) => {
    if (!enabledLevels.has(e.level as Level)) return false;
    if (s) {
      // Match across EVERY field the row renders: time, level,
      // destination, message, AND every structured field. Older
      // version only searched message + destination + fields, so
      // looking up a username by its log time was awkward.
      const blob = [
        e.time,
        e.level,
        e.destination ?? '',
        e.message,
        fieldsAsString(e.fields),
      ]
        .join(' ')
        .toLowerCase();
      if (!blob.includes(s)) return false;
    }
    return true;
  });
}
