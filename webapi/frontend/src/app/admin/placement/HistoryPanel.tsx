'use client';

// The placementd's history: who changed what, newest first. For one
// directory entry, or for the whole directory.

import { useQuery } from '@tanstack/react-query';
import {
  type DirAuthorization,
  type FieldValue,
  type Modification,
  type PlacementKind,
  placementAdmin,
} from '@/lib/placementAdmin';
import { Modal, formatWhen } from './directoryShared';

const OPERATION_LABEL: Record<string, string> = {
  create: 'Created',
  update: 'Updated',
  delete: 'Deleted',
  adopt: 'Adopted',
  reclaim: 'Reclaimed by the map file',
  handoff: 'Handed off from the map file',
};

const CHANNEL_LABEL: Record<string, string> = {
  cedar: 'directory',
  mapfile: 'map file',
  migration: 'import',
};

// who is the person a change is attributed to: whom the editor acted for,
// else the editor itself; the map file and the import stand for themselves.
export function who(m: Modification): string {
  if (m.on_behalf_of) return m.on_behalf_of;
  if (m.channel === 'mapfile') return 'Map file';
  if (m.channel === 'migration') return 'Import';
  return m.actor;
}

// fieldLabel turns DefaultProject into "Default project".
export function fieldLabel(field: string): string {
  const words = field.replace(/([a-z0-9])([A-Z])/g, '$1 $2').toLowerCase();
  return words.charAt(0).toUpperCase() + words.slice(1);
}

function scalar(field: string, v: FieldValue): string {
  if (v === null || v === undefined || v === '') return '—';
  if (typeof v === 'boolean') return v ? 'Yes' : 'No';
  if (typeof v === 'number' && /At$/.test(field) && v > 0) {
    return new Date(v * 1000).toLocaleString();
  }
  if (Array.isArray(v)) return v.map(String).join(', ');
  return String(v);
}

const asList = (v: FieldValue): string[] | null =>
  Array.isArray(v) ? v.map(String) : v === null ? [] : null;

// ListDiff renders an old and new list as chips: removed, added, kept.
export function ListDiff({
  before,
  after,
  render,
}: {
  before: string[];
  after: string[];
  render?: (name: string) => string;
}) {
  const label = render ?? ((n: string) => n);
  const removed = before.filter((x) => !after.includes(x));
  const added = after.filter((x) => !before.includes(x));
  const kept = after.filter((x) => before.includes(x));
  if (removed.length + added.length + kept.length === 0) {
    return <span className="text-gray-400">—</span>;
  }
  return (
    <span className="flex flex-wrap gap-1">
      {removed.map((x) => (
        <span
          key={`-${x}`}
          data-diff="removed"
          className="rounded-sm bg-red-50 px-1.5 py-0.5 text-[11px] text-red-700 line-through ring-1 ring-inset ring-red-200"
        >
          {label(x)}
        </span>
      ))}
      {added.map((x) => (
        <span
          key={`+${x}`}
          data-diff="added"
          className="rounded-sm bg-emerald-50 px-1.5 py-0.5 text-[11px] text-emerald-800 ring-1 ring-inset ring-emerald-200"
        >
          + {label(x)}
        </span>
      ))}
      {kept.map((x) => (
        <span
          key={`=${x}`}
          data-diff="kept"
          className="rounded-sm bg-gray-100 px-1.5 py-0.5 text-[11px] text-gray-600 ring-1 ring-inset ring-gray-200"
        >
          {label(x)}
        </span>
      ))}
    </span>
  );
}

export function HistoryEntry({
  m,
  showEntity,
  authzByName,
}: {
  m: Modification;
  showEntity?: boolean;
  authzByName?: Map<string, DirAuthorization>;
}) {
  const fields = Object.keys(m.changes ?? {}).sort();
  const authzLabel = (n: string) => authzByName?.get(n.toUpperCase())?.label || n;
  return (
    <li className="py-3" data-testid={`history-${m.id}`}>
      <div className="flex flex-wrap items-baseline gap-x-2 text-sm">
        <span className="font-medium text-gray-900">{OPERATION_LABEL[m.operation] ?? m.operation}</span>
        {showEntity && (
          <span className="text-gray-600">
            {m.entity_type} <span className="font-mono text-xs">{m.entity_id}</span>
          </span>
        )}
        <span className="text-gray-600">by {who(m)}</span>
        <span className="rounded-full bg-gray-100 px-2 py-0.5 text-[10px] text-gray-600" title={m.actor}>
          {CHANNEL_LABEL[m.channel] ?? m.channel}
        </span>
        <span className="ml-auto text-xs text-gray-500">{formatWhen(m.time)}</span>
      </div>
      {m.comment && <p className="mt-1 text-xs italic text-gray-600">{m.comment}</p>}
      {fields.length > 0 && (
        <table className="mt-2 w-full text-xs">
          <tbody className="divide-y divide-gray-100">
            {fields.map((f) => {
              const { old: before, new: after } = m.changes[f];
              const beforeList = asList(before);
              const afterList = asList(after);
              const isList = Array.isArray(before) || Array.isArray(after);
              return (
                <tr key={f}>
                  <td className="w-40 py-1 pr-2 align-top text-gray-500">{fieldLabel(f)}</td>
                  <td className="py-1">
                    {isList && beforeList && afterList ? (
                      <ListDiff
                        before={beforeList}
                        after={afterList}
                        render={f === 'Authorizations' ? authzLabel : undefined}
                      />
                    ) : (
                      <span>
                        <span className="text-gray-500">{scalar(f, before)}</span>
                        <span className="mx-1.5 text-gray-400">→</span>
                        <span className="text-gray-900">{scalar(f, after)}</span>
                      </span>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
    </li>
  );
}

export function HistoryPanel({
  target,
  title,
  onClose,
  authzByName,
}: {
  // One entry's history, or the whole directory's when absent.
  target?: { kind: PlacementKind; id: string };
  title: string;
  onClose: () => void;
  authzByName?: Map<string, DirAuthorization>;
}) {
  const history = useQuery({
    queryKey: ['placement', 'history', target?.kind ?? '', target?.id ?? ''],
    queryFn: () => placementAdmin.history(target, 100),
  });
  return (
    <Modal title={title} onClose={onClose} wide>
      {history.isLoading && <p className="text-sm text-gray-400">Loading…</p>}
      {history.error && (
        <p className="text-sm text-red-600">Failed to load history: {(history.error as Error).message}</p>
      )}
      {history.data && history.data.length === 0 && <p className="text-sm text-gray-500">No changes recorded.</p>}
      {history.data && history.data.length > 0 && (
        <ul className="max-h-[60vh] divide-y divide-gray-100 overflow-y-auto">
          {history.data.map((m) => (
            <HistoryEntry key={m.id} m={m} showEntity={!target} authzByName={authzByName} />
          ))}
        </ul>
      )}
    </Modal>
  );
}
