'use client';

// Admin views of the schedd records behind placement accounts and projects:
// a projects list, and a detail drawer with the job counters and
// Suspend / Unsuspend.

import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { ApiError, api, type PlacementRecord } from '@/lib/api';

export type PlacementRecordTarget = { kind: 'accounts' | 'projects'; name: string };

// The counters a drawer shows, in order, with their labels.
const STATS: [string, string][] = [
  ['NumIdle', 'Idle'],
  ['NumRunning', 'Running'],
  ['NumHeld', 'Held'],
  ['NumSuspended', 'Suspended'],
  ['NumSchedulerIdle', 'Scheduler idle'],
  ['NumSchedulerRunning', 'Scheduler running'],
  ['NumSchedulerHeld', 'Scheduler held'],
  ['TotalCompletedJobs', 'Completed (history)'],
  ['TotalRemovedJobs', 'Removed (history)'],
];

export function PlacementRecordDrawer({
  target,
  onClose,
}: {
  target: PlacementRecordTarget;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const key = ['placement', 'record', target.kind, target.name];
  const record = useQuery({
    queryKey: key,
    queryFn: () => api.placement.record(target.kind, target.name),
  });
  const toggle = useMutation({
    mutationFn: (suspend: boolean) => api.placement.setSuspended(target.kind, target.name, suspend),
    onSuccess: (rec) => {
      qc.setQueryData(key, rec);
      qc.invalidateQueries({ queryKey: ['placement', 'projects'] });
    },
  });

  const noun = target.kind === 'accounts' ? 'Account' : 'Project';
  return (
    <div className="fixed inset-0 z-40 flex justify-end" role="dialog" aria-label={`${noun} ${target.name}`}>
      <div className="absolute inset-0 bg-black/30" aria-hidden="true" onClick={onClose} />
      <aside className="relative h-full w-full max-w-md overflow-y-auto bg-white p-5 shadow-xl">
        <div className="flex items-start justify-between gap-3">
          <div>
            <div className="text-xs uppercase tracking-wide text-gray-500">{noun}</div>
            <h2 className="break-all font-mono text-base font-semibold text-gray-900">{target.name}</h2>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="rounded-sm px-2 py-1 text-sm text-gray-500 hover:bg-gray-100"
            aria-label="Close"
          >
            ✕
          </button>
        </div>

        {record.isLoading && <p className="mt-4 text-gray-400">Loading…</p>}
        {record.error && (
          <p className="mt-4 text-sm text-red-600">
            {(record.error as Error).message}
            {record.error instanceof ApiError ? ` (${record.error.status})` : ''}
          </p>
        )}
        {record.data && (
          <RecordBody
            rec={record.data}
            pending={toggle.isPending}
            error={toggle.error as Error | null}
            onToggle={(suspend) => toggle.mutate(suspend)}
          />
        )}
      </aside>
    </div>
  );
}

function RecordBody({
  rec,
  pending,
  error,
  onToggle,
}: {
  rec: PlacementRecord;
  pending: boolean;
  error: Error | null;
  onToggle: (suspend: boolean) => void;
}) {
  return (
    <div className="mt-4 space-y-4 text-sm">
      <div className="flex items-center gap-2">
        <span
          className={`rounded-full px-2 py-0.5 text-xs font-medium ${
            rec.enabled ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'
          }`}
        >
          {rec.enabled ? 'Active' : 'Suspended'}
        </span>
        {!rec.found && <span className="text-xs text-gray-500">No jobs submitted yet</span>}
      </div>
      {rec.disable_reason && <p className="text-gray-700">Reason: {rec.disable_reason}</p>}

      {rec.found && (
        <div className="flex items-center gap-3">
          <button
            type="button"
            disabled={pending}
            onClick={() => onToggle(rec.enabled)}
            className={`rounded-sm px-3 py-1.5 text-sm font-medium disabled:opacity-50 ${
              rec.enabled
                ? 'border border-red-300 text-red-700 hover:bg-red-50'
                : 'bg-brand-600 text-white hover:bg-brand-700'
            }`}
          >
            {pending ? 'Working…' : rec.enabled ? 'Suspend' : 'Unsuspend'}
          </button>
          {error && <span className="text-xs text-red-600">{error.message}</span>}
        </div>
      )}

      {rec.stats && Object.keys(rec.stats).length > 0 && (
        <div>
          <h3 className="mb-1 text-xs font-semibold uppercase tracking-wide text-gray-500">Jobs</h3>
          <dl className="grid grid-cols-2 gap-x-4 gap-y-1">
            {STATS.filter(([attr]) => rec.stats?.[attr] !== undefined).map(([attr, label]) => (
              <div key={attr} className="contents">
                <dt className="text-gray-600">{label}</dt>
                <dd className="text-right tabular-nums text-gray-900">{rec.stats?.[attr]}</dd>
              </div>
            ))}
          </dl>
        </div>
      )}

      {rec.members && rec.members.length > 0 && (
        <div>
          <h3 className="mb-1 text-xs font-semibold uppercase tracking-wide text-gray-500">
            {rec.kind === 'account' ? 'Identities' : 'Accounts'}
          </h3>
          <ul className="space-y-0.5 font-mono text-xs text-gray-800">
            {rec.members.map((m) => (
              <li key={m} className="break-all">
                {m}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

// PlacementProjectsTab lists the projects the placementd hands out, with
// their schedd state.
export function PlacementProjectsTab({
  onOpen,
}: {
  onOpen: (target: PlacementRecordTarget) => void;
}) {
  const [filter, setFilter] = useState('');
  const projects = useQuery({
    queryKey: ['placement', 'projects'],
    queryFn: api.placement.projects,
    refetchInterval: 60_000,
  });
  const rows = (projects.data?.projects ?? []).filter(
    (p) => !filter.trim() || p.name.toLowerCase().includes(filter.trim().toLowerCase()),
  );
  return (
    <div className="space-y-3">
      <input
        type="text"
        value={filter}
        onChange={(e) => setFilter(e.target.value)}
        placeholder="Filter by project"
        className="w-80 rounded-sm border border-gray-300 px-2 py-1 text-sm"
      />
      {projects.isLoading && <p className="text-gray-400">Loading…</p>}
      {projects.error && (
        <p className="text-sm text-red-600">Failed to list projects: {(projects.error as Error).message}</p>
      )}
      {projects.data && rows.length === 0 && <p className="text-sm text-gray-500">No projects match.</p>}
      {rows.length > 0 && (
        <div className="overflow-x-auto rounded-lg border border-gray-200 bg-white">
          <table className="min-w-full text-sm">
            <thead className="bg-gray-50 text-left text-xs uppercase tracking-wide text-gray-500">
              <tr>
                <th className="px-3 py-2">Project</th>
                <th className="px-3 py-2">Accounts</th>
                <th className="px-3 py-2">State</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {rows.map((p) => (
                <tr key={p.name} className="hover:bg-gray-50">
                  <td className="px-3 py-2">
                    <button
                      type="button"
                      onClick={() => onOpen({ kind: 'projects', name: p.name })}
                      className="font-mono text-xs text-brand-700 hover:underline"
                    >
                      {p.name}
                    </button>
                  </td>
                  <td className="px-3 py-2 text-xs tabular-nums">{p.members}</td>
                  <td className="px-3 py-2 text-xs">
                    {p.enabled ? 'Active' : <span className="text-red-700">Suspended</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
