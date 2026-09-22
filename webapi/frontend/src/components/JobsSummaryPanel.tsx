'use client';

import { gibNum } from '@/lib/pool';
import type { JobsSummary } from '@/lib/batches';

// JobsSummaryPanel answers "what am I looking at, and what is it using?"
// above a job listing.
//
// It summarizes the jobs ON SCREEN, so it moves with the filters: narrow
// to one user or to the held jobs and the totals narrow with it. A summary
// that ignored the filters would contradict the table under it.
export function JobsSummaryPanel({
  summary,
  showOwners,
}: {
  summary: JobsSummary;
  // Whether a user count is worth a tile. In the "Mine" view it is
  // always 1, which is not information.
  showOwners?: boolean;
}) {
  const rows: { label: string; inUse: string; idle: string }[] = [
    {
      label: 'CPUs',
      inUse: summary.running.cpus.toLocaleString(),
      idle: summary.idle.cpus.toLocaleString(),
    },
    {
      label: 'Memory (GiB)',
      inUse: gibNum(summary.running.memoryMB),
      idle: gibNum(summary.idle.memoryMB),
    },
  ];
  // GPUs only when somebody asked for one; a column of zeroes on a pool
  // without GPUs is noise.
  if (summary.running.gpus > 0 || summary.idle.gpus > 0) {
    rows.push({
      label: 'GPUs',
      inUse: summary.running.gpus.toLocaleString(),
      idle: summary.idle.gpus.toLocaleString(),
    });
  }

  const unresolved = summary.running.unresolved + summary.idle.unresolved;

  return (
    <div className="grid gap-3 lg:grid-cols-3">
      <div className="overflow-x-auto rounded-lg border border-gray-200 bg-white lg:col-span-2">
        <table className="min-w-full text-sm tabular-nums">
          <thead className="bg-gray-50 text-xs uppercase tracking-wide text-gray-500">
            <tr>
              <th className="px-3 py-2 text-left">Resource</th>
              <th className="px-3 py-2 text-right">In use</th>
              <th className="px-3 py-2 text-right">Requested (idle)</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-100">
            {rows.map((r) => (
              <tr key={r.label}>
                <td className="px-3 py-2 font-medium text-gray-700">{r.label}</td>
                <td className="px-3 py-2 text-right text-gray-900">{r.inUse}</td>
                <td className="px-3 py-2 text-right text-gray-500">{r.idle}</td>
              </tr>
            ))}
          </tbody>
        </table>
        <p className="border-t border-gray-100 px-3 py-1.5 text-[11px] text-gray-400">
          Requested allocations, not measured usage. &ldquo;In use&rdquo; covers
          running, suspended and output-transferring jobs.
          {unresolved > 0 && (
            <>
              {' '}
              {unresolved.toLocaleString()} job
              {unresolved === 1 ? "'s request is" : "s' requests are"} still an
              unevaluated expression and {unresolved === 1 ? 'is' : 'are'} not
              counted.
            </>
          )}
        </p>
      </div>
      <div className="grid grid-cols-2 gap-3 content-start">
        <SummaryTile label="Batches" value={summary.batches.toLocaleString()} />
        <SummaryTile label="Jobs" value={summary.jobs.toLocaleString()} />
        {showOwners && (
          <SummaryTile label="Users" value={summary.owners.toLocaleString()} />
        )}
      </div>
    </div>
  );
}

function SummaryTile({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-lg border border-gray-200 bg-white p-3">
      <div className="text-xs uppercase tracking-wide text-gray-500">{label}</div>
      <div className="mt-1 text-lg font-semibold text-gray-900">{value}</div>
    </div>
  );
}
