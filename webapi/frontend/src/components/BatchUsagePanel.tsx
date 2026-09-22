'use client';

import type { BatchUsage, BatchUsageRow, ResourceUnit } from '@/lib/batches';

// BatchUsagePanel sits at the top of an expanded batch: what the pool
// handed this batch, what the execute nodes measured it using, and what
// it is still waiting for.
//
// The comparison is the point. A batch whose jobs asked for 8 GiB and
// are touching 400 MiB is the single most common thing worth knowing
// about a running batch, and until now the page could not say it.
export function BatchUsagePanel({
  usage,
  loading,
}: {
  usage: BatchUsage;
  loading?: boolean;
}) {
  const nothingToSay =
    usage.running === 0 && usage.idle === 0 && !loading;
  if (nothingToSay) return null;

  return (
    <div className="border-t border-gray-200 bg-white px-3 py-2">
      <div className="mb-1.5 flex flex-wrap items-baseline gap-2 text-[11px] text-gray-500">
        <span className="font-medium uppercase tracking-wide">Resources</span>
        <span>
          {usage.running.toLocaleString()} running, {usage.idle.toLocaleString()} idle
        </span>
        {loading && <span className="text-gray-400">loading…</span>}
      </div>
      <table className="min-w-full max-w-2xl text-xs tabular-nums">
        <thead className="text-left text-[10px] uppercase tracking-wide text-gray-500">
          <tr>
            <th className="py-1 pr-4 font-normal">Resource</th>
            <th className="py-1 pr-4 text-right font-normal">Allocated</th>
            <th className="py-1 pr-4 text-right font-normal">Used</th>
            <th className="py-1 pr-4 text-right font-normal">Of allocation</th>
            <th className="py-1 text-right font-normal">Waiting (idle)</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-gray-100">
          {usage.rows.map((r) => (
            <UsageRow key={r.label} row={r} />
          ))}
        </tbody>
      </table>
      <p className="mt-1 text-[10px] text-gray-400">
        {usage.running > 0 && usage.reporting === 0
          ? // Distinguishing "nothing measured yet" from "using nothing":
            // a batch that started ten seconds ago has no report, and
            // showing it as 0% used would read as a stuck job.
            'The execute nodes have not reported usage for these jobs yet.'
          : 'Allocated and waiting are what the jobs requested; used is what the execute nodes measured.'}
      </p>
    </div>
  );
}

function UsageRow({ row }: { row: BatchUsageRow }) {
  const ratio =
    row.used !== undefined && row.allocated !== undefined && row.allocated > 0
      ? row.used / row.allocated
      : undefined;
  return (
    <tr>
      <td className="py-1 pr-4 font-medium text-gray-700">{row.label}</td>
      <td className="py-1 pr-4 text-right text-gray-900">
        {fmt(row.allocated, row.unit)}
      </td>
      <td className="py-1 pr-4 text-right text-gray-900">
        {fmt(row.used, row.unit)}
      </td>
      <td
        className={`py-1 pr-4 text-right ${
          // Over the allocation is not an error -- memory can exceed a
          // request before the startd reacts -- but it is the case
          // worth spotting, as is a batch touching a tenth of what it
          // reserved.
          ratio === undefined
            ? 'text-gray-400'
            : ratio > 1
              ? 'text-red-700'
              : ratio < 0.25
                ? 'text-amber-700'
                : 'text-gray-500'
        }`}
      >
        {ratio === undefined ? '—' : `${Math.round(ratio * 100)}%`}
      </td>
      <td className="py-1 text-right text-gray-500">
        {fmt(row.waiting, row.unit)}
      </td>
    </tr>
  );
}

// fmt renders a value in the unit it was measured in, picking a scale
// that keeps the number readable: bytes-ish quantities go to GiB once
// they are big enough to be worth it.
function fmt(v: number | undefined, unit: ResourceUnit): string {
  if (v === undefined) return '—';
  if (unit === 'count') {
    // CPUsUsage is fractional; a request is not. Show a decimal only
    // when there is one, so "4" does not render as "4.0".
    return Number.isInteger(v) ? v.toLocaleString() : v.toFixed(1);
  }
  const mib = unit === 'kib' ? v / 1024 : v;
  if (mib >= 1024) return `${(mib / 1024).toFixed(1)} GiB`;
  return `${Math.round(mib).toLocaleString()} MiB`;
}
