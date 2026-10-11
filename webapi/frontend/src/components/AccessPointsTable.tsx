'use client';

import Link from 'next/link';
import { ApiError } from '@/lib/api';
import { useAccessPoints } from '@/lib/multiap';

const STATE_CLS: Record<string, string> = {
  fresh: 'bg-green-100 text-green-800',
  stale: 'bg-amber-100 text-amber-800',
  absent: 'bg-gray-200 text-gray-700',
  untrusted: 'bg-red-100 text-red-800',
  retiring: 'bg-gray-200 text-gray-700',
};

const STATE_LABEL: Record<string, string> = {
  fresh: 'current',
  stale: 'behind',
  absent: 'not available',
  untrusted: 'untrusted',
  retiring: 'leaving',
};

// AccessPointsTable lists the access points this server fronts and how
// current each one's jobs are.
export function AccessPointsTable() {
  const { data, error, isLoading } = useAccessPoints(true);
  if (isLoading) return <p className="text-gray-400">Loading…</p>;
  if (error) {
    return (
      <p className="text-sm text-red-600">
        Could not load the access points: {error instanceof ApiError ? error.message : String(error)}
      </p>
    );
  }
  if (!data) return null;
  return (
    <div className="space-y-2">
      {!data.hub.reachable && (
        <div className="rounded-sm border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">
          Job listings are unavailable{data.hub.last_error ? `: ${data.hub.last_error}` : '.'}
        </div>
      )}
      <div className="overflow-x-auto rounded-lg border border-gray-200 bg-white">
        <table className="min-w-full text-sm">
          <thead className="bg-gray-50 text-left text-xs uppercase tracking-wide text-gray-500">
            <tr>
              <th className="px-3 py-2">Access point</th>
              <th className="px-3 py-2">Job data</th>
              <th className="px-3 py-2">Behind by</th>
              <th className="px-3 py-2">Advertised</th>
              <th className="px-3 py-2"></th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-100">
            {data.aps.length === 0 ? (
              <tr>
                <td colSpan={5} className="px-3 py-4 text-center text-xs text-gray-500">
                  No access points match this server&apos;s configuration yet.
                </td>
              </tr>
            ) : (
              data.aps.map((ap) => (
                <tr key={ap.schedd}>
                  <td className="px-3 py-2 font-mono text-xs text-gray-900">{ap.schedd}</td>
                  <td className="px-3 py-2">
                    <span
                      className={`inline-flex rounded-full px-2 py-0.5 text-xs font-medium ${STATE_CLS[ap.hub.state] ?? 'bg-gray-200 text-gray-700'}`}
                      title={ap.hub.reason}
                    >
                      {STATE_LABEL[ap.hub.state] ?? ap.hub.state}
                    </span>
                  </td>
                  <td className="px-3 py-2 text-xs text-gray-700 tabular-nums">
                    {ap.hub.staleness_seconds !== undefined ? `${ap.hub.staleness_seconds} s` : '—'}
                  </td>
                  <td className="px-3 py-2 text-xs text-gray-700">
                    {ap.in_collector
                      ? 'yes'
                      : `no${ap.last_seen ? ` (last seen ${new Date(ap.last_seen).toLocaleString()})` : ''}`}
                  </td>
                  <td className="px-3 py-2 text-right text-xs whitespace-nowrap">
                    <Link
                      href={`/jobs?schedd=${encodeURIComponent(ap.schedd)}`}
                      className="text-brand-700 hover:underline"
                    >
                      jobs
                    </Link>
                    {' · '}
                    <Link
                      href={`/archive?schedd=${encodeURIComponent(ap.schedd)}`}
                      className="text-brand-700 hover:underline"
                    >
                      archive
                    </Link>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
