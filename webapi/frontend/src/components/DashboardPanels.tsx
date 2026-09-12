'use client';

import Link from 'next/link';
import { JOB_STATUS_LABEL, type DashboardActivity, type RecentJob } from '@/lib/api';
import type { ActivityStreamState } from '@/lib/useActivityStream';

// The dashboard's panels, split out of app/page.tsx so they can be
// rendered one state at a time in a test. They cannot live in the page
// module: Next.js treats a route file's exports as a closed set
// (`page.ts` may export a component, `metadata`, `generateMetadata` and
// little else), so exporting a panel from there fails the production
// build -- and, notably, not `tsc --noEmit`, since the rule lives in
// Next's generated route types.

// The panels below are exported so page.test.tsx can render them one
// state at a time. Next.js only ever uses the default export here, so
// these are for the tests; keeping them in this file rather than
// splitting the page into a components/ tree keeps the diff small.
//
// HoldReasons answers the question a HELD count cannot: whether ten
// thousand held jobs are one broken submission or ten thousand unrelated
// problems. Ordered by weight, because the dominant cause is the one to
// act on.
export function HoldReasons({ activity }: { activity: DashboardActivity }) {
  const rows = activity.hold_reasons ?? [];
  if (rows.length === 0) return null;

  return (
    <section>
      <h2 className="mb-2 text-sm font-semibold uppercase tracking-wide text-gray-500">
        Why jobs are held
      </h2>
      <div className="overflow-hidden rounded border border-gray-200">
        <table className="min-w-full text-sm">
          <tbody className="divide-y divide-gray-100">
            {rows.map((row) => (
              <tr key={row.code} className="align-top">
                <td className="px-3 py-2 text-right tabular-nums font-medium w-20">
                  {row.count.toLocaleString()}
                </td>
                <td className="px-3 py-2">
                  <span className={row.code === 16 ? 'text-gray-600' : 'text-gray-900'}>
                    {row.label}
                  </span>
                  {row.code === 16 && (
                    <span className="ml-2 text-xs text-gray-400">
                      (a submit in progress, not a failure)
                    </span>
                  )}
                  {row.example && (
                    <div className="mt-0.5 font-mono text-xs text-gray-500 break-all">
                      {row.example}
                    </div>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

// RecentActivity shows what changed lately, which is how a burst becomes
// visible: four counts look the same whether nothing has happened for an
// hour or a thousand jobs started in the last minute.
export function RecentActivity({ activity }: { activity: DashboardActivity }) {
  const lists = [
    { title: 'Recently submitted', jobs: activity.recently_submitted },
    { title: 'Recently started', jobs: activity.recently_started },
    { title: 'Recently held', jobs: activity.recently_held },
    {
      title: 'Recently completed',
      jobs: activity.recently_completed,
      // The queue only holds finished jobs until the reaper takes them,
      // so without the archive this is the last few seconds rather than
      // the last hour. Saying which keeps a short list from reading as a
      // quiet access point.
      note: activity.completed_available && activity.completed_partial
        ? 'only what the queue still holds — the history mirror is not answering'
        : undefined,
      unavailable: !activity.completed_available
        ? 'needs the htcondordb history mirror'
        : undefined,
    },
  ];
  const anything = lists.some((l) => (l.jobs?.length ?? 0) > 0 || l.unavailable);

  return (
    <section>
      <div className="mb-2 flex items-baseline gap-2">
        <h2 className="text-sm font-semibold uppercase tracking-wide text-gray-500">
          Recent activity
        </h2>
        <span className="text-xs text-gray-400">
          from the {activity.source}
          {activity.computed_at > 0 && <> · {ago(activity.computed_at)} ago</>}
        </span>
      </div>

      {!anything && (
        <p className="text-sm text-gray-500">
          Nothing has changed recently.
        </p>
      )}

      {anything && (
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
          {lists.map((list) => (
            <RecentList
              key={list.title}
              title={list.title}
              jobs={list.jobs ?? []}
              note={list.note}
              unavailable={list.unavailable}
            />
          ))}
        </div>
      )}
    </section>
  );
}

function RecentList({
  title,
  jobs,
  note,
  unavailable,
}: {
  title: string;
  jobs: RecentJob[];
  note?: string;
  unavailable?: string;
}) {
  return (
    <div className="rounded border border-gray-200">
      <div className="border-b border-gray-100 px-3 py-1.5 text-xs font-medium text-gray-600">
        {title}
      </div>
      {note && <p className="px-3 pt-1.5 text-xs text-amber-700">{note}</p>}
      {jobs.length === 0 ? (
        // "unavailable" and "none" are different answers: one means
        // nothing could tell us, the other that nothing happened.
        <p className="px-3 py-2 text-xs text-gray-400">{unavailable ?? 'none'}</p>
      ) : (
        <ul className="divide-y divide-gray-100">
          {jobs.map((job) => (
            <li key={`${job.cluster_id}.${job.proc_id}`} className="px-3 py-1.5">
              <div className="flex items-baseline justify-between gap-2">
                <Link
                  href={`/jobs/${job.cluster_id}.${job.proc_id}`}
                  className="font-mono text-xs text-brand-700 hover:underline"
                >
                  {job.cluster_id}.{job.proc_id}
                </Link>
                <span className="text-xs tabular-nums text-gray-400">{ago(job.at)}</span>
              </div>
              {job.detail && (
                <div className="truncate font-mono text-xs text-gray-500" title={job.detail}>
                  {job.detail}
                </div>
              )}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

// ago renders an age compactly. Absolute timestamps make a reader do
// arithmetic to answer the only question they have, which is "just now,
// or a while back?".
export function ago(unixSeconds: number): string {
  const secs = Math.max(0, Math.floor(Date.now() / 1000) - unixSeconds);
  if (secs < 60) return `${secs}s`;
  if (secs < 3600) return `${Math.floor(secs / 60)}m`;
  if (secs < 86400) return `${Math.floor(secs / 3600)}h`;
  return `${Math.floor(secs / 86400)}d`;
}

export const STATUS_LABEL_BY_KEY: Record<string, string> = {
  idle: JOB_STATUS_LABEL[1],
  running: JOB_STATUS_LABEL[2],
  removed: JOB_STATUS_LABEL[3],
  completed: JOB_STATUS_LABEL[4],
  held: JOB_STATUS_LABEL[5],
  // Not a JobStatus: the server buckets held-because-spooling separately
  // so a routine submit does not show up as HELD. Matches the label
  // displayJobStatus gives the same job on the jobs page.
  uploading: 'Uploading Inputs',
  transferring_output: JOB_STATUS_LABEL[6],
  suspended: JOB_STATUS_LABEL[7],
};

export function StatCard({
  label,
  value,
  primary,
}: {
  label: string;
  value: number;
  primary?: boolean;
}) {
  return (
    <div
      className={`rounded-lg border p-4 ${
        primary ? 'border-brand-200 bg-brand-50' : 'border-gray-200 bg-white'
      }`}
    >
      <div className="text-xs uppercase tracking-wide text-gray-500">{label}</div>
      <div className="mt-1 text-2xl font-semibold text-gray-900">
        {value.toLocaleString()}
      </div>
    </div>
  );
}

export function OtherStatuses({ byStatus }: { byStatus: Record<string, number> }) {
  const known = new Set([
    'idle',
    'running',
    'held',
    'completed',
    'removed',
    'transferring_output',
    'suspended',
    'uploading',
  ]);
  const extras = Object.entries(byStatus).filter(
    ([key, n]) => n > 0 && !['idle', 'running', 'held', 'completed'].includes(key),
  );
  if (extras.length === 0) return null;

  return (
    <div className="rounded-lg border border-gray-200 bg-white p-4">
      <div className="text-xs uppercase tracking-wide text-gray-500 mb-2">
        Other statuses
      </div>
      <ul className="text-sm text-gray-700 space-y-1">
        {extras.map(([key, n]) => (
          <li key={key} className="flex justify-between">
            <span>{STATUS_LABEL_BY_KEY[key] ?? key}</span>
            <span className="font-medium">{n.toLocaleString()}</span>
            {!known.has(key) && (
              <span className="ml-2 text-gray-400 text-xs">(unmapped)</span>
            )}
          </li>
        ))}
      </ul>
    </div>
  );
}

// LiveTicker is the dashboard's one moving part: transitions as they
// happen, rather than a count that was true when the page loaded.
//
// It renders nothing at all where there is no mirror to stream from. An
// empty panel that never moves is worse than no panel -- it reads as a
// broken feature rather than an absent one -- and the deployments
// without a mirror are exactly the ones that cannot have this.
export function LiveTicker({ events, connected, unavailable }: ActivityStreamState) {
  if (unavailable) return null;

  return (
    <section>
      <div className="mb-2 flex items-baseline gap-2">
        <h2 className="text-sm font-semibold uppercase tracking-wide text-gray-500">Live</h2>
        <span className="flex items-center gap-1.5 text-xs text-gray-400">
          <span
            className={`inline-block h-1.5 w-1.5 rounded-full ${
              connected ? 'bg-green-500' : 'bg-gray-300'
            }`}
            aria-hidden="true"
          />
          {connected ? 'watching' : 'connecting'}
        </span>
      </div>

      <div className="rounded border border-gray-200">
        {events.length === 0 ? (
          <p className="px-3 py-2 text-xs text-gray-400">
            {connected ? 'Nothing has happened since this page loaded.' : 'Waiting for the stream...'}
          </p>
        ) : (
          <ul className="divide-y divide-gray-100">
            {events.map((ev) => (
              <li
                key={`${ev.at}-${ev.cluster_id}.${ev.proc_id}-${ev.kind}`}
                className="flex items-baseline gap-2 px-3 py-1.5 text-xs"
              >
                <span
                  className={`w-20 shrink-0 font-medium ${ACTIVITY_TONE[ev.kind] ?? 'text-gray-600'}`}
                >
                  {ev.kind}
                </span>
                <Link
                  href={`/jobs/${ev.cluster_id}.${ev.proc_id}`}
                  className="font-mono text-brand-700 hover:underline"
                >
                  {ev.cluster_id}.{ev.proc_id}
                </Link>
                {ev.owner && <span className="text-gray-500">{ev.owner}</span>}
                {ev.detail && (
                  <span className="truncate text-gray-500" title={ev.detail}>
                    {ev.detail}
                  </span>
                )}
                {/* A gap that looks like a quiet minute is worse than one
                    that says it is a gap. */}
                {!!ev.skipped && (
                  <span className="ml-auto shrink-0 text-gray-400">
                    +{ev.skipped} not shown
                  </span>
                )}
                <span className="ml-auto shrink-0 tabular-nums text-gray-400">{ago(ev.at)}</span>
              </li>
            ))}
          </ul>
        )}
      </div>
    </section>
  );
}

const ACTIVITY_TONE: Record<string, string> = {
  submitted: 'text-blue-700',
  started: 'text-green-700',
  held: 'text-amber-700',
  released: 'text-blue-700',
  completed: 'text-gray-700',
  removed: 'text-gray-500',
};
