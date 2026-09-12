'use client';

import Link from 'next/link';
import {
  JOB_STATUS_LABEL,
  type DashboardActivity,
  type ExitCodeCount,
  type HoldReasonCount,
  type GoodputSummary,
  type RecentJob,
} from '@/lib/api';
import type { ActivityStreamState } from '@/lib/useActivityStream';
import { archiveDrilldown, jobsDrilldown, statusConstraint } from '@/lib/drilldown';

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
      <div className="mb-2 flex items-baseline gap-2">
        <h2 className="text-sm font-semibold uppercase tracking-wide text-gray-500">
          Why jobs are held now
        </h2>
        {/* "Recently held" was wrong twice over. These are jobs still
            held, counted by when they entered that state -- so a job
            released by policy since leaves the count, which is why the
            numbers were seen to fall on their own. Saying both is also
            what separates this panel from the HELD tile. */}
        <span className="text-xs text-gray-400">
          {activity.hold_window_seconds
            ? `still held, entered in the last ${duration(activity.hold_window_seconds)}`
            : 'still held, entered recently'}
        </span>
      </div>
      <div className="overflow-hidden rounded border border-gray-200">
        <table className="min-w-full text-sm">
          <tbody className="divide-y divide-gray-100">
            {rows.map((row) => (
              <tr key={row.code} className="align-top hover:bg-gray-50">
                <td className="px-3 py-2 text-right tabular-nums font-medium w-20">
                  {row.count.toLocaleString()}
                </td>
                <td className="px-3 py-2">
                  {/* The count answers "how many"; the obvious next
                      question is "which ones", and it should not require
                      composing a ClassAd expression by hand. */}
                  <Link
                    href={holdRowHref(row, activity)}
                    className={`hover:underline ${row.code === 16 ? 'text-gray-600' : 'text-gray-900'}`}
                  >
                    {row.label}
                  </Link>
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

// jobHref points a row at a page that will actually resolve.
//
// A finished job survives in the queue for seconds before the schedd
// destroys it, so nearly everything under "recently completed" is only
// in the history archive by the time anyone clicks. Linking those to
// /jobs was a guaranteed "not found".
export function jobHref(job: RecentJob): string {
  const id = `${job.cluster_id}.${job.proc_id}`;
  return job.archived ? `/archive/${id}` : `/jobs/${id}`;
}

// holdRowHref drills from a row of the breakdown into the jobs that
// make it up.
//
// The window is carried across so the list matches the count that was
// clicked. Without it the page would show every job ever held for that
// reason, which is a different and usually much larger number -- and a
// drill-down whose total disagrees with the row above it reads as a bug.
export function holdRowHref(row: HoldReasonCount, activity: DashboardActivity): string {
  const parts = ['JobStatus == 5'];
  // -1 is the synthesised "other reasons" row, which is a sum rather
  // than a code and cannot be expressed as one.
  if (row.code >= 0) parts.push(`HoldReasonCode == ${row.code}`);
  if (activity.hold_window_seconds && activity.computed_at) {
    parts.push(`EnteredCurrentStatus >= ${activity.computed_at - activity.hold_window_seconds}`);
  }
  const why = row.code >= 0 ? `jobs held: ${row.label}` : 'recently held jobs';
  return `/jobs?constraint=${encodeURIComponent(parts.join(' && '))}&why=${encodeURIComponent(why)}`;
}

// RecentActivity shows what changed lately, which is how a burst becomes
// visible: four counts look the same whether nothing has happened for an
// hour or a thousand jobs started in the last minute.
export function RecentActivity({ activity }: { activity: DashboardActivity }) {
  // The window the lists were built over, so "see all" asks the same
  // question rather than a broader one.
  const since = activity.computed_at - (activity.hold_window_seconds ?? 3600);
  const lists = [
    {
      title: 'Recently submitted',
      jobs: activity.recently_submitted,
      allHref: jobsDrilldown(`QDate >= ${since}`, 'recently submitted jobs'),
    },
    {
      title: 'Recently started',
      jobs: activity.recently_started,
      allHref: jobsDrilldown(`JobCurrentStartDate >= ${since}`, 'recently started jobs'),
    },
    {
      title: 'Recently held',
      jobs: activity.recently_held,
      allHref: jobsDrilldown(
        `JobStatus == 5 && EnteredCurrentStatus >= ${since}`,
        'jobs held recently',
      ),
    },
    {
      title: 'Recently completed',
      jobs: activity.recently_completed,
      // The archive, not the queue: a finished job is gone from the
      // queue within seconds, so "all of them" only exists in history.
      allHref: archiveDrilldown(`CompletionDate >= ${since}`, 'recently completed jobs'),
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
              allHref={list.allHref}
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
  allHref,
}: {
  title: string;
  jobs: RecentJob[];
  note?: string;
  unavailable?: string;
  allHref?: string;
}) {
  return (
    <div className="rounded border border-gray-200">
      <div className="flex items-baseline gap-2 border-b border-gray-100 px-3 py-1.5 text-xs font-medium text-gray-600">
        <span>{title}</span>
        {/* These lists are the newest handful, not everything in the
            window. Without a way through to the rest, a truncated list
            is indistinguishable from a complete one. */}
        {allHref && jobs.length > 0 && (
          <Link href={allHref} className="ml-auto font-normal text-brand-700 hover:underline">
            see all
          </Link>
        )}
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
                  href={jobHref(job)}
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
  href,
}: {
  label: string;
  value: number;
  primary?: boolean;
  href?: string;
}) {
  const body = (
    <>
      <div className="text-xs uppercase tracking-wide text-gray-500">{label}</div>
      <div className="mt-1 text-2xl font-semibold text-gray-900">
        {value.toLocaleString()}
      </div>
    </>
  );
  const cls = `block rounded-lg border p-4 ${
    primary ? 'border-brand-200 bg-brand-50' : 'border-gray-200 bg-white'
  }`;

  // A tile with nothing in it links nowhere: sending someone to an empty
  // list is a worse answer than not offering the link.
  if (!href || value === 0) {
    return <div className={cls}>{body}</div>;
  }
  return (
    <Link href={href} className={`${cls} transition-colors hover:border-brand-300 hover:bg-brand-50`}>
      {body}
    </Link>
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
            {statusConstraint(key) ? (
              <Link
                href={jobsDrilldown(
                  statusConstraint(key) as string,
                  `${(STATUS_LABEL_BY_KEY[key] ?? key).toLowerCase()} jobs`,
                )}
                className="hover:underline"
              >
                {STATUS_LABEL_BY_KEY[key] ?? key}
              </Link>
            ) : (
              <span>{STATUS_LABEL_BY_KEY[key] ?? key}</span>
            )}
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

      {/* The list scrolls inside a fixed height instead of growing the
          page. A busy access point produces events indefinitely, and an
          uncapped ticker turns the dashboard into an endless document
          where the panels below it drift out of reach. */}
      <div className="max-h-64 overflow-y-auto rounded border border-gray-200">
        {events.length === 0 ? (
          <p className="px-3 py-2 text-xs text-gray-400">
            {connected ? 'Nothing has happened since this page loaded.' : 'Waiting for the stream...'}
          </p>
        ) : (
          <ul className="divide-y divide-gray-100">
            {events.map((ev) => (
              <li
                // Arrival order, not event content: two changes to one
                // job inside a second are identical in every field the
                // event carries, and duplicate keys make React reuse the
                // wrong row.
                key={ev.seq ?? `${ev.at}-${ev.cluster_id}.${ev.proc_id}-${ev.kind}`}
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

// Goodput answers the question the tiles cannot: of the work that
// actually ran, how much of it survived.
//
// The wall-clock split is the part worth reading. Ten thousand jobs
// failing in two seconds each is a broken submission and costs nothing;
// ten failing after twelve hours each is most of a day of a machine
// thrown away. The counts alone cannot tell those apart.
export function Goodput({ goodput }: { goodput?: GoodputSummary }) {
  // Absent means no history archive answered, not that nothing
  // succeeded. Rendering zeros there would be a confident wrong answer.
  if (!goodput) return null;

  const { succeeded, failed, unfinished, good_seconds, bad_seconds } = goodput;
  const finished = succeeded + failed + unfinished;
  if (finished === 0) {
    return null;
  }
  const wall = good_seconds + bad_seconds;

  return (
    <section>
      <div className="mb-2 flex items-baseline gap-2">
        <h2 className="text-sm font-semibold uppercase tracking-wide text-gray-500">
          Goodput
        </h2>
        <span className="text-xs text-gray-400">last {goodput.window_hours}h</span>
      </div>

      <div className="rounded border border-gray-200 p-3">
        <div className="flex flex-wrap items-baseline gap-x-6 gap-y-1 text-sm">
          <span>
            <span className="font-medium text-green-700">{succeeded.toLocaleString()}</span>
            <span className="ml-1.5 text-gray-500">succeeded</span>
          </span>
          <span>
            <span className="font-medium text-red-700">{failed.toLocaleString()}</span>
            <span className="ml-1.5 text-gray-500">failed</span>
          </span>
          {unfinished > 0 && (
            <span>
              <span className="font-medium text-gray-700">{unfinished.toLocaleString()}</span>
              {/* A job its owner cancelled is not the access point going
                  wrong, so it is counted apart from failures. */}
              <span className="ml-1.5 text-gray-500">did not finish</span>
            </span>
          )}
        </div>

        {wall > 0 && (
          <div className="mt-2.5">
            <div className="flex h-1.5 overflow-hidden rounded-full bg-gray-100">
              <div
                className="bg-green-500"
                style={{ width: `${(good_seconds / wall) * 100}%` }}
                aria-hidden="true"
              />
              <div
                className="bg-red-400"
                style={{ width: `${(bad_seconds / wall) * 100}%` }}
                aria-hidden="true"
              />
            </div>
            <p className="mt-1.5 text-xs text-gray-500">
              {Math.round((good_seconds / wall) * 100)}% of {duration(wall)} of compute went
              to jobs that succeeded
              {bad_seconds > 0 && <> · {duration(bad_seconds)} wasted</>}
            </p>
          </div>
        )}

        {!!goodput.top_failures?.length && (
          <ul className="mt-2.5 space-y-0.5 border-t border-gray-100 pt-2 text-xs text-gray-600">
            {goodput.top_failures.map((f) => (
              <li key={f.signal ? 'signal' : `code-${f.code}`} className="flex gap-2">
                <Link href={failureDrilldown(f, goodput.since)} className="font-medium hover:underline">
                  {f.signal ? 'killed by a signal' : `exit ${f.code}`}
                </Link>
                <span className="text-gray-500">
                  {f.count.toLocaleString()} {f.count === 1 ? 'job' : 'jobs'}
                </span>
                {/* Ranked by time rather than count: the expensive
                    failure is frequently the rare one. */}
                <span className="ml-auto tabular-nums text-gray-400">{duration(f.seconds)}</span>
              </li>
            ))}
          </ul>
        )}
      </div>
    </section>
  );
}

// failureDrilldown points at the finished jobs behind one failure row.
//
// The archive, always: these jobs ran to completion and the queue
// destroyed them within seconds of recording how they went. It is also
// the only place the exit status still exists.
export function failureDrilldown(f: ExitCodeCount, since: number): string {
  // A signalled job's ExitCode is whatever happened to be in the ad, so
  // matching on it would select the wrong jobs -- often those that
  // exited cleanly.
  const what = f.signal ? 'ExitBySignal == true' : `ExitCode == ${f.code} && ExitBySignal =!= true`;
  const why = f.signal ? 'jobs killed by a signal' : `jobs that exited ${f.code}`;
  return archiveDrilldown(`${what} && CompletionDate >= ${since}`, why);
}

// duration renders a span of seconds the way an operator says it.
export function duration(seconds: number): string {
  if (seconds < 60) return `${Math.round(seconds)}s`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m`;
  const hours = seconds / 3600;
  if (hours < 48) return `${hours < 10 ? hours.toFixed(1) : Math.round(hours)}h`;
  return `${Math.round(hours / 24)}d`;
}
