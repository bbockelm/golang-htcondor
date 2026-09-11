'use client';

import { useQuery } from '@tanstack/react-query';
import Link from 'next/link';
import {
  api,
  JOB_STATUS_LABEL,
  type DashboardActivity,
  type RecentJob,
} from '@/lib/api';
import { ScopeToggle, useScope } from '@/components/ScopeToggle';

export default function Dashboard() {
  const { data: session, isLoading: sessionLoading } = useQuery({
    queryKey: ['session'],
    queryFn: api.auth.me,
  });

  if (sessionLoading) {
    return <p className="text-gray-400">Loading...</p>;
  }

  if (!session?.authenticated) {
    return <LandingPage />;
  }

  return (
    <AuthenticatedDashboard
      username={session.username ?? ''}
      isAdmin={!!session.is_admin}
    />
  );
}

function LandingPage() {
  return (
    <div className="max-w-2xl">
      <h1 className="text-2xl font-bold text-gray-900">HTCondor Access Point</h1>
      <p className="mt-3 text-gray-600">
        Sign in to view your jobs, submit new work, and download outputs.
      </p>
      <a
        href="/login"
        className="mt-6 inline-block rounded-sm bg-brand-600 px-4 py-2 text-sm font-medium text-white hover:bg-brand-700"
      >
        Sign In
      </a>
    </div>
  );
}

function AuthenticatedDashboard({
  username,
  isAdmin,
}: {
  username: string;
  isAdmin: boolean;
}) {
  // Shared with /jobs and /archive; see lib/scope.ts. Default is "mine"
  // for everyone — admin pool-wide counts are explicit, not surprising.
  const [scope] = useScope();
  const ownedByMe = scope === 'mine';

  const { data, isLoading, error } = useQuery({
    queryKey: ['dashboard', scope],
    queryFn: () => api.dashboard({ owned_by_me: ownedByMe }),
    // The snapshot behind this refreshes on its own interval
    // server-side; polling faster only re-fetches the same bytes.
    refetchInterval: 30_000,
  });

  return (
    <div className="space-y-6">
      <div className="flex items-baseline gap-3 flex-wrap">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Dashboard</h1>
          <p className="text-sm text-gray-500">Signed in as {username}</p>
        </div>
        {isAdmin && <ScopeToggle className="ml-auto" />}
      </div>

      {isLoading && <p className="text-gray-400">Loading job counts...</p>}

      {error && (
        <p className="text-red-600 text-sm">
          Could not load dashboard: {(error as Error).message}
        </p>
      )}

      {data && (
        <>
          <div className="grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-4">
            <StatCard label="Total" value={data.jobs_total} primary />
            {(['idle', 'running', 'held', 'completed'] as const).map((key) => (
              <StatCard
                key={key}
                label={STATUS_LABEL_BY_KEY[key]}
                value={data.jobs_by_status[key] ?? 0}
              />
            ))}
          </div>

          <OtherStatuses byStatus={data.jobs_by_status} />

          <HoldReasons activity={data.activity} />

          <RecentActivity activity={data.activity} />

          <div>
            <Link
              href="/jobs"
              className="text-sm text-brand-700 hover:text-brand-900 underline"
            >
              View all jobs →
            </Link>
          </div>
        </>
      )}
    </div>
  );
}

// HoldReasons answers the question a HELD count cannot: whether ten
// thousand held jobs are one broken submission or ten thousand unrelated
// problems. Ordered by weight, because the dominant cause is the one to
// act on.
function HoldReasons({ activity }: { activity: DashboardActivity }) {
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
function RecentActivity({ activity }: { activity: DashboardActivity }) {
  const lists = [
    { title: 'Recently submitted', jobs: activity.recently_submitted, verb: 'submitted' },
    { title: 'Recently started', jobs: activity.recently_started, verb: 'started' },
    { title: 'Recently held', jobs: activity.recently_held, verb: 'held' },
  ];
  const anything = lists.some((l) => (l.jobs?.length ?? 0) > 0);

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
        <div className="grid gap-4 md:grid-cols-3">
          {lists.map((list) => (
            <RecentList key={list.title} title={list.title} jobs={list.jobs ?? []} />
          ))}
        </div>
      )}

      {!activity.completed_available && (
        // Not an empty list: a finished job is removed from the queue by
        // the schedd, so a queue walk cannot see one however recent.
        // Showing an empty "recently completed" would read as "nothing
        // finished", which is the opposite of the truth here.
        <p className="mt-3 text-xs text-gray-400">
          Recently completed is not shown: finished jobs leave the queue, so this
          needs the htcondordb history mirror, which is not answering.
        </p>
      )}
    </section>
  );
}

function RecentList({ title, jobs }: { title: string; jobs: RecentJob[] }) {
  return (
    <div className="rounded border border-gray-200">
      <div className="border-b border-gray-100 px-3 py-1.5 text-xs font-medium text-gray-600">
        {title}
      </div>
      {jobs.length === 0 ? (
        <p className="px-3 py-2 text-xs text-gray-400">none</p>
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
function ago(unixSeconds: number): string {
  const secs = Math.max(0, Math.floor(Date.now() / 1000) - unixSeconds);
  if (secs < 60) return `${secs}s`;
  if (secs < 3600) return `${Math.floor(secs / 60)}m`;
  if (secs < 86400) return `${Math.floor(secs / 3600)}h`;
  return `${Math.floor(secs / 86400)}d`;
}

const STATUS_LABEL_BY_KEY: Record<string, string> = {
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

function StatCard({
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

function OtherStatuses({ byStatus }: { byStatus: Record<string, number> }) {
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
