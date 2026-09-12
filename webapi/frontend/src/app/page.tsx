'use client';

import { useQuery } from '@tanstack/react-query';
import Link from 'next/link';
import { api } from '@/lib/api';
import {
  Goodput,
  HoldReasons,
  LiveTicker,
  OtherStatuses,
  RecentActivity,
  StatCard,
  STATUS_LABEL_BY_KEY,
} from '@/components/DashboardPanels';
import { useActivityStream } from '@/lib/useActivityStream';
import { jobsDrilldown, statusConstraint } from '@/lib/drilldown';
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

  // The live stream is independent of the snapshot query: it needs no
  // data from it, and a mirror-less deployment simply renders no ticker.
  const live = useActivityStream(ownedByMe);

  // Two queries, not one, so the page paints in stages: the tiles are a
  // single aggregate against the mirror and land in a few milliseconds,
  // while the panels below cost a hold breakdown and four windowed
  // lookups. Combined, everything waited for the slowest of those --
  // which is what made the page feel slow after the panels were added.
  const { data, isLoading, error } = useQuery({
    queryKey: ['dashboard', scope],
    queryFn: () => api.dashboard({ owned_by_me: ownedByMe }),
    // The snapshot behind this refreshes on its own interval
    // server-side; polling faster only re-fetches the same bytes.
    refetchInterval: 30_000,
  });

  const { data: panels, isLoading: panelsLoading } = useQuery({
    queryKey: ['dashboard-activity', scope],
    queryFn: () => api.dashboardActivity({ owned_by_me: ownedByMe }),
    refetchInterval: 30_000,
  });

  // An older server still answers /dashboard with both halves; prefer
  // the dedicated response and fall back to what the tiles carried.
  const activity = panels?.activity ?? data?.activity;
  const goodput = panels?.goodput ?? data?.goodput;

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
            <StatCard label="Total" value={data.jobs_total} primary href="/jobs" />
            {(['idle', 'running', 'held', 'completed'] as const).map((key) => (
              <StatCard
                key={key}
                label={STATUS_LABEL_BY_KEY[key]}
                value={data.jobs_by_status[key] ?? 0}
                href={jobsDrilldown(
                  statusConstraint(key) as string,
                  `${STATUS_LABEL_BY_KEY[key].toLowerCase()} jobs`,
                )}
              />
            ))}
          </div>

          <OtherStatuses byStatus={data.jobs_by_status} />

          <LiveTicker {...live} />

          <Goodput goodput={goodput} />

          {activity ? (
            <>
              <HoldReasons activity={activity} />
              <RecentActivity activity={activity} />
            </>
          ) : (
            panelsLoading && (
              <p className="text-sm text-gray-400">Loading recent activity...</p>
            )
          )}

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
