'use client';

import { useQuery } from '@tanstack/react-query';
import Link from 'next/link';
import { api } from '@/lib/api';
import {
  Goodput,
  HoldReasons,
  LiveTicker,
  RecentActivity,
  StatusRow,
} from '@/components/DashboardPanels';
import { CalendarPanel } from '@/components/CalendarPanel';
import { CALENDAR_DAYS } from '@/lib/calendar';
import { useActivityStream } from '@/lib/useActivityStream';
import { ScopeToggle, useScope } from '@/components/ScopeToggle';
import { AccessPointsTable } from '@/components/AccessPointsTable';

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

  if (session.multi_ap) {
    return <MultiAPDashboard />;
  }

  return (
    <AuthenticatedDashboard
      username={session.username ?? ''}
      isAdmin={!!session.is_admin}
    />
  );
}

// MultiAPDashboard is the home page when this server fronts several
// access points: where your jobs are, and how current each one is.
function MultiAPDashboard() {
  return (
    <div className="space-y-4">
      <div className="flex items-baseline gap-3 flex-wrap">
        <h1 className="text-2xl font-bold text-gray-900">Dashboard</h1>
        <span className="text-sm text-gray-500">
          Your jobs on every access point.{' '}
          <Link href="/jobs" className="text-brand-700 hover:underline">
            Jobs
          </Link>{' '}
          ·{' '}
          <Link href="/archive" className="text-brand-700 hover:underline">
            Archive
          </Link>
        </span>
      </div>
      <AccessPointsTable />
    </div>
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

  // Two queries, not one, so the page paints in stages: the status row
  // is a single aggregate against the mirror and lands in a few
  // milliseconds, while the panels below cost a hold breakdown and four
  // windowed lookups. Combined, everything waited for the slowest of
  // those -- which is what made the page feel slow after the panels were
  // added.
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

  // The calendar is a third query: a quarter of per-day counts out of
  // the history mirror is the slowest thing on the page, and a day's
  // figures change about once a day, so it neither holds the panels
  // above it nor polls with them. The scope is in the key, as it is for
  // the others -- without it, switching to Everyone would redraw the
  // same person's calendar.
  const { data: calendar } = useQuery({
    queryKey: ['calendar', scope],
    queryFn: () => api.calendar({ days: CALENDAR_DAYS, owned_by_me: ownedByMe }),
    refetchInterval: 300_000,
    // A server that does not serve this will not serve it on the second
    // ask either, and the panel renders nothing where it cannot answer.
    retry: false,
  });

  // An older server still answers /dashboard with both halves; prefer
  // the dedicated response and fall back to what the counts carried.
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
          <StatusRow byStatus={data.jobs_by_status} total={data.jobs_total} />

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

          <CalendarPanel calendar={calendar} />

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
