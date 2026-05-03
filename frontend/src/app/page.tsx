'use client';

import { useQuery } from '@tanstack/react-query';
import Link from 'next/link';
import { api, JOB_STATUS_LABEL } from '@/lib/api';

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

  return <AuthenticatedDashboard username={session.username ?? ''} />;
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
        className="mt-6 inline-block rounded bg-brand-600 px-4 py-2 text-sm font-medium text-white hover:bg-brand-700"
      >
        Sign In
      </a>
    </div>
  );
}

function AuthenticatedDashboard({ username }: { username: string }) {
  const { data, isLoading, error } = useQuery({
    queryKey: ['dashboard'],
    queryFn: api.dashboard,
    refetchInterval: 15_000,
  });

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Dashboard</h1>
        <p className="text-sm text-gray-500">Signed in as {username}</p>
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

const STATUS_LABEL_BY_KEY: Record<string, string> = {
  idle: JOB_STATUS_LABEL[1],
  running: JOB_STATUS_LABEL[2],
  removed: JOB_STATUS_LABEL[3],
  completed: JOB_STATUS_LABEL[4],
  held: JOB_STATUS_LABEL[5],
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
      <div className="mt-1 text-2xl font-semibold text-gray-900">{value}</div>
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
            <span className="font-medium">{n}</span>
            {!known.has(key) && (
              <span className="ml-2 text-gray-400 text-xs">(unmapped)</span>
            )}
          </li>
        ))}
      </ul>
    </div>
  );
}
