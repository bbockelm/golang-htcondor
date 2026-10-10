'use client';

// How well a user's finished jobs used what they reserved, and what to
// request next time. The panels live in components/UtilizationPanels.tsx
// and the charts in components/UtilizationCharts.tsx; this file owns the
// fetch and the URL.
//
// Everything the page shows is in the URL -- the window (?days=), the
// access point (?schedd=) and the workflow being looked at (?w=) -- so a
// link to "this workflow over the last 30 days" can be sent to someone.
// The workflow is a query parameter rather than a path segment because
// the app is a static export, where a dynamic route needs a page per
// value at build time.

import { useCallback, useMemo } from 'react';
import { keepPreviousData, useQuery } from '@tanstack/react-query';
import Link from 'next/link';
import { useRouter, useSearchParams } from 'next/navigation';
import { api } from '@/lib/api';
import { useMultiAP } from '@/lib/multiap';
import { ScheddFilter } from '@/components/ScheddFilter';
import { ScopeToggle, useScope } from '@/components/ScopeToggle';
import { parseDays, windowPhrase, type UtilDays } from '@/lib/utilization';
import {
  EmptyState,
  Headline,
  Suggestions,
  TruncatedNotice,
  WindowToggle,
  WorkflowDetail,
  WorkflowsTable,
} from '@/components/UtilizationPanels';

export default function UtilizationPage() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const days = parseDays(searchParams.get('days'));
  const workflowKey = searchParams.get('w') ?? '';
  const schedd = searchParams.get('schedd') ?? '';

  const { data: session } = useQuery({ queryKey: ['session'], queryFn: api.auth.me });
  const isAdmin = !!session?.is_admin;
  const isLead = (session?.project_lead_of?.length ?? 0) > 0;
  const multiAP = useMultiAP();
  const [scope] = useScope();
  // The stored scope is shared with /jobs and /archive and outlives a
  // session's privileges; only a session that can see other people's jobs
  // gets a pool-wide title and question.
  const canWiden = (isAdmin || isLead) && !multiAP;
  const ownedByMe = scope === 'mine' || !canWiden;

  // hrefFor builds a link that keeps the other parameters, so moving
  // between workflows does not reset the window.
  const hrefFor = useCallback(
    (over: { days?: UtilDays; w?: string; schedd?: string }) => {
      const qs = new URLSearchParams();
      const d = over.days ?? days;
      if (d !== 7) qs.set('days', String(d));
      const s = over.schedd ?? schedd;
      if (s) qs.set('schedd', s);
      const w = over.w ?? workflowKey;
      if (w) qs.set('w', w);
      const q = qs.toString();
      return `/utilization${q ? `?${q}` : ''}`;
    },
    [days, schedd, workflowKey],
  );
  const workflowHref = useCallback((key: string) => hrefFor({ w: key }), [hrefFor]);

  const { data, error, isLoading, isFetching } = useQuery({
    queryKey: ['utilization', days, ownedByMe, multiAP, schedd],
    queryFn: () =>
      api.utilization({
        days,
        owned_by_me: ownedByMe,
        schedd: multiAP && schedd ? schedd : undefined,
      }),
    // Switching the window keeps the previous answer on screen, dimmed,
    // rather than blanking the page while the new one loads.
    // Wait for the session: until it arrives every session looks
    // unprivileged, and an admin would pay for a "mine" answer first.
    enabled: session !== undefined,
    placeholderData: keepPreviousData,
    staleTime: 60_000,
  });

  const workflow = useMemo(
    () => (workflowKey ? data?.workflows.find((w) => w.key === workflowKey) : undefined),
    [data, workflowKey],
  );

  const title = ownedByMe
    ? 'Utilization'
    : isAdmin || !isLead
      ? 'Utilization: everyone'
      : 'Utilization: you and your projects';

  return (
    <div className="space-y-6">
      <div className="space-y-3">
        <div className="flex flex-wrap items-baseline gap-3">
          <h1 className="text-2xl font-bold text-gray-900">{title}</h1>
          {canWiden && <ScopeToggle />}
        </div>
        <p className="text-sm text-gray-500">
          How much of the CPU, memory and disk {ownedByMe ? 'your' : 'these'} finished jobs reserved they actually used,
          and what to request next time.
        </p>
        <div className="flex flex-wrap items-center gap-3">
          <WindowToggle value={days} onChange={(d) => router.replace(hrefFor({ days: d }), { scroll: false })} />
          {multiAP && (
            <ScheddFilter value={schedd} onChange={(s) => router.replace(hrefFor({ schedd: s }), { scroll: false })} />
          )}
          {isFetching && !isLoading && <span className="text-xs text-gray-400">Updating…</span>}
        </div>
      </div>

      {isLoading && <p className="text-gray-400">Loading…</p>}

      {error && !data && (
        <p className="rounded-sm border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">
          Could not load utilization: {error.message}
        </p>
      )}

      {data && (
        <div className={`space-y-8 transition-opacity ${isFetching ? 'opacity-60' : ''}`} aria-busy={isFetching}>
          <TruncatedNotice data={data} />
          {data.jobs_considered === 0 ? (
            <EmptyState days={days} />
          ) : workflowKey ? (
            workflow ? (
              <WorkflowDetail workflow={workflow} days={days} backHref={hrefFor({ w: '' })} />
            ) : (
              <div className="space-y-2">
                <Link href={hrefFor({ w: '' })} className="text-sm text-brand-700 hover:underline">
                  ← All workflows
                </Link>
                <p className="text-sm text-gray-600">
                  This workflow has no jobs that finished in {windowPhrase(days)}.
                </p>
              </div>
            )
          ) : (
            <>
              <Headline overall={data.overall} mine={ownedByMe} />
              <Suggestions workflows={data.workflows} hrefFor={workflowHref} />
              <WorkflowsTable
                workflows={data.workflows}
                hrefFor={workflowHref}
                onOpen={(key) => router.push(workflowHref(key))}
              />
            </>
          )}
        </div>
      )}
    </div>
  );
}
