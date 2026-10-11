'use client';

// How well a user's finished jobs used what they reserved, and what to
// request next time. The panels live in components/UtilizationPanels.tsx
// and the charts in components/UtilizationCharts.tsx; this file owns the
// fetch and the URL.
//
// Everything the page shows is in the URL -- the window (?days=), the
// access point (?schedd=), the workflow being looked at (?w=), the
// filters (?q=, ?constraint=, ?owners=) and a bigger analysis (?limit=)
// -- so a link to "Bob's GPU jobs over the last 30 days" can be sent to
// someone. The workflow is a query parameter rather than a path segment
// because the app is a static export, where a dynamic route needs a page
// per value at build time.

import { useState } from 'react';
import { keepPreviousData, useQuery } from '@tanstack/react-query';
import Link from 'next/link';
import { useRouter, useSearchParams } from 'next/navigation';
import { api, ApiError } from '@/lib/api';
import { useMultiAP } from '@/lib/multiap';
import { ScheddFilter } from '@/components/ScheddFilter';
import { ScopeToggle, useScope } from '@/components/ScopeToggle';
import { FilterControls, type FilterMode } from '@/components/FilterControls';
import {
  filterWorkflows,
  parseDays,
  parseLimit,
  parseOwners,
  windowPhrase,
  type UtilDays,
} from '@/lib/utilization';
import {
  EmptyState,
  Headline,
  OwnerFilter,
  Suggestions,
  TruncatedNotice,
  WindowToggle,
  WorkflowDetail,
  WorkflowsTable,
} from '@/components/UtilizationPanels';

interface UrlState {
  days: UtilDays;
  w: string;
  schedd: string;
  q: string;
  constraint: string;
  owners: string[];
  limit: number | undefined;
}

export default function UtilizationPage() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const url: UrlState = {
    days: parseDays(searchParams.get('days')),
    w: searchParams.get('w') ?? '',
    schedd: searchParams.get('schedd') ?? '',
    q: searchParams.get('q') ?? '',
    constraint: searchParams.get('constraint') ?? '',
    owners: parseOwners(searchParams.get('owners')),
    limit: parseLimit(searchParams.get('limit')),
  };
  const { days, w: workflowKey, schedd, constraint, limit } = url;

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
  // Narrowing to users only means something when the answer has others.
  const owners = ownedByMe ? [] : url.owners;

  // hrefFor builds a link that keeps every other parameter, so moving
  // between workflows or filters does not reset the rest.
  const hrefFor = (over: Partial<UrlState>) => {
    const next = { ...url, ...over };
    const qs = new URLSearchParams();
    if (next.days !== 7) qs.set('days', String(next.days));
    if (next.schedd) qs.set('schedd', next.schedd);
    if (next.q) qs.set('q', next.q);
    if (next.constraint) qs.set('constraint', next.constraint);
    if (next.owners.length) qs.set('owners', next.owners.join(','));
    if (next.limit !== undefined) qs.set('limit', String(next.limit));
    if (next.w) qs.set('w', next.w);
    const q = qs.toString();
    return `/utilization${q ? `?${q}` : ''}`;
  };
  const workflowHref = (key: string) => hrefFor({ w: key });
  const replace = (over: Partial<UrlState>) => router.replace(hrefFor(over), { scroll: false });

  // The filter inputs. Text applies as it is typed and lives in the URL as
  // it changes; an expression applies on submit, the way /jobs does it.
  const [mode, setMode] = useState<FilterMode>(constraint ? 'expr' : 'text');
  const [text, setText] = useState(url.q);
  const [exprInput, setExprInput] = useState(constraint);
  // A constraint that arrives in the URL from elsewhere -- /jobs links
  // here with a batch's constraint, or the back button restores one --
  // shows in the box it applies through. Compared during render, so the
  // box never paints a frame showing the old expression.
  const [seenConstraint, setSeenConstraint] = useState(constraint);
  if (seenConstraint !== constraint) {
    setSeenConstraint(constraint);
    setExprInput(constraint);
    if (constraint) setMode('expr');
  }
  const [seenQ, setSeenQ] = useState(url.q);
  if (seenQ !== url.q) {
    setSeenQ(url.q);
    setText(url.q);
  }

  const queryFor = (ownersParam: string[]) => ({
    queryKey: ['utilization', days, ownedByMe, multiAP, schedd, constraint, ownersParam.join(','), limit ?? null],
    queryFn: () =>
      api.utilization({
        days,
        owned_by_me: ownedByMe,
        schedd: multiAP && schedd ? schedd : undefined,
        constraint: constraint || undefined,
        owners: ownersParam,
        limit,
      }),
  });

  const { data, error, isLoading, isFetching, isPlaceholderData } = useQuery({
    ...queryFor(owners),
    // Changing the window or a filter keeps the previous answer on
    // screen, dimmed, rather than blanking the page while the new one
    // loads -- which matters most for a bigger analysis, which is slower.
    // Wait for the session: until it arrives every session looks
    // unprivileged, and an admin would pay for a "mine" answer first.
    enabled: session !== undefined,
    placeholderData: keepPreviousData,
    staleTime: 60_000,
  });

  // The user list comes from the answer without the user filter: the
  // filtered one only lists the users already chosen. Usually it is in
  // the cache already, from before the first user was picked.
  const { data: unfiltered } = useQuery({
    ...queryFor([]),
    enabled: session !== undefined && !ownedByMe && owners.length > 0,
    staleTime: 60_000,
  });
  const ownerOptions = (owners.length > 0 ? unfiltered?.owners : data?.owners) ?? [];

  // A rejected expression is a typo, not an outage: reported next to the
  // input rather than as "could not load".
  const exprError = constraint && error instanceof ApiError && error.status === 400 ? error.message : null;

  const shownWorkflows = filterWorkflows(data?.workflows ?? [], url.q);
  const shownKeys = url.q ? new Set(shownWorkflows.map((w) => w.key)) : undefined;

  // The parameters of the analysis, which the workflow's detail, its job
  // list and an apply must all repeat to be about the same jobs.
  const analysis = {
    days,
    owned_by_me: ownedByMe,
    schedd: multiAP && schedd ? schedd : undefined,
    constraint: constraint || undefined,
    owners,
    limit,
  };
  // The list carries summaries; a workflow's histograms, advice text and
  // throughput come from its own endpoint when it is opened.
  const detail = useQuery({
    queryKey: ['utilization-workflow', workflowKey, days, ownedByMe, multiAP, schedd, constraint, owners.join(','), limit ?? null],
    queryFn: () => api.utilizationWorkflow({ w: workflowKey, ...analysis }),
    enabled: session !== undefined && !!workflowKey,
    staleTime: 60_000,
    retry: (n, e) => !(e instanceof ApiError && e.status === 404) && n < 1,
  });
  const detailMissing = detail.error instanceof ApiError && detail.error.status === 404;

  const addOwner = (o: string) => {
    if (!owners.includes(o)) replace({ owners: [...owners, o] });
  };

  const title = ownedByMe
    ? 'Utilization'
    : isAdmin || !isLead
      ? 'Utilization: everyone'
      : 'Utilization: you and your projects';

  const busy = isFetching && (isPlaceholderData || isLoading);

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
          <WindowToggle value={days} onChange={(d) => replace({ days: d })} />
          {multiAP && <ScheddFilter value={schedd} onChange={(s) => replace({ schedd: s })} />}
          {!ownedByMe && (
            <OwnerFilter options={ownerOptions} selected={owners} onChange={(o) => replace({ owners: o })} />
          )}
        </div>
        {!workflowKey && (
          <FilterControls
            mode={mode}
            input={mode === 'text' ? text : exprInput}
            onMode={(m) => {
              setMode(m);
              // Switching away from a mode stops applying it.
              if (m === 'text' && constraint) replace({ constraint: '' });
              if (m === 'expr' && url.q) replace({ q: '' });
            }}
            onInput={(v) => {
              if (mode === 'text') {
                setText(v);
                replace({ q: v });
              } else {
                setExprInput(v);
              }
            }}
            onApplyExpr={() => replace({ constraint: exprInput.trim() })}
            textPlaceholder="Filter workflows by name, executable, user or access point…"
            exprPlaceholder={'ClassAd, e.g. RequestGpus > 0 && JobBatchName == "train"'}
          />
        )}
        {exprError && (
          <p className="rounded-sm border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700" role="alert">
            {exprError}
          </p>
        )}
        {busy && (
          <p className="flex items-center gap-2 text-sm text-gray-600" role="status" data-testid="util-loading">
            <span
              aria-hidden
              className="inline-block h-3.5 w-3.5 animate-spin rounded-full border-2 border-gray-300 border-t-brand-600"
            />
            {limit ? `Analyzing up to ${limit.toLocaleString()} jobs…` : 'Loading…'}
          </p>
        )}
      </div>

      {error && !data && !exprError && (
        <p className="rounded-sm border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">
          Could not load utilization: {error.message}
        </p>
      )}

      {data && !exprError && (
        <div className={`space-y-8 transition-opacity ${busy ? 'opacity-50' : ''}`} aria-busy={busy}>
          <TruncatedNotice data={data} requested={limit} onLimit={(l) => replace({ limit: l })} />
          {data.jobs_considered === 0 ? (
            <EmptyState days={days} />
          ) : workflowKey ? (
            detail.data ? (
              <WorkflowDetail
                workflow={detail.data.workflow}
                days={days}
                backHref={hrefFor({ w: '' })}
                jobsQuery={analysis}
                waitingJobs={detail.data.waiting_jobs}
              />
            ) : detail.isLoading ? (
              <p className="text-sm text-gray-400">Loading the workflow…</p>
            ) : detail.error && !detailMissing ? (
              <p className="rounded-sm border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">
                Could not load the workflow: {detail.error.message}
              </p>
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
              <Suggestions suggestions={data.suggestions} keys={shownKeys} hrefFor={workflowHref} />
              <WorkflowsTable
                workflows={shownWorkflows}
                hrefFor={workflowHref}
                onOpen={(key) => router.push(workflowHref(key))}
                onOwner={ownedByMe ? undefined : addOwner}
              />
              {url.q && (
                <p className="text-xs text-gray-500">
                  {shownWorkflows.length.toLocaleString()} of {data.workflows.length.toLocaleString()} workflows match “
                  {url.q}”. The figures above cover all of them.
                </p>
              )}
            </>
          )}
        </div>
      )}
    </div>
  );
}
