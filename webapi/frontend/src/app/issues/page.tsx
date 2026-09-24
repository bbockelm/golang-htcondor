'use client';

// /issues is the facilitator's page: what is going wrong on this access
// point, ranked, rather than a queue to read.
//
// The rows are clusters of hold reasons and run failures, grouped by the
// server (see webapi/issues). What the page adds is the reading order --
// biggest first, with the size of each problem visible at a glance, the
// number of DISTINCT USERS beside it, and one representative case
// expanded far enough to recognise without clicking.
//
// The three controls are all sticky, because they describe how somebody
// works rather than what they are looking at this minute: the window,
// the granularity, and whether to read run-attempt history.

import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import Link from 'next/link';
import { api, ApiError, type IssuesResponse } from '@/lib/api';
import { IssueSectionPanel } from '@/components/IssueSection';
import { ScopeToggle, useScope } from '@/components/ScopeToggle';
import {
  ISSUE_WINDOWS,
  useIssueGranularity,
  useIssueIncludeEnded,
  useIssueWindow,
} from '@/lib/issuePrefs';

// The page polls: an access point in trouble is one somebody is watching.
const REFRESH_MS = 60_000;

export default function IssuesPage() {
  const { data: session } = useQuery({
    queryKey: ['session'],
    queryFn: api.auth.me,
  });
  const isAdmin = !!session?.is_admin;

  const [scope] = useScope();
  const ownedByMe = scope === 'mine';

  const [windowSeconds, setWindowSeconds] = useIssueWindow();
  const [granularity, setGranularity] = useIssueGranularity();
  const [includeEnded, setIncludeEnded] = useIssueIncludeEnded();

  const { data, isLoading, isFetching, error } = useQuery<IssuesResponse, Error>({
    queryKey: ['issues', scope, windowSeconds, granularity, includeEnded],
    queryFn: () =>
      api.issues({
        window_seconds: windowSeconds,
        granularity,
        include_ended: includeEnded,
        owned_by_me: ownedByMe,
      }),
    refetchInterval: REFRESH_MS,
    // Moving the slider should redraw rather than blank the page: the
    // server re-clusters records it already has, so the answer is
    // milliseconds away and a spinner in between is just a flicker.
    placeholderData: (prev) => prev,
    retry: false,
  });

  const nothingWrong =
    !!data && data.sections.every((s) => s.clusters.length === 0);

  return (
    <div className="space-y-4">
      <div className="flex items-baseline gap-3 flex-wrap">
        <h1 className="text-2xl font-bold text-gray-900">
          {ownedByMe ? 'My Issues' : 'Issues'}
        </h1>
        <span className="text-sm text-gray-500">
          The most common problems, grouped.
        </span>
        {isAdmin && <ScopeToggle />}
        {isFetching && !isLoading && (
          <span className="text-xs text-gray-400">refreshing…</span>
        )}
      </div>

      <Controls
        windowSeconds={windowSeconds}
        onWindow={setWindowSeconds}
        granularity={granularity}
        onGranularity={setGranularity}
        includeEnded={includeEnded}
        onIncludeEnded={setIncludeEnded}
      />

      {error && (
        <p className="rounded-sm border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">
          Could not work out what is going wrong:{' '}
          {error instanceof ApiError ? error.message : String(error)}
        </p>
      )}

      {data?.notes?.map((note) => (
        <p
          key={note}
          className="rounded-sm border border-amber-200 bg-amber-50 px-3 py-2 text-sm text-amber-900"
        >
          {note}
        </p>
      ))}

      {data?.truncated && (
        <p className="rounded-sm border border-amber-200 bg-amber-50 px-3 py-2 text-sm text-amber-900">
          There was more than this page reads in one go, so these counts are a
          floor rather than a total. Narrow the window to see the rest in
          proportion.
        </p>
      )}

      {isLoading && <p className="text-sm text-gray-400">Looking…</p>}

      {nothingWrong && (
        <p className="rounded-lg border border-gray-200 bg-white p-4 text-sm text-gray-600">
          Nothing held and no failed run attempts in this window.
        </p>
      )}

      {data?.sections.map((section) => (
        <IssueSectionPanel key={section.kind} section={section} />
      ))}

      {data && (
        <p className="text-xs text-gray-400">
          {data.source ? `Read from the ${data.source}. ` : ''}
          Problems are grouped by what their messages have in common, not by
          hold code: one cause produces thousands of distinct messages, and a
          dozen codes cover everything that can go wrong.
        </p>
      )}
    </div>
  );
}

function Controls({
  windowSeconds,
  onWindow,
  granularity,
  onGranularity,
  includeEnded,
  onIncludeEnded,
}: {
  windowSeconds: number;
  onWindow: (v: number) => void;
  granularity: number;
  onGranularity: (v: number) => void;
  includeEnded: boolean;
  onIncludeEnded: (v: boolean) => void;
}) {
  return (
    <div className="flex flex-wrap items-center gap-x-6 gap-y-3 rounded-lg border border-gray-200 bg-white px-3 py-2">
      <div className="flex items-center gap-2">
        <span className="text-xs uppercase tracking-wide text-gray-500">
          Last
        </span>
        <div className="inline-flex overflow-hidden rounded-sm border border-gray-300">
          {ISSUE_WINDOWS.map((w) => (
            <button
              key={w.seconds}
              type="button"
              onClick={() => onWindow(w.seconds)}
              aria-pressed={windowSeconds === w.seconds}
              className={`px-3 py-1 text-sm ${
                windowSeconds === w.seconds
                  ? 'bg-brand-600 text-white'
                  : 'bg-white text-gray-600 hover:bg-gray-50'
              }`}
            >
              {w.label}
            </button>
          ))}
        </div>
      </div>

      <label className="flex items-center gap-2">
        <span className="text-xs uppercase tracking-wide text-gray-500">
          Detail
        </span>
        <span className="text-[11px] text-gray-400">fewer, broader</span>
        <input
          type="range"
          min={0}
          max={1}
          step={0.05}
          value={granularity}
          onChange={(e) => onGranularity(Number(e.target.value))}
          className="w-40 accent-brand-600"
          aria-label="Cluster granularity"
        />
        <span className="text-[11px] text-gray-400">more, narrower</span>
      </label>

      <label className="flex items-center gap-2 text-sm text-gray-700">
        <input
          type="checkbox"
          checked={includeEnded}
          onChange={(e) => onIncludeEnded(e.target.checked)}
          className="accent-brand-600"
        />
        {/* The distinction the facilitators asked about: a job that was
            held and released, or one that failed to start and was
            retried, is invisible in the queue minutes later. */}
        Include problems that have already ended
      </label>
    </div>
  );
}
