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
// the granularity, and whether to read run-attempt history. The
// expression filter is not: it is a question about some jobs, asked now.
//
// The chat panel is wired up the way /archive's is, with a server-side
// analyze_issues tool that reads the same answer this page shows and a
// set_constraint hook that applies an expression here.

import { useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import Link from 'next/link';
import { api, ApiError, type IssueTimings, type IssuesResponse } from '@/lib/api';
import { IssueSectionPanel } from '@/components/IssueSection';
import { ChatPanel, type ToolHandler } from '@/components/ChatPanel';
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
  // The expression filter: the box's text, and what was applied.
  const [exprInput, setExprInput] = useState('');
  const [constraint, setConstraint] = useState('');

  const { data, isLoading, isFetching, error } = useQuery<IssuesResponse, Error>({
    queryKey: ['issues', scope, windowSeconds, granularity, includeEnded, constraint],
    queryFn: () =>
      api.issues({
        window_seconds: windowSeconds,
        granularity,
        include_ended: includeEnded,
        owned_by_me: ownedByMe,
        constraint: constraint || undefined,
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

  // A rejected expression is a typo, not an outage: reported next to the
  // input rather than as "could not work out what is going wrong".
  const exprError =
    constraint && error instanceof ApiError && error.status === 400 ? error.message : null;

  const applyConstraint = (c: string) => {
    const v = c.trim();
    setExprInput(v);
    setConstraint(v);
  };

  const { data: chatInfo } = useQuery({
    queryKey: ['chat-info'],
    queryFn: api.chat.info,
    staleTime: Infinity,
    retry: false,
  });
  const chatVisible = !!chatInfo?.enabled;

  // === KEEP IN SYNC WITH webapi/httpserver/handlers_chat_tools.go (issuesPageInstructions) ===
  // The server's instructions tell the assistant what this page shows and
  // which of these hooks exist. Adding or removing a hook, a control or a
  // filter here means updating that text.
  const chatHooks = useMemo<Record<string, ToolHandler>>(
    () => ({
      set_constraint: (input) => {
        const c = typeof input.constraint === 'string' ? input.constraint.trim() : '';
        setExprInput(c);
        setConstraint(c);
        return { ok: true, applied_constraint: c };
      },
    }),
    [],
  );

  const pageContext = issuesChatContext({
    ownedByMe,
    windowSeconds,
    granularity,
    includeEnded,
    constraint,
    exprError,
    data,
    loading: isLoading,
  });

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

      <ChatPanel
        visible={chatVisible}
        page="issues"
        scope={ownedByMe ? 'mine' : 'everyone'}
        pageContext={pageContext}
        hooks={chatHooks}
        confirmableTools={[]}
        headerLabel="Issues assistant"
        togglerLabel="Ask about these problems"
        pageHelp={`Ask things like "what is the biggest problem right now?", "is this one user or a site?", or "show only jobs that asked for a GPU".`}
      />

      <Controls
        windowSeconds={windowSeconds}
        onWindow={setWindowSeconds}
        granularity={granularity}
        onGranularity={setGranularity}
        includeEnded={includeEnded}
        onIncludeEnded={setIncludeEnded}
      />

      <ExpressionFilter
        input={exprInput}
        onInput={setExprInput}
        applied={constraint}
        onApply={applyConstraint}
      />
      {exprError && (
        <p className="rounded-sm border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700" role="alert">
          {exprError}
        </p>
      )}

      {error && !exprError && (
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
          Nothing held and no failed run attempts in this window
          {constraint ? ' among jobs matching the expression' : ''}.
        </p>
      )}

      {data?.sections.map((section) => (
        <IssueSectionPanel
          key={section.kind}
          section={section}
          bucketSeconds={data.bucket_seconds}
          endsAt={data.computed_at}
        />
      ))}

      {data?.timings && <TimingLine timings={data.timings} />}

      {data && (
        <p className="text-xs text-gray-400">
          Problems are grouped by what their messages have in common, not by
          hold code: one cause produces thousands of distinct messages, and a
          dozen codes cover everything that can go wrong.
        </p>
      )}
    </div>
  );
}

// issuesChatContext tells the assistant what this page is showing: the
// settings it should repeat to analyze_issues, and the headline numbers
// so it can answer "why is this empty?" without a call.
function issuesChatContext({
  ownedByMe,
  windowSeconds,
  granularity,
  includeEnded,
  constraint,
  exprError,
  data,
  loading,
}: {
  ownedByMe: boolean;
  windowSeconds: number;
  granularity: number;
  includeEnded: boolean;
  constraint: string;
  exprError: string | null;
  data: IssuesResponse | undefined;
  loading: boolean;
}): string {
  const lines = [
    `View: ${ownedByMe ? 'My Issues' : "everyone's issues"}.`,
    `Window: last ${windowSeconds / 3600} hours (window_hours=${windowSeconds / 3600}).`,
    `Detail: ${granularity} (granularity=${granularity}).`,
    `Include problems that have already ended: ${includeEnded ? 'yes' : 'no'} (include_ended=${includeEnded}).`,
    constraint ? `Expression filter: ${constraint}` : 'Expression filter: none.',
  ];
  if (exprError) lines.push(`The expression was rejected: ${exprError}`);
  if (loading) lines.push('The page is still loading.');
  if (data) {
    if (data.sections.every((s) => s.clusters.length === 0)) {
      lines.push('The page shows nothing held and no failed run attempts.');
    }
    for (const s of data.sections) {
      const top = s.clusters
        .slice(0, 3)
        .map((c) => `${c.count} jobs/${c.users} users: ${(c.examples?.[0]?.message || c.template).slice(0, 120)}`)
        .join(' | ');
      lines.push(`${s.title}: ${s.total} jobs, ${s.users} users, ${s.clusters.length} problems. Largest: ${top}`);
    }
    if (data.truncated) lines.push('The read was truncated; counts are a floor.');
    for (const n of data.notes ?? []) lines.push(`Note shown: ${n}`);
  }
  return lines.join('\n');
}

// ExpressionFilter narrows the page to some jobs' problems. Applied on
// submit, like the other pages' expression filters: every half-typed
// expression is a syntax error or a different query.
function ExpressionFilter({
  input,
  onInput,
  applied,
  onApply,
}: {
  input: string;
  onInput: (v: string) => void;
  applied: string;
  onApply: (v: string) => void;
}) {
  return (
    <form
      className="flex flex-wrap items-center gap-2"
      onSubmit={(e) => {
        e.preventDefault();
        onApply(input);
      }}
    >
      <label htmlFor="issues-expr" className="text-xs uppercase tracking-wide text-gray-500">
        Only jobs matching
      </label>
      <input
        id="issues-expr"
        type="text"
        value={input}
        onChange={(e) => onInput(e.target.value)}
        placeholder={'ClassAd, e.g. RequestGPUs >= 1 && JobBatchName == "train"'}
        spellCheck={false}
        className="min-w-[20rem] flex-1 rounded-sm border border-gray-300 px-3 py-1.5 font-mono text-sm"
      />
      <button
        type="submit"
        className="rounded-sm bg-brand-600 px-4 py-1.5 text-sm font-medium text-white hover:bg-brand-700"
      >
        Apply
      </button>
      {applied && (
        <button
          type="button"
          onClick={() => onApply('')}
          className="rounded-sm border border-gray-300 bg-white px-3 py-1.5 text-sm text-gray-600 hover:bg-gray-50"
        >
          Clear
        </button>
      )}
    </form>
  );
}

// TimingLine says what the answer cost.
//
// On a page that reads the whole queue and an append-only archive, "why
// is this slow" is a question somebody will ask, and the person who can
// see the slowness is usually not the person who can read the server's
// log. Splitting it into the two reads and the grouping is what makes
// the answer actionable rather than a shrug.
function TimingLine({ timings }: { timings: IssueTimings }) {
  const parts = [
    `${timings.holds.toLocaleString()} held job${timings.holds === 1 ? '' : 's'} in ${secs(timings.holds_query_ms)}`,
  ];
  if (timings.run_attempts > 0 || timings.run_attempts_query_ms > 0) {
    parts.push(
      `${timings.run_attempts.toLocaleString()} run attempt${timings.run_attempts === 1 ? '' : 's'} in ${secs(timings.run_attempts_query_ms)}`,
    );
  }
  return (
    <p className="text-xs text-gray-400">
      Read {parts.join(' and ')}; grouped in {secs(timings.cluster_ms)}.
      {timings.cached
        ? ` Reads are reused for a minute — these are from ${secs((timings.age_seconds ?? 0) * 1000)} ago.`
        : ''}
    </p>
  );
}

function secs(ms: number): string {
  if (ms < 1000) return `${Math.round(ms)}ms`;
  return `${(ms / 1000).toFixed(1)}s`;
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
