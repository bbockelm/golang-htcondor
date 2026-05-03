'use client';

import { useState } from 'react';
import {
  api,
  ApiError,
  type MatchAnalysisResponse,
  type MatchAnalysisPredicate,
  type MatchAnalysisAttributeDistribution,
} from '@/lib/api';

// MatchAnalysisPanel renders a collapsible "why isn't my job matching?"
// view backed by /api/v1/jobs/{id}/match-analysis.
//
// Crucially, this component never auto-runs the analysis. The endpoint is
// expensive (per-call collector slot dump on first invocation, ~30s
// cache), so we gate it behind an explicit "Run analysis" button. Once
// the analysis has been run for a job, re-running is cheap (cache hit on
// the slot side) but the user still has to click — auto-refetch on
// invalidation would defeat the cost-control intent.
//
// The component is reusable: pass it a job ID and an optional title /
// helper text, and it slots into any host page. The Jupyter launcher
// uses it to debug "why hasn't my Jupyter job started?"; the job detail
// page exposes it directly. Add new hosts by importing this and passing
// the job ID — no other plumbing required.
export interface MatchAnalysisPanelProps {
  /** Job ID in the form "<cluster>.<proc>". */
  jobID: string;
  /** Heading shown at the top of the panel. */
  title?: string;
  /**
   * Helper text shown above the run button. Use this to explain *why*
   * an analysis is offered in this context — e.g., on the Jupyter
   * launcher, "If your session hasn't started, run this to see which
   * job requirement is excluding the most slots."
   */
  helperText?: string;
  /**
   * defaultOpen controls the initial collapsed state of the host
   * <details> wrapper. Defaults to true (open) so the run button is
   * visible without a click. The host page can still wrap us in a
   * collapsed shell if it wants to hide the panel until requested.
   */
  defaultOpen?: boolean;
}

export function MatchAnalysisPanel({
  jobID,
  title = 'Match Analysis',
  helperText,
  defaultOpen = true,
}: MatchAnalysisPanelProps) {
  // We deliberately don't use react-query for this — it would cache the
  // result and make it harder to surface the "you haven't run this yet"
  // state. Local state is cheap; this panel is its own scope.
  const [data, setData] = useState<MatchAnalysisResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function run() {
    setLoading(true);
    setError(null);
    try {
      const res = await api.jobs.matchAnalysis(jobID);
      setData(res);
    } catch (e) {
      if (e instanceof ApiError) {
        setError(`${e.status}: ${e.message}`);
      } else if (e instanceof Error) {
        setError(e.message);
      } else {
        setError(String(e));
      }
    } finally {
      setLoading(false);
    }
  }

  return (
    <details
      className="rounded border border-gray-200 bg-white"
      open={defaultOpen}
    >
      <summary className="cursor-pointer px-3 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50">
        {title}
      </summary>
      <div className="px-3 pb-3 pt-1 space-y-3">
        {helperText ? (
          <p className="text-xs text-gray-600">{helperText}</p>
        ) : (
          <p className="text-xs text-gray-600">
            Run a {' '}
            <code className="text-[11px] bg-gray-100 px-1 py-0.5 rounded">
              condor_q -better-analyze
            </code>
            -style breakdown of this job&apos;s requirements against the
            current slot pool. The collector query is cached for ~30
            seconds so re-running is cheap, but the first call can be
            heavy on large pools.
          </p>
        )}

        <div className="flex items-center gap-3">
          <button
            type="button"
            onClick={run}
            disabled={loading}
            className="rounded bg-blue-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-blue-700 disabled:bg-gray-400 disabled:cursor-not-allowed"
          >
            {loading
              ? 'Running…'
              : data
                ? 'Re-run analysis'
                : 'Run analysis'}
          </button>
          {data && data.slot_cache?.age_seconds !== undefined ? (
            <span className="text-[11px] text-gray-500">
              Slot cache: {data.slot_cache.ad_count ?? 0} ads,{' '}
              {data.slot_cache.age_seconds}s old
              {data.slot_cache.all_attrs ? ' (all attrs)' : ''}
            </span>
          ) : null}
        </div>

        {error ? (
          <div className="text-xs text-red-700 border border-red-200 bg-red-50 rounded px-3 py-2">
            {error}
          </div>
        ) : null}

        {data ? <MatchAnalysisBody data={data} /> : null}
      </div>
    </details>
  );
}

// Internal sub-component: renders the headline summary + per-predicate
// breakdown. Split out so the parent's loading/error/idle states stay
// focused on the wire interaction.
function MatchAnalysisBody({ data }: { data: MatchAnalysisResponse }) {
  const { result, requirements } = data;
  const narrowing =
    result.narrowing_predicate_index >= 0 &&
    result.narrowing_predicate_index < result.predicates.length
      ? result.predicates[result.narrowing_predicate_index]
      : null;

  return (
    <div className="space-y-3">
      <div className="rounded border border-gray-200 bg-gray-50 px-3 py-2">
        <div className="text-sm">
          <span className="font-semibold">{result.full_matches}</span>
          <span className="text-gray-600">
            {' '}
            of {result.total_slots.toLocaleString()} slots fully match all
            requirements.
          </span>
        </div>
        {narrowing ? (
          <div className="mt-1.5 text-xs text-gray-700">
            <span className="font-medium text-amber-800">
              Narrowing predicate:
            </span>{' '}
            <code className="text-[11px] bg-white border border-gray-300 px-1 py-0.5 rounded">
              {narrowing.source}
            </code>
            <span className="text-gray-500">
              {' '}— removing this predicate would gain the most matches.
            </span>
          </div>
        ) : result.full_matches < result.total_slots ? (
          <div className="mt-1.5 text-xs text-gray-600">
            No single predicate is uniquely responsible for narrowing —
            multiple predicates each fail on different slots.
          </div>
        ) : null}
      </div>

      {requirements ? (
        <details className="rounded border border-gray-200">
          <summary className="cursor-pointer px-3 py-1.5 text-xs font-medium text-gray-700 hover:bg-gray-50">
            Job Requirements expression
          </summary>
          <pre className="px-3 py-2 text-[11px] bg-gray-50 overflow-auto font-mono whitespace-pre-wrap break-all">
            {requirements}
          </pre>
        </details>
      ) : null}

      <div>
        <h4 className="text-xs font-semibold text-gray-700 mb-1.5">
          Per-predicate breakdown
        </h4>
        <ul className="space-y-2">
          {result.predicates.map((p) => (
            <PredicateRow
              key={p.index}
              predicate={p}
              isNarrowing={p.index === result.narrowing_predicate_index}
              totalSlots={result.total_slots}
            />
          ))}
        </ul>
      </div>
    </div>
  );
}

// PredicateRow is the per-predicate display: counts, a tiny stacked bar
// for matched/not-matched/undefined/error, sample matched hosts, and the
// per-attribute value distribution. Designed to be readable at a glance
// without scrolling — the dense info goes inside <details>.
function PredicateRow({
  predicate,
  isNarrowing,
  totalSlots,
}: {
  predicate: MatchAnalysisPredicate;
  isNarrowing: boolean;
  totalSlots: number;
}) {
  // Guard against divide-by-zero. If totalSlots is 0 the segments below
  // collapse to width:0 anyway, but the percentages would be NaN without
  // this. Use Math.max so we never hand a 0 to the divisor in any path.
  const denom = Math.max(totalSlots, 1);
  const matchedPct = (predicate.matched / denom) * 100;
  const notMatchedPct = (predicate.not_matched / denom) * 100;
  const undefinedPct = (predicate.undefined / denom) * 100;
  const errorPct = (predicate.error / denom) * 100;

  return (
    <li
      className={`rounded border px-3 py-2 ${
        isNarrowing
          ? 'border-amber-300 bg-amber-50'
          : 'border-gray-200 bg-white'
      }`}
    >
      <div className="flex items-baseline gap-2 flex-wrap">
        <span className="text-[11px] text-gray-500 font-mono">
          #{predicate.index}
        </span>
        <code className="text-[11px] bg-gray-100 px-1 py-0.5 rounded font-mono break-all">
          {predicate.source}
        </code>
        {isNarrowing ? (
          <span className="text-[10px] uppercase tracking-wide text-amber-800 font-semibold">
            narrowing
          </span>
        ) : null}
      </div>

      <div className="mt-1.5 flex items-center gap-2 text-[11px] text-gray-700">
        <span className="text-emerald-700">
          matched={predicate.matched}
        </span>
        <span className="text-rose-700">
          not_matched={predicate.not_matched}
        </span>
        {predicate.undefined > 0 && (
          <span className="text-gray-600">
            undefined={predicate.undefined}
          </span>
        )}
        {predicate.error > 0 && (
          <span className="text-orange-700">error={predicate.error}</span>
        )}
      </div>

      {/* Stacked horizontal bar for at-a-glance distribution. */}
      <div className="mt-1.5 h-1.5 w-full bg-gray-100 rounded overflow-hidden flex">
        <div
          className="bg-emerald-500"
          style={{ width: `${matchedPct}%` }}
          title={`matched: ${predicate.matched}`}
        />
        <div
          className="bg-rose-400"
          style={{ width: `${notMatchedPct}%` }}
          title={`not_matched: ${predicate.not_matched}`}
        />
        <div
          className="bg-gray-300"
          style={{ width: `${undefinedPct}%` }}
          title={`undefined: ${predicate.undefined}`}
        />
        <div
          className="bg-orange-400"
          style={{ width: `${errorPct}%` }}
          title={`error: ${predicate.error}`}
        />
      </div>

      {predicate.sample_matched_hosts &&
        predicate.sample_matched_hosts.length > 0 && (
          <details className="mt-1.5">
            <summary className="cursor-pointer text-[11px] text-gray-600 hover:text-gray-900">
              Sample matching slots ({predicate.sample_matched_hosts.length})
            </summary>
            <ul className="mt-1 ml-4 text-[11px] text-gray-700 font-mono">
              {predicate.sample_matched_hosts.map((h) => (
                <li key={h}>{h}</li>
              ))}
            </ul>
          </details>
        )}

      {predicate.attribute_distributions &&
        predicate.attribute_distributions.length > 0 && (
          <div className="mt-2 space-y-1.5">
            {predicate.attribute_distributions.map((d) => (
              <AttrDistribution key={d.attribute} dist={d} />
            ))}
          </div>
        )}
    </li>
  );
}

function AttrDistribution({
  dist,
}: {
  dist: MatchAnalysisAttributeDistribution;
}) {
  const total =
    (dist.values.reduce((s, v) => s + v.count, 0) ?? 0) +
    (dist.undefined ?? 0) +
    (dist.error ?? 0);
  const denom = Math.max(total, 1);
  return (
    <div className="text-[11px]">
      <div className="text-gray-700 font-medium">{dist.attribute}</div>
      <ul className="mt-0.5 ml-3 space-y-0.5">
        {dist.values.map((v) => (
          <li key={v.value} className="flex items-center gap-2">
            <span className="font-mono text-gray-700 truncate max-w-[16rem]">
              {v.value}
            </span>
            <div className="flex-1 h-1 bg-gray-100 rounded overflow-hidden">
              <div
                className="bg-blue-400 h-full"
                style={{ width: `${(v.count / denom) * 100}%` }}
              />
            </div>
            <span className="text-gray-600 tabular-nums">{v.count}</span>
          </li>
        ))}
        {dist.undefined ? (
          <li className="flex items-center gap-2 text-gray-500">
            <span className="font-mono italic">undefined</span>
            <div className="flex-1 h-1 bg-gray-100 rounded overflow-hidden">
              <div
                className="bg-gray-300 h-full"
                style={{ width: `${(dist.undefined / denom) * 100}%` }}
              />
            </div>
            <span className="tabular-nums">{dist.undefined}</span>
          </li>
        ) : null}
        {dist.error ? (
          <li className="flex items-center gap-2 text-orange-600">
            <span className="font-mono italic">error</span>
            <div className="flex-1 h-1 bg-orange-100 rounded overflow-hidden">
              <div
                className="bg-orange-400 h-full"
                style={{ width: `${(dist.error / denom) * 100}%` }}
              />
            </div>
            <span className="tabular-nums">{dist.error}</span>
          </li>
        ) : null}
      </ul>
    </div>
  );
}
