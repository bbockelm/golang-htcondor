'use client';

import { useEffect, useState } from 'react';
import {
  api,
  ApiError,
  type DisplayStatus,
  type MatchAnalysisResponse,
  type MatchAnalysisPredicate,
  type MatchAnalysisAttributeDistribution,
} from '@/lib/api';

// MIN_AGE_FOR_ANALYSIS_SECONDS is the recommended minimum job age before
// running the analyzer. Below this, "the job hasn't started yet" is
// the boring most-likely answer — startup time (collector advertise
// cycle, schedd negotiator pass, image pull on the worker) routinely
// takes 30–60 seconds even on healthy pools. We don't HARD-block the
// run button at this age; we just surface a banner explaining the
// likely cause so impatient users don't burn an expensive collector
// query before HTCondor has had a chance to do its thing.
const MIN_AGE_FOR_ANALYSIS_SECONDS = 60;

// statusAllowsAnalysis identifies the job states where running the
// analyzer is informative. Only "idle" (waiting to be matched) and
// "held" (waiting for operator action) yield useful insight: the
// analyzer answers "why isn't this matching slots?", and that's
// exactly the question for those states.
//
// "uploading" (spool-input hold) is treated as not-analyzable — at
// this point the job is bottlenecked on the user's transfer, not on
// match-making. "running"/"transferring"/"completed"/"removed" are
// past the matching phase entirely.
function statusAllowsAnalysis(s: DisplayStatus | undefined): boolean {
  return s === 'idle' || s === 'held';
}

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
  /**
   * Current displayJobStatus.key value. The widget greys out the Run
   * button for any status other than 'idle' or 'held' — running an
   * expensive collector query for a job that's already running, or
   * removed, is wasted work. Pass undefined when the status is unknown
   * (e.g., still loading); the widget treats unknown as "allow" so
   * existing host pages without status plumbing keep working.
   */
  jobStatus?: DisplayStatus;
  /**
   * QDate from the job ad — Unix seconds when the job entered the queue.
   * If the job is younger than MIN_AGE_FOR_ANALYSIS_SECONDS, the
   * widget shows a banner suggesting the user wait a minute before
   * running the analysis. Most "stuck idle" reports for a 30-second-
   * old job are explained by routine HTCondor startup latency, not by
   * a real matching problem. Pass undefined when QDate isn't available.
   */
  jobQDate?: number;
}

export function MatchAnalysisPanel({
  jobID,
  title = 'Match Analysis',
  helperText,
  defaultOpen = true,
  jobStatus,
  jobQDate,
}: MatchAnalysisPanelProps) {
  // We deliberately don't use react-query for this — it would cache the
  // result and make it harder to surface the "you haven't run this yet"
  // state. Local state is cheap; this panel is its own scope.
  const [data, setData] = useState<MatchAnalysisResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Gating: button is disabled unless the job is in a state where
  // analysis is informative. Status undefined means "the host page
  // didn't pass us status info" — fall through to allow rather than
  // permanently disable, so older callers keep working.
  const stateAllows = jobStatus === undefined || statusAllowsAnalysis(jobStatus);

  // Young-job banner: shown for jobs less than a minute old. The
  // banner doesn't disable the button — sometimes operators DO want
  // to run the analysis on a fresh job — but it sets the expectation
  // so a "Run analysis" click on a 12-second-old job isn't taken as
  // "the system is broken" when it returns nothing surprising.
  // useNowTick at 5s is fine — we just need to flip the banner off
  // once the job clears the threshold; finer cadence wastes renders.
  const [now, setNow] = useState(() => Math.floor(Date.now() / 1000));
  useEffect(() => {
    if (jobQDate === undefined) return undefined;
    const ageNow = Math.floor(Date.now() / 1000) - jobQDate;
    if (ageNow >= MIN_AGE_FOR_ANALYSIS_SECONDS) return undefined;
    const id = setInterval(
      () => setNow(Math.floor(Date.now() / 1000)),
      5_000,
    );
    return () => clearInterval(id);
  }, [jobQDate]);
  const jobAgeSec = jobQDate === undefined ? undefined : now - jobQDate;
  const jobIsFresh =
    jobAgeSec !== undefined && jobAgeSec < MIN_AGE_FOR_ANALYSIS_SECONDS;

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

        {/* Young-job banner. Doesn't gate the button — operators may
            still want to run early — but explains that a "no obvious
            problem" result on a 12-second-old job is expected. */}
        {jobIsFresh ? (
          <div className="text-[11px] text-amber-800 border border-amber-200 bg-amber-50 rounded px-2 py-1.5">
            {/* "0s old" reads awkwardly the moment after submit;
                phrase the very-young case as "just submitted" and only
                quote the seconds once there's a meaningful number. */}
            {jobAgeSec !== undefined && jobAgeSec <= 1
              ? 'This job was just submitted.'
              : `This job is only ${jobAgeSec}s old.`}
            {' '}
            Some startup latency (collector advertise cycle, schedd
            negotiator pass, image pull) is normal — please give it at
            least a minute before running the analysis. Running it now
            is fine but may not yet reflect the steady-state matching
            picture.
          </div>
        ) : null}

        <div className="flex items-center gap-3 flex-wrap">
          <button
            type="button"
            onClick={run}
            disabled={loading || !stateAllows}
            title={
              !stateAllows
                ? `Match analysis is only useful for idle or held jobs (current state: ${jobStatus ?? 'unknown'}).`
                : undefined
            }
            className="rounded bg-blue-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-blue-700 disabled:bg-gray-400 disabled:cursor-not-allowed"
          >
            {loading
              ? 'Running…'
              : data
                ? 'Re-run analysis'
                : 'Run analysis'}
          </button>
          {!stateAllows ? (
            <span className="text-[11px] text-gray-500">
              Disabled — analysis is only informative when the job is
              idle or held (current: {jobStatus ?? 'unknown'}).
            </span>
          ) : null}
          {data && data.slot_cache?.age_seconds !== undefined ? (
            <span className="text-[11px] text-gray-500">
              Slot cache: {data.slot_cache.ad_count ?? 0} ads,{' '}
              {data.slot_cache.age_seconds}s old
              {data.slot_cache.all_attrs ? ' (all attrs)' : ''}
            </span>
          ) : null}
        </div>

        {/* Surface the projection actually requested from the
            collector. Helps an operator verify "did we ask for the
            attributes the predicate references?" — the most common
            cause of "but Arch is defined!" surprises is that we
            forgot to add it to the projection (then the slot ad
            comes back stripped and TARGET.Arch is absent). Wrapped
            in a <details> so it's there when needed but doesn't
            crowd the panel by default. */}
        {data?.slot_cache?.projection && data.slot_cache.projection.length > 0 ? (
          <details className="text-[11px]">
            <summary className="cursor-pointer text-gray-500 hover:text-gray-700">
              Slot projection ({data.slot_cache.projection.length} attrs)
            </summary>
            <code className="mt-1 block bg-gray-50 border border-gray-200 rounded px-2 py-1 text-gray-700 break-all">
              {data.slot_cache.projection.join(', ')}
            </code>
          </details>
        ) : null}

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

// VISIBLE_PREDICATE_COUNT is the number of "actually narrowing" predicates
// shown by default before the show-more gate. 3 is the sweet spot from
// condor_q -better-analyze convention: enough to see the top contributors
// without overwhelming the panel. Predicates beyond this — and any
// predicate with a narrowing score of 0 (no impact on matching) — go
// behind the show-more click. Pulled out as a constant so the choice
// is reviewable.
const VISIBLE_PREDICATE_COUNT = 3;

// Internal sub-component: renders the headline summary + per-predicate
// breakdown. Split out so the parent's loading/error/idle states stay
// focused on the wire interaction.
function MatchAnalysisBody({ data }: { data: MatchAnalysisResponse }) {
  const { result, requirements } = data;
  const [showAll, setShowAll] = useState(false);

  // Sort predicates by narrowing score descending (most impactful
  // first). Ties broken by original index for stability — a regression
  // in score computation would otherwise scramble the order on every
  // re-run. The narrowing predicate (server's choice) is the same as
  // the first sorted predicate when there's a unique narrower; when
  // there's a tie, both have the same score and the server arbitrates
  // by index, which we mirror here.
  const sorted = [...result.predicates].sort((a, b) => {
    if (a.narrowing_score !== b.narrowing_score) {
      return b.narrowing_score - a.narrowing_score;
    }
    return a.index - b.index;
  });

  // Default-visible predicates: top N with a non-zero score. Anything
  // past N, or with score 0, hides behind the show-more gate. The
  // operator can always reveal the rest. Score-0 predicates often
  // include `(TARGET.Arch isnt undefined)` — true on every slot in a
  // healthy pool — and crowding the panel with them obscures the
  // actually-narrowing predicates.
  const narrowingPreds = sorted.filter((p) => p.narrowing_score > 0);
  const visibleCount = Math.min(VISIBLE_PREDICATE_COUNT, narrowingPreds.length);
  const visiblePreds = showAll ? sorted : sorted.slice(0, visibleCount);
  const hiddenCount = sorted.length - visiblePreds.length;

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
        {narrowingPreds.length > 0 ? (
          <NarrowingHint predicate={narrowingPreds[0]} />
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
          Per-predicate breakdown{' '}
          <span className="font-normal text-gray-500">
            (sorted by narrowing impact)
          </span>
        </h4>
        <ul className="space-y-2">
          {visiblePreds.map((p) => (
            <PredicateRow
              key={p.index}
              predicate={p}
              isNarrowing={p.index === result.narrowing_predicate_index}
              totalSlots={result.total_slots}
            />
          ))}
        </ul>
        {hiddenCount > 0 ? (
          <button
            type="button"
            onClick={() => setShowAll(true)}
            className="mt-2 text-xs text-blue-700 hover:text-blue-900 hover:underline"
          >
            Show {hiddenCount} more predicate{hiddenCount === 1 ? '' : 's'}{' '}
            {narrowingPreds.length === 0
              ? '(none are narrowing)'
              : '(no narrowing impact)'}
          </button>
        ) : null}
        {showAll && sorted.length > visibleCount ? (
          <button
            type="button"
            onClick={() => setShowAll(false)}
            className="mt-2 ml-3 text-xs text-blue-700 hover:text-blue-900 hover:underline"
          >
            Collapse
          </button>
        ) : null}
      </div>
    </div>
  );
}

// NarrowingHint renders the "what to do about it" line under the
// headline summary. Two paths:
//
//  1. The narrowing predicate has a resource_suggestion — phrase the
//     hint as "lower RequestMemory from 8192 to N to unlock M slots".
//     This is what an operator can act on directly; auto-generated
//     predicates like `(TARGET.Memory >= RequestMemory)` are accurate
//     but most users don't know what to do with them.
//
//  2. No suggestion — fall back to the generic "removing this
//     predicate would gain N matches" form. Still useful for
//     non-resource predicates (e.g., `Arch == "Linux"`) where the
//     fix is "use a different OS" rather than "lower a number".
function NarrowingHint({
  predicate,
}: {
  predicate: MatchAnalysisPredicate;
}) {
  const sug = predicate.resource_suggestion;
  if (sug && sug.options.length > 0) {
    return (
      <div className="mt-1.5 text-xs text-gray-700 space-y-1">
        <div>
          <span className="font-medium text-amber-800">
            Try lowering {sug.job_attribute}
            {sug.current_value ? ` (currently ${sug.current_value})` : ''}:
          </span>
        </div>
        <ul className="ml-4 space-y-0.5">
          {sug.options.map((opt) => (
            <li key={opt.new_value}>
              <span className="text-gray-700">
                Set <code className="text-[11px] bg-white border border-gray-300 px-1 py-0.5 rounded">{sug.job_attribute} = {opt.new_value}</code>
              </span>{' '}
              <span className="text-emerald-800">
                → unlocks{' '}
                <span className="font-semibold">
                  {opt.additional_matches.toLocaleString()}
                </span>{' '}
                more slot
                {opt.additional_matches === 1 ? '' : 's'} for this requirement
              </span>
            </li>
          ))}
        </ul>
        <div className="text-gray-500 text-[11px]">
          (The narrowing predicate{' '}
          <code className="text-[11px] bg-white border border-gray-300 px-0.5 rounded">
            {predicate.source}
          </code>{' '}
          compares this slot attribute against the job&apos;s request.)
        </div>
      </div>
    );
  }
  return (
    <div className="mt-1.5 text-xs text-gray-700">
      <span className="font-medium text-amber-800">
        Narrowing predicate:
      </span>{' '}
      <code className="text-[11px] bg-white border border-gray-300 px-1 py-0.5 rounded">
        {predicate.source}
      </code>
      <span className="text-gray-500">
        {' '}— removing this predicate would gain{' '}
        {predicate.narrowing_score.toLocaleString()} more match
        {predicate.narrowing_score === 1 ? '' : 'es'}.
      </span>
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
            <summary className="cursor-pointer text-[11px] text-emerald-700 hover:text-emerald-900">
              Sample matching slots ({predicate.sample_matched_hosts.length})
            </summary>
            <ul className="mt-1 ml-4 text-[11px] text-gray-700 font-mono">
              {predicate.sample_matched_hosts.map((h) => (
                <li key={h}>{h}</li>
              ))}
            </ul>
          </details>
        )}

      {predicate.sample_not_matched_hosts &&
        predicate.sample_not_matched_hosts.length > 0 && (
          <details className="mt-1.5">
            <summary className="cursor-pointer text-[11px] text-rose-700 hover:text-rose-900">
              Sample non-matching slots (
              {predicate.sample_not_matched_hosts.length})
            </summary>
            <ul className="mt-1 ml-4 text-[11px] text-gray-700 font-mono">
              {predicate.sample_not_matched_hosts.map((h) => (
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
    (dist.absent ?? 0) +
    (dist.undefined ?? 0) +
    (dist.error ?? 0);
  const denom = Math.max(total, 1);
  // 100% absent for an attribute we explicitly projected is a smoking
  // gun: either the collector isn't honoring the projection request
  // (server-side filter bug, schema mismatch, etc.) or the slots in
  // this pool genuinely don't publish the attribute. Either way the
  // operator wants to know — flag it loudly so they don't blame the
  // analyzer for a "slot has Arch but predicate says undefined" case
  // that's actually upstream.
  const allAbsent = total > 0 && (dist.absent ?? 0) === total;
  // Each distribution row is laid out as a 4-column grid:
  // [value | bar | count | example slot]. Putting the example in its
  // own column (rather than tucked under the value) makes it easy to
  // scan: "which slot has Memory=2048?" → eye to that row's last column.
  return (
    <div className="text-[11px]">
      <div className="text-gray-700 font-medium">
        {dist.attribute}
        {allAbsent ? (
          <span
            className="ml-2 text-[10px] text-rose-700 font-normal"
            title={`Every slot's ad lacks "${dist.attribute}" entirely. If the slots actually publish this attribute, the collector may not be honoring the projection request — verify the slot projection list above includes "${dist.attribute}".`}
          >
            ⚠ absent on every slot
          </span>
        ) : null}
      </div>
      <div className="mt-0.5 ml-3 grid grid-cols-[minmax(0,1fr)_minmax(4rem,3fr)_auto_minmax(0,2fr)] gap-x-2 gap-y-0.5 items-center">
        {dist.values.map((v) => (
          <DistRow
            key={v.value}
            label={v.value}
            labelClass="font-mono text-gray-700 truncate"
            barClass="bg-blue-400"
            count={v.count}
            denom={denom}
            example={v.example}
          />
        ))}
        {/* "absent" and "undefined" are deliberately separate rows. An
            operator looking at "(TARGET.Arch isnt undefined)" reporting
            non-matches needs to know whether slots aren't publishing
            Arch at all (absent) or are publishing it bound to something
            that resolves to undefined (undefined) — different problems
            with different fixes. */}
        {dist.absent ? (
          <DistRow
            label="absent"
            labelClass="font-mono italic text-gray-500"
            labelTitle="Attribute not present in the slot ad"
            barClass="bg-gray-400"
            count={dist.absent}
            denom={denom}
            example={dist.absent_example}
          />
        ) : null}
        {dist.undefined ? (
          <DistRow
            label="undefined"
            labelClass="font-mono italic text-gray-500"
            labelTitle="Attribute is in the slot ad but its value evaluates to undefined"
            barClass="bg-gray-300"
            count={dist.undefined}
            denom={denom}
            example={dist.undefined_example}
          />
        ) : null}
        {dist.error ? (
          <DistRow
            label="error"
            labelClass="font-mono italic text-orange-600"
            barClass="bg-orange-400"
            count={dist.error}
            denom={denom}
            example={dist.error_example}
          />
        ) : null}
      </div>
    </div>
  );
}

// DistRow is one row of the per-attribute distribution grid. Pulled
// out as a component so the four bucket types (values, absent,
// undefined, error) share the same column layout — operators expect
// the example slot to land in the same place regardless of bucket.
function DistRow({
  label,
  labelClass,
  labelTitle,
  barClass,
  count,
  denom,
  example,
}: {
  label: string;
  labelClass: string;
  labelTitle?: string;
  barClass: string;
  count: number;
  denom: number;
  example?: string;
}) {
  return (
    <>
      <span className={labelClass} title={labelTitle}>
        {label}
      </span>
      <div className="h-1 bg-gray-100 rounded overflow-hidden">
        <div
          className={`${barClass} h-full`}
          style={{ width: `${(count / denom) * 100}%` }}
        />
      </div>
      <span className="text-gray-600 tabular-nums">{count}</span>
      <span
        className="font-mono text-gray-500 text-[10px] truncate"
        title={example ? `Example slot: ${example}` : ''}
      >
        {example ? `e.g. ${example}` : ''}
      </span>
    </>
  );
}
