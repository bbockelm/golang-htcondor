'use client';

// How long a waiting or running job is likely to take, on the job page:
// a card of its own under the summary.
//
// It renders nothing at all unless there is an estimate: no placeholder
// while the access point is still reading its history, nothing for a job
// with nothing comparable, nothing on a server without the feature. So
// where there is no answer the page looks exactly as it did.

import { useQuery } from '@tanstack/react-query';

import { RuntimeRangeBar } from '@/components/RuntimeRangeBar';
import { api, type RuntimeEstimate } from '@/lib/api';

import { runtimeCard } from './runtimeCard';

export { basisLine, rangeText } from './runtimeCard';

// RoughChip marks an estimate that is only a rough guess: a dashed
// outline, quieter than a status.
export function RoughChip() {
  return (
    <span className="ml-1.5 inline-flex whitespace-nowrap rounded-full border border-dashed border-gray-400 px-1.5 text-[10px] font-medium leading-4 text-gray-600 align-middle">
      rough guess
    </span>
  );
}

// The page's own ways to look inside a running job, offered when the job
// has run longer than usual. Each is absent when the page has no such
// action for this job.
export interface RuntimeEstimateActions {
  onViewOutput?: () => void;
  onOpenShell?: () => void;
  // Opens the list of the jobs the estimate is based on.
  onShowSimilar?: () => void;
}

const actionCls =
  'rounded-sm border border-gray-300 bg-white px-3 py-1.5 text-sm font-medium text-gray-700 hover:bg-gray-50';

// RuntimeEstimateView is the card for one estimate. fetchedAt is when the
// estimate was read, in unix seconds.
export function RuntimeEstimateView({
  estimate,
  status,
  fetchedAt,
  locale,
  onViewOutput,
  onOpenShell,
  onShowSimilar,
}: {
  estimate: RuntimeEstimate | undefined;
  status: number | undefined;
  fetchedAt: number;
  locale?: string;
} & RuntimeEstimateActions) {
  const card = runtimeCard(estimate, status, fetchedAt, locale);
  if (!card) return null;
  const showActions = card.actions && (onViewOutput || onOpenShell);
  return (
    <section
      aria-labelledby="runtime-estimate-title"
      data-testid="runtime-estimate"
      className={`rounded-sm border bg-white p-4 space-y-3 ${card.longer ? 'border-amber-300' : 'border-gray-200'}`}
    >
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h2
          id="runtime-estimate-title"
          className="text-xs font-semibold uppercase tracking-wide text-gray-500"
        >
          Expected run time
        </h2>
        {card.longer && (
          <span className="inline-flex whitespace-nowrap rounded-full bg-amber-100 px-2 py-0.5 text-xs font-semibold text-amber-900">
            Longer than usual
          </span>
        )}
      </div>
      <p className={`text-lg font-medium ${card.rough ? 'text-gray-600' : 'text-gray-900'}`}>
        {card.headline}
        {card.rough && <RoughChip />}
      </p>
      <div>
        <RuntimeRangeBar {...card.bar} rough={card.rough} longer={card.longer} />
        <div className="flex justify-between gap-3 text-xs text-gray-600 tabular-nums">
          <span>{card.axis.left}</span>
          {card.axis.middle && <span className="text-center">{card.axis.middle}</span>}
          <span className="text-right">{card.axis.right}</span>
        </div>
      </div>
      {card.lines.map((line) => {
        // The basis sentence names a group of jobs; it opens them.
        const at = card.basis && onShowSimilar ? line.indexOf(card.basis) : -1;
        return (
          <p key={line} className="text-sm text-gray-600">
            {at < 0 ? (
              line
            ) : (
              <>
                {line.slice(0, at)}
                <button
                  type="button"
                  onClick={onShowSimilar}
                  className="text-left text-brand-700 underline decoration-dotted underline-offset-2 hover:decoration-solid"
                  data-testid="runtime-basis-link"
                >
                  {card.basis}
                </button>
                {line.slice(at + card.basis!.length)}
              </>
            )}
          </p>
        );
      })}
      {showActions && (
        <div className="flex flex-wrap gap-2">
          {onViewOutput && (
            <button type="button" onClick={onViewOutput} className={actionCls}>
              View live output
            </button>
          )}
          {onOpenShell && (
            <button type="button" onClick={onOpenShell} className={actionCls}>
              Open a shell in the job
            </button>
          )}
        </div>
      )}
    </section>
  );
}

// RuntimeEstimateField fetches and shows the estimate for a waiting or
// running job. A running job's remaining time moves, so it is asked
// again every minute; a waiting job's estimate changes only as other
// jobs finish, so every five.
export function RuntimeEstimateField({
  jobID,
  status,
  ...actions
}: {
  jobID: string;
  status: number | undefined;
} & RuntimeEstimateActions) {
  const live = status === 1 || status === 2;
  const { data, dataUpdatedAt } = useQuery({
    queryKey: ['runtime-estimate', jobID],
    enabled: live,
    retry: false,
    refetchInterval: status === 2 ? 60_000 : 300_000,
    queryFn: () => api.jobs.runtimeEstimate(jobID),
  });
  if (!live) return null;
  return (
    <RuntimeEstimateView
      estimate={data}
      status={status}
      fetchedAt={Math.floor(dataUpdatedAt / 1000)}
      {...actions}
    />
  );
}
