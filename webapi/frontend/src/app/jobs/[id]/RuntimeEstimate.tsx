'use client';

// How long a waiting or running job is likely to take, on the job page.
//
// It renders nothing at all unless there is an estimate: no placeholder
// while the access point is still reading its history, nothing for a job
// with nothing comparable, nothing on a server without the feature. So
// where there is no answer the page looks exactly as it did.

import { useQuery } from '@tanstack/react-query';

import { api, type RuntimeEstimate, type RuntimeEstimateLevel } from '@/lib/api';
import { approxDuration } from '@/lib/duration';

// What each basis compared the job with. [singular, plural]; null for a
// basis that carries no count worth printing.
const basisText: Record<RuntimeEstimateLevel, [string, string] | null> = {
  cluster: ['from 1 finished job in this cluster', 'from N finished jobs in this cluster'],
  exact: [
    'from 1 earlier job with the same command and arguments',
    'from N of your earlier jobs with the same command and arguments',
  ],
  template: [
    'from 1 earlier job with the same command and argument pattern',
    'from N of your earlier jobs with the same command and argument pattern',
  ],
  batch: ['from 1 earlier job in the same batch', 'from N of your earlier jobs in the same batch'],
  iwd: [
    'from 1 earlier job from the same submit directory',
    'from N of your earlier jobs from the same submit directory',
  ],
  cmd: [
    'from 1 earlier job running the same program',
    'from N of your earlier jobs running the same program',
  ],
  owner: null,
  global: null,
};

// basisLine says what the estimate was drawn from. The two broadest
// bases say why nothing closer answered when that is known: a rough
// guess should say what it is a guess from.
export function basisLine(basis: RuntimeEstimate['basis']): string | undefined {
  if (!basis) return undefined;
  if (basis.level === 'owner') {
    return basis.new_command
      ? 'This command has not run recently. Based on your recent jobs in general.'
      : 'Based on your recent jobs in general.';
  }
  if (basis.level === 'global') {
    return 'You have no recently finished jobs to compare with. Based on recent jobs on this access point.';
  }
  const text = basisText[basis.level];
  if (!text) return undefined;
  return basis.sample_count === 1
    ? text[0]
    : text[1].replace('N', String(basis.sample_count));
}

// rangeText is the likely range, or undefined when it would read as a
// single figure ("1h to 1h"). A rough guess's range is wide and says so.
export function rangeText(
  r: Pick<RuntimeEstimate, 'p10_seconds' | 'p90_seconds' | 'rough'>,
): string | undefined {
  if (r.p10_seconds === undefined || r.p90_seconds === undefined) return undefined;
  const lo = approxDuration(r.p10_seconds);
  const hi = approxDuration(r.p90_seconds);
  if (lo === hi) return undefined;
  return r.rough ? `anywhere from ${lo} to ${hi}` : `usually ${lo} to ${hi}`;
}

// runtimeEstimateText is what the page prints for an estimate, or null
// when it prints nothing: no estimate, or a job that is neither waiting
// (1) nor running (2).
//
// rough marks an estimate from one of the broad bases: it reads "Roughly"
// rather than "About", and the view adds a "rough guess" chip.
export function runtimeEstimateText(
  r: RuntimeEstimate | undefined,
  status: number | undefined,
): { value: string; sub?: string; rough?: boolean } | null {
  if (!r || !r.available || r.estimate_seconds === undefined) return null;
  if (status !== 1 && status !== 2) return null;
  const total = approxDuration(r.estimate_seconds);
  const sub = basisLine(r.basis);
  const rough = !!r.rough;
  if (status === 2 && r.exceeded_history) {
    return { value: `Running longer than similar jobs (they took about ${total})`, sub };
  }
  const range = rangeText(r);
  const withRange = (s: string) => (range ? `${s} (${range})` : s);
  const [About, about] = rough ? ['Roughly', 'roughly'] : ['About', 'about'];
  if (status === 2 && r.remaining_seconds !== undefined && r.elapsed_seconds !== undefined) {
    return {
      value: withRange(
        `${About} ${approxDuration(r.remaining_seconds)} left · running ${approxDuration(r.elapsed_seconds)} of ${about} ${total}`,
      ),
      sub,
      rough,
    };
  }
  return { value: withRange(`${About} ${total}`), sub, rough };
}

// RoughChip marks an estimate that is only a rough guess: a dashed
// outline, quieter than a status.
export function RoughChip() {
  return (
    <span className="ml-1.5 inline-flex whitespace-nowrap rounded-full border border-dashed border-gray-400 px-1.5 text-[10px] font-medium leading-4 text-gray-600 align-middle">
      rough guess
    </span>
  );
}

// RuntimeEstimateView lays an estimate out as one full-width field of
// the job page's summary card.
export function RuntimeEstimateView({
  estimate,
  status,
}: {
  estimate: RuntimeEstimate | undefined;
  status: number | undefined;
}) {
  const text = runtimeEstimateText(estimate, status);
  if (!text) return null;
  return (
    <div className="col-span-2" data-testid="runtime-estimate">
      <div className="text-xs uppercase tracking-wide text-gray-500">Expected run time</div>
      <div className="mt-0.5 text-sm text-gray-900 wrap-break-word">
        {text.value}
        {text.rough && <RoughChip />}
      </div>
      {text.sub && <div className="mt-0.5 text-xs text-gray-500">{text.sub}</div>}
    </div>
  );
}

// RuntimeEstimateField fetches and shows the estimate for a waiting or
// running job. A running job's remaining time moves, so it is asked
// again every minute; a waiting job's estimate changes only as other
// jobs finish, so every five.
export function RuntimeEstimateField({
  jobID,
  status,
}: {
  jobID: string;
  status: number | undefined;
}) {
  const live = status === 1 || status === 2;
  const { data } = useQuery({
    queryKey: ['runtime-estimate', jobID],
    enabled: live,
    retry: false,
    refetchInterval: status === 2 ? 60_000 : 300_000,
    queryFn: () => api.jobs.runtimeEstimate(jobID),
  });
  if (!live) return null;
  return <RuntimeEstimateView estimate={data} status={status} />;
}
