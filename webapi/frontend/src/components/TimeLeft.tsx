'use client';

// The jobs listing's "Time left" cells and the batch's "running longer
// than usual" and "using more memory than usual" chips. The wording
// lives in lib/timeLeft.

import { RoughChip } from '@/app/jobs/[id]/RuntimeEstimate';
import { RangePlot } from '@/components/RangePlot';
import type { DagNodeCounts } from '@/lib/batches';
import {
  batchTimeLeft,
  dagTimeLeft,
  jobTimeLeft,
  longerThanUsualText,
  moreMemoryText,
  rangeBar,
  type TimedJob,
} from '@/lib/timeLeft';

// LongerThanUsualChip is amber, like the job page's warnings: a job past
// what comparable jobs took may be stuck.
// A job using more memory than similar jobs did gets the same chip.
export function LongerThanUsualChip({ text, title }: { text: string; title?: string }) {
  return (
    <span
      className="inline-flex whitespace-nowrap rounded-full bg-amber-100 px-1.5 py-0.5 text-[11px] font-medium text-amber-800"
      title={title}
    >
      {text}
    </span>
  );
}

// BatchLongerThanUsual is the chip under a batch's status pills, or
// nothing when every running job is within its usual time.
export function BatchLongerThanUsual({ jobs }: { jobs: readonly TimedJob[] }) {
  const text = longerThanUsualText(jobs);
  if (!text) return null;
  return (
    <div className="mt-1" data-testid="longer-than-usual">
      <LongerThanUsualChip text={text} />
    </div>
  );
}

// BatchMoreMemoryThanUsual is the batch's memory chip, or nothing when
// no running job is past what similar jobs peaked at.
export function BatchMoreMemoryThanUsual({ jobs }: { jobs: readonly TimedJob[] }) {
  const text = moreMemoryText(jobs);
  if (!text) return null;
  return (
    <div className="mt-1" data-testid="more-memory-than-usual">
      <LongerThanUsualChip text={text} />
    </div>
  );
}

export function BatchTimeLeftCell({
  jobs,
  dag,
  fetchedAt,
  now,
}: {
  jobs: readonly TimedJob[];
  // Set for a DAG's row, with its node counts when it has reported them:
  // the cell then describes nodes, never a finish time for the DAG.
  dag?: { nodes?: DagNodeCounts };
  fetchedAt: number;
  now: number;
}) {
  const t = dag ? dagTimeLeft(jobs, dag.nodes, fetchedAt, now) : batchTimeLeft(jobs, fetchedAt, now);
  if (!t) return <span className="text-gray-400">—</span>;
  return (
    <div className="w-40 text-xs" title={t.title} data-testid="batch-time-left">
      <div className={t.overrun ? 'font-medium text-amber-800' : t.main === '—' ? 'text-gray-400' : 'text-gray-800'}>
        {t.main}
        {t.rough && <RoughChip />}
      </div>
      {t.sub && <div className="mt-0.5 text-[11px] text-gray-500">{t.sub}</div>}
      {t.more?.map((line) => (
        <div key={line} className="mt-0.5 text-[11px] text-gray-500">
          {line}
        </div>
      ))}
    </div>
  );
}

export function JobTimeLeftCell({
  job,
  scale,
  fetchedAt,
  now,
}: {
  job: TimedJob;
  scale: number;
  fetchedAt: number;
  now: number;
}) {
  const t = jobTimeLeft(job, fetchedAt, now);
  if (!t) return null;
  const bar = rangeBar(job, scale, fetchedAt, now);
  return (
    <div className="whitespace-nowrap" title={t.title} data-testid="job-time-left">
      <div>
        {t.longer && <LongerThanUsualChip text="Longer than usual" />}
        {t.main && <span className={t.main === '—' ? 'text-gray-400' : 'font-medium text-gray-800'}>{t.main}</span>}
        {t.rough && <RoughChip />}
      </div>
      {t.memory && (
        <div className="mt-0.5" data-testid="job-more-memory">
          <LongerThanUsualChip text="More memory than usual" title={t.memory} />
        </div>
      )}
      {t.sub && <div className="mt-0.5 text-[11px] text-gray-500">{t.sub}</div>}
      {bar && <RangeBar g={bar} rough={t.rough} />}
    </div>
  );
}

// RangeBar is one job on its batch's shared axis, drawn with the same
// marks as the job page's run time card: the usual range as a band, the
// typical run as a tick, and how far a running job has got as a fill --
// amber once it is past nearly every comparable run.
function RangeBar({ g, rough }: { g: NonNullable<ReturnType<typeof rangeBar>>; rough?: boolean }) {
  return (
    <div className="mt-1 hidden w-36 sm:block">
      <RangePlot
        size="sm"
        band={{ from: g.bandLeft / 100, to: (g.bandLeft + g.bandWidth) / 100 }}
        tick={g.tick / 100}
        job={g.elapsed !== undefined ? g.elapsed / 100 : undefined}
        rough={rough}
        unusual={g.overrun}
      />
    </div>
  );
}
