'use client';

// The jobs listing's "Time left" cells and the batch's "running longer
// than usual" chip. The wording lives in lib/timeLeft.

import { RoughChip } from '@/app/jobs/[id]/RuntimeEstimate';
import {
  batchTimeLeft,
  jobTimeLeft,
  longerThanUsualText,
  rangeBar,
  type TimedJob,
} from '@/lib/timeLeft';

// LongerThanUsualChip is amber, like the job page's warnings: a job past
// what comparable jobs took may be stuck.
export function LongerThanUsualChip({ text }: { text: string }) {
  return (
    <span className="inline-flex whitespace-nowrap rounded-full bg-amber-100 px-1.5 py-0.5 text-[11px] font-medium text-amber-800">
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

export function BatchTimeLeftCell({
  jobs,
  fetchedAt,
  now,
}: {
  jobs: readonly TimedJob[];
  fetchedAt: number;
  now: number;
}) {
  const t = batchTimeLeft(jobs, fetchedAt, now);
  if (!t) return <span className="text-gray-400">—</span>;
  return (
    <div className="w-40 text-xs" title={t.title} data-testid="batch-time-left">
      <div className={t.overrun ? 'font-medium text-amber-800' : t.main === '—' ? 'text-gray-400' : 'text-gray-800'}>
        {t.main}
        {t.rough && <RoughChip />}
      </div>
      {t.sub && <div className="mt-0.5 text-[11px] text-gray-500">{t.sub}</div>}
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
      {t.sub && <div className="mt-0.5 text-[11px] text-gray-500">{t.sub}</div>}
      {bar && <RangeBar g={bar} />}
    </div>
  );
}

// RangeBar is one job on its batch's shared axis: the usual range as a
// band, the typical run as a tick, and how far a running job has got as
// a fill -- amber once it is past nearly every comparable run.
function RangeBar({ g }: { g: NonNullable<ReturnType<typeof rangeBar>> }) {
  return (
    <div className="relative mt-1 hidden h-2.5 w-36 sm:block" aria-hidden>
      <div className="absolute inset-x-0 top-[4px] h-0.5 rounded-sm bg-gray-200" />
      <div
        className="absolute top-[2px] h-1.5 rounded-sm bg-sky-200"
        style={{ left: `${g.bandLeft}%`, width: `${g.bandWidth}%` }}
      />
      {g.elapsed !== undefined && (
        <div
          className={`absolute left-0 top-[2px] h-1.5 rounded-sm ${g.overrun ? 'bg-amber-600/85' : 'bg-emerald-600'}`}
          style={{ width: `${g.elapsed}%` }}
        />
      )}
      {!g.overrun && (
        <div className="absolute top-0 h-2.5 w-0.5 bg-sky-700" style={{ left: `${g.tick}%` }} />
      )}
    </div>
  );
}
