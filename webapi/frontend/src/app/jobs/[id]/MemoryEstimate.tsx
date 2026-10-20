'use client';

// What similar jobs peaked at, beside the run time card: on the job page
// for a waiting or running job, and on the archived job's page for a
// finished one. It describes the same group of jobs the run time card
// does, and like it renders nothing at all when there is nothing to say.

import { useQuery } from '@tanstack/react-query';

import { RangePlot } from '@/components/RangePlot';
import { chartEntries, HowToRead } from '@/components/RangeLegend';
import { api, type RuntimeMemory } from '@/lib/api';

import { memoryCard } from './memoryCard';
import { liveEstimateQuery, RoughChip } from './RuntimeEstimate';

export function MemoryEstimateView({ memory, status }: { memory: RuntimeMemory | undefined; status: number | undefined }) {
  const card = memoryCard(memory, status);
  if (!card) return null;
  return (
    <section
      aria-labelledby="memory-estimate-title"
      data-testid="memory-estimate"
      className={`rounded-sm border bg-white p-4 space-y-3 ${card.above ? 'border-amber-300' : 'border-gray-200'}`}
    >
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h2 id="memory-estimate-title" className="text-xs font-semibold uppercase tracking-wide text-gray-500">
          Peak memory
        </h2>
        {card.above && (
          <span className="inline-flex whitespace-nowrap rounded-full bg-amber-100 px-2 py-0.5 text-xs font-semibold text-amber-900">
            More memory than usual
          </span>
        )}
      </div>
      <p className={`text-lg font-medium ${card.rough ? 'text-gray-600' : 'text-gray-900'}`}>
        {card.headline}
        {card.rough && <RoughChip />}
      </p>
      <div>
        <RangePlot
          band={card.bar.band}
          box={card.bar.box}
          tick={card.bar.tick}
          job={card.bar.elapsed}
          jobCapped={card.bar.elapsedCapped}
          refs={card.bar.refs}
          rough={card.rough}
          unusual={card.above}
          testID="memory-range-bar"
        />
        <div className="flex justify-between gap-3 text-xs text-gray-600 tabular-nums">
          <span>{card.axis.left}</span>
          {card.axis.middle && <span className="text-center">{card.axis.middle}</span>}
          <span className="text-right">{card.axis.right}</span>
        </div>
        <div className="mt-1">
          <HowToRead
            entries={chartEntries({
              rough: card.rough,
              box: card.bar.box !== undefined,
              job: card.bar.elapsed !== undefined,
              // Only a running job is compared with what is usual.
              canBeUnusual: status === 2,
              requested: !!card.bar.refs?.length,
            })}
          />
        </div>
      </div>
      {card.lines.map((line) => (
        <p key={line} className="text-sm text-gray-600">
          {line}
        </p>
      ))}
    </section>
  );
}

// MemoryEstimateField shows a waiting or running job's card, from the
// estimate the run time card reads.
export function MemoryEstimateField({ jobID, status }: { jobID: string; status: number | undefined }) {
  const { data } = useQuery(liveEstimateQuery(jobID, status));
  if ((status !== 1 && status !== 2) || !data?.available) return null;
  return <MemoryEstimateView memory={data.memory} status={status} />;
}

// ArchivedMemoryEstimate fetches and shows a finished job's card. The
// record does not change, so it is read once.
export function ArchivedMemoryEstimate({ jobID, status }: { jobID: string; status: number | undefined }) {
  const finished = status === 3 || status === 4;
  const { data } = useQuery({
    queryKey: ['runtime-estimate', jobID],
    enabled: finished,
    retry: false,
    staleTime: Infinity,
    queryFn: () => api.jobs.runtimeEstimate(jobID),
  });
  if (!finished || !data?.available) return null;
  return <MemoryEstimateView memory={data.memory} status={status} />;
}
