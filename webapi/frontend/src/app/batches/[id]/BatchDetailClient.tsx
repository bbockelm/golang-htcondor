'use client';

// /batches/<id>: one batch or DAG -- its progress, its finished jobs'
// outcomes, why any were held, what it used, and every job in it. The
// id is any cluster of the batch; the page moves to the batch's own id
// once it knows it.

import { useEffect } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useQuery } from '@tanstack/react-query';
import { api, ApiError } from '@/lib/api';
import { useResolvedParams } from '@/lib/useResolvedParams';
import { useMultiAP } from '@/lib/multiap';
import { useNowTick } from '@/lib/useNowTick';
import { batchPageHref } from '@/lib/batchPage';
import {
  BatchHeader,
  DagSection,
  HoldsSection,
  JobsSection,
  OutcomesSection,
  ProgressSection,
  ResourcesSection,
  useBatchTimeLeft,
} from '@/components/BatchPage';

export default function BatchDetailClient() {
  const { id } = useResolvedParams<{ id: string }>('/batches/[id]');
  const router = useRouter();
  const multiAP = useMultiAP();
  const now = useNowTick(30_000);
  const valid = !!id && id !== '_';

  const { data: batch, error, isLoading } = useQuery({
    queryKey: ['batch', id],
    enabled: valid,
    queryFn: () => api.batches.get(id),
    refetchInterval: 30_000,
    retry: (n, e) => !(e instanceof ApiError && e.status < 500) && n < 1,
  });

  // A link from any of the batch's clusters lands here; show the batch's
  // own id in the address bar -- but only to a page that would list this
  // batch: never to an id that is not one of its clusters.
  useEffect(() => {
    if (batch && String(batch.id) !== id && batch.clusters.includes(batch.id)) {
      router.replace(batchPageHref(batch.id));
    }
  }, [batch, id, router]);

  const { timed, estimates } = useBatchTimeLeft(batch);

  const back = (
    <Link href="/jobs" className="text-sm text-brand-700 hover:underline">
      ← All batches
    </Link>
  );

  if (!valid) return <div className="space-y-4">{back}</div>;
  if (error) {
    const status = error instanceof ApiError ? error.status : 0;
    return (
      <div className="space-y-4">
        {back}
        <h1 className="text-2xl font-bold text-gray-900">Batch {id}</h1>
        <p className="text-sm text-gray-600" data-testid="batch-error">
          {status === 404
            ? 'No batch with this id is visible to you. It may never have existed, or it belongs to someone else.'
            : status === 400
              ? 'This is not a batch id: a batch is named by one of its cluster numbers.'
              : status === 501
                ? 'Batch pages are not available when this page shows several access points. The batch is on the jobs page.'
                : `Could not load this batch: ${error.message}`}
        </p>
      </div>
    );
  }
  if (isLoading || !batch) {
    return (
      <div className="space-y-4">
        {back}
        <p className="text-gray-400">Loading…</p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {back}
      <BatchHeader batch={batch} now={now} multiAP={multiAP} />
      <ProgressSection batch={batch} timed={timed} estimates={estimates} now={now} />
      <DagSection batch={batch} />
      <div className="grid gap-4 lg:grid-cols-2">
        <OutcomesSection batch={batch} />
        <ResourcesSection batch={batch} />
      </div>
      <HoldsSection batch={batch} />
      <JobsSection batch={batch} estimates={estimates} now={now} />
    </div>
  );
}
