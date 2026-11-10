'use client';

// The groups a job belongs to, near the top of its page: its batch, its
// workflow on the Utilization page, and the similar jobs its runtime
// estimate is based on. Going from one job back to the group was the
// hard part; this row is where it starts.

import Link from 'next/link';
import { useQuery } from '@tanstack/react-query';
import { api } from '@/lib/api';
import { batchHref, utilizationHrefForJob } from '@/lib/similar';
import { batchPagePath } from '@/lib/batches';

export function JobRelated({
  jobID,
  cluster,
  batchID,
  archived,
  onSimilar,
}: {
  jobID: string;
  cluster: number | undefined;
  // The job's batch (batchIDOfJob): a DAG's root cluster for each of its
  // jobs. Without it the job's own cluster, which the batch page
  // resolves to the same batch.
  batchID?: number;
  archived: boolean;
  // Opens and scrolls to the page's similar-jobs section.
  onSimilar: () => void;
}) {
  const { data: session } = useQuery({ queryKey: ['session'], queryFn: api.auth.me });
  // The workflow link is only offered when there is a workflow with
  // finished jobs to show; any failure to find it hides it.
  const { data: workflow } = useQuery({
    queryKey: ['utilization-for-job', jobID],
    queryFn: () => api.jobs.utilizationWorkflow(jobID),
    retry: false,
    staleTime: 300_000,
  });
  const utilHref = utilizationHrefForJob(workflow, session?.username);
  const linkCls = 'text-brand-700 hover:underline';
  // Batch pages serve a single access point; a multi-AP job id
  // (cluster.proc@schedd) lists its cluster instead.
  const multiAP = jobID.includes('@');
  const batch = multiAP ? cluster : (batchID ?? cluster);
  const batchLink =
    batch === undefined ? undefined : multiAP ? batchHref(batch, archived) : batchPagePath({ batchID: batch });
  return (
    <nav aria-label="Related" className="flex flex-wrap items-center gap-x-4 gap-y-1 text-sm" data-testid="job-related">
      <span className="text-xs font-semibold uppercase tracking-wide text-gray-500">Related</span>
      {batchLink && (
        <Link href={batchLink} className={linkCls}>
          Batch {batch}
        </Link>
      )}
      {utilHref && workflow && (
        <Link href={utilHref} className={linkCls} data-testid="related-utilization">
          Workflow utilization{workflow.name ? ` (${workflow.name})` : ''}
        </Link>
      )}
      <button type="button" onClick={onSimilar} className={linkCls}>
        Similar jobs
      </button>
    </nav>
  );
}
