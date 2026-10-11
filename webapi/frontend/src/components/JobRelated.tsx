'use client';

// The groups a job belongs to, near the top of its page: its batch, its
// workflow on the Utilization page, and the similar jobs its runtime
// estimate is based on. Going from one job back to the group was the
// hard part; this row is where it starts.

import Link from 'next/link';
import { useQuery } from '@tanstack/react-query';
import { api } from '@/lib/api';
import { batchHref, utilizationHrefForJob } from '@/lib/similar';

export function JobRelated({
  jobID,
  cluster,
  archived,
  onSimilar,
}: {
  jobID: string;
  cluster: number | undefined;
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
  return (
    <nav aria-label="Related" className="flex flex-wrap items-center gap-x-4 gap-y-1 text-sm" data-testid="job-related">
      <span className="text-xs font-semibold uppercase tracking-wide text-gray-500">Related</span>
      {cluster !== undefined && (
        <Link href={batchHref(cluster, archived)} className={linkCls}>
          Batch {cluster}
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
