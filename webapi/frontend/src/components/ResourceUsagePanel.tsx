'use client';

// Resource-usage graphs for one job, fed by the job_metrics sampler. Used
// by both the live job page and the archive detail page -- the samples
// outlive the queue, so a completed job still plots until job_metrics'
// retention drops its segments.
//
// It renders nothing at all unless the sampler is enabled AND a metric has
// more than three points (the sampler's floor is ~one point per 15 min, so
// a short or just-started job has too little to plot). Disk and GPU appear
// only when the job actually used them. So on a pool without the sampler,
// for a job with no samples yet, or for an archived job old enough to have
// aged out, the page looks exactly as it did.

import { useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import { api } from '@/lib/api';
import {
  buildJobMetrics,
  JOB_METRICS_AGG,
  JOB_METRICS_BUCKET_SECONDS,
  JOB_METRICS_GROUP_BY,
} from '@/lib/metrics';
import { MetricChart } from '@/components/MetricChart';

export function ResourceUsagePanel({
  jobID,
  status,
}: {
  jobID: string;
  status: number | undefined;
}) {
  // jobID is "cluster.proc"; only integers make a valid constraint.
  // parseInt (rather than Number) so an id carrying a suffix -- the
  // archive route builds keys like "12345.0@1790000000" -- still resolves,
  // matching how the archive detail page itself reads the id.
  const [clusterStr, procStr] = jobID.split('.');
  const cluster = Number.parseInt(clusterStr, 10);
  const proc = Number.parseInt(procStr ?? '0', 10);
  const valid = Number.isInteger(cluster) && Number.isInteger(proc);

  // A running/idle job is still accruing samples; a finished one is fixed.
  const live = status === 1 || status === 2 || status === 6 || status === 7;

  const { data } = useQuery({
    queryKey: ['job-metrics', cluster, proc],
    enabled: valid,
    retry: false,
    refetchInterval: live ? 60_000 : false,
    queryFn: () =>
      api.metrics.query('job_metrics', {
        constraint: `ClusterId == ${cluster} && ProcId == ${proc}`,
        group_by: JOB_METRICS_GROUP_BY,
        bucket: JOB_METRICS_BUCKET_SECONDS,
        agg: JOB_METRICS_AGG,
      }),
  });

  const series = useMemo(() => buildJobMetrics(data), [data]);

  // The whole section is invisible until there is something worth showing.
  if (series.length === 0) return null;

  return (
    <div className="space-y-3">
      <h2 className="text-sm font-semibold text-gray-900">Resource usage</h2>
      <div className="grid gap-3 lg:grid-cols-2">
        {series.map((s) => (
          <MetricChart key={s.key} series={s} />
        ))}
      </div>
    </div>
  );
}
