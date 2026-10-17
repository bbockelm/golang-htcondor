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
import { api, type ClassAd } from '@/lib/api';
import {
  buildJobMetrics,
  JOB_METRICS_AGG,
  JOB_METRICS_BUCKET_SECONDS,
  JOB_METRICS_GROUP_BY,
  jobMetricsSelector,
} from '@/lib/metrics';
import { MetricChart } from '@/components/MetricChart';

export function ResourceUsagePanel({
  jobID,
  status,
  job,
  multiAP = false,
}: {
  // "cluster.proc"; in multi-AP mode the server's complete job_id.
  jobID: string;
  status: number | undefined;
  // The job's ad, for the "requested" reference: the same evaluated
  // requests the resource table shows.
  job?: ClassAd;
  multiAP?: boolean;
}) {
  const selector = jobMetricsSelector(jobID, multiAP);

  // A running/idle job is still accruing samples; a finished one is fixed.
  const live = status === 1 || status === 2 || status === 6 || status === 7;

  const { data } = useQuery({
    queryKey: ['job-metrics', multiAP, selector],
    enabled: selector !== undefined,
    retry: false,
    refetchInterval: live ? 60_000 : false,
    queryFn: () =>
      api.metrics.query('job_metrics', {
        ...selector!,
        group_by: JOB_METRICS_GROUP_BY,
        bucket: JOB_METRICS_BUCKET_SECONDS,
        agg: JOB_METRICS_AGG,
      }),
  });

  const series = useMemo(() => buildJobMetrics(data, job), [data, job]);

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
