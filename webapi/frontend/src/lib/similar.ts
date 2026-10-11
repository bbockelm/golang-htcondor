// The groups a job belongs to: the finished jobs its runtime estimate was
// drawn from (GET /api/v1/jobs/{id}/similar), and its workflow on the
// Utilization page (GET /api/v1/utilization/for-job/{id}).

import type { RuntimeEstimateLevel } from './api';

export type EstimateLevel = RuntimeEstimateLevel;

export interface SimilarJobsResponse {
  job_id: string;
  level: EstimateLevel; // the level listed
  description: string; // the group in plain words, e.g. "same command, numbers ignored"
  estimate_level: EstimateLevel | null; // the level that answered this job's estimate; null if none
  levels: {
    level: EstimateLevel;
    description: string;
    applies: boolean; // false when the job has nothing to group on at that level
    count?: number | null; // the group's sample count right now, when known
  }[];
  window: { days: number; max_jobs: number };
  // The runtimes the estimator holds for this group right now -- what the
  // estimate used; null when there are none to show.
  runtimes: {
    count: number;
    p10: number;
    p25: number;
    p50: number;
    p75: number;
    p90: number;
  } | null;
  aggregate_only: boolean; // true for 'global' (it spans other users): jobs is always []
  total: number; // jobs found in history for this group (<= window.max_jobs)
  offset: number;
  next_offset: number | null;
  jobs: SimilarJob[]; // newest first
}

export interface SimilarJob {
  id: string; // "cluster.proc"
  cluster: number;
  proc: number;
  submitted: number | null; // unix seconds
  completed: number; // unix seconds
  runtime: number; // seconds
  exit_code: number; // always 0: only jobs that completed normally feed estimates
}

export interface UtilizationForJob {
  job_id: string;
  key: string;
  name: string;
  executable: string;
  owner: string;
  has_history: boolean | null; // finished jobs of this workflow in the last 30 days; null if unknown
}

/**
 * utilizationHrefForJob links a job to its workflow on the Utilization
 * page, over the last 30 days -- or nothing, when the workflow has no
 * finished jobs there to show. Someone else's job (an admin looking)
 * needs the pool-wide scope narrowed to its owner.
 */
export function utilizationHrefForJob(u: UtilizationForJob | undefined, viewer: string | undefined): string | null {
  if (!u || u.has_history === false) return null;
  const qs = new URLSearchParams({ days: '30', w: u.key });
  if (viewer !== undefined && u.owner !== viewer) {
    qs.set('owned_by_me', 'false');
    qs.set('owners', u.owner);
  }
  return `/utilization?${qs.toString()}`;
}

/** batchHref lists a job's batch, on /jobs for a queued job or /archive. */
export function batchHref(cluster: number, archived: boolean): string {
  const qs = new URLSearchParams({ constraint: `ClusterId == ${cluster}`, why: `jobs in batch ${cluster}` });
  return `/${archived ? 'archive' : 'jobs'}?${qs.toString()}`;
}
