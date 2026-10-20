import type { RuntimeEstimate } from './api';
import type { EstimateLevel, Quantiles, SimilarJob, SimilarJobsResponse, UtilizationForJob } from './similar';

// Sample answers for GET /api/v1/jobs/{id}/similar,
// /api/v1/jobs/{id}/runtime-estimate and /api/v1/utilization/for-job/{id},
// for the component tests, the smoke suite and a dev mock. Only type
// imports, so Node can load it directly.
//
// A job's estimate and its similar jobs describe one group -- the one the
// estimate used -- so both are built from one JobGroup: the estimate's
// figures are the group's, as they are on a real server, and a page that
// shows both says the same thing twice.

// mem is each level's median peak memory in MiB; null for a group whose
// records carry no peak.
const LEVELS: { level: EstimateLevel; description: string; count: number | null; median: number; mem: number | null }[] = [
  { level: 'exact', description: 'same command and arguments, directories and hashes ignored', count: 12, median: 2400, mem: 1100 },
  { level: 'template', description: 'same command, numbers ignored', count: 41, median: 2700, mem: 1200 },
  { level: 'batch', description: 'same batch name, run number ignored', count: 64, median: 3000, mem: 1300 },
  { level: 'iwd', description: 'same submit directory, numbers ignored', count: 80, median: 3300, mem: null },
  { level: 'cmd', description: 'same program, any arguments', count: 150, median: 3600, mem: 1500 },
  { level: 'owner', description: 'all your jobs of this kind', count: 400, median: 1800, mem: 900 },
];

const NOW = 1_760_100_000;

function jobsFor(level: EstimateLevel, count: number, median: number, mem: number | null): SimilarJob[] {
  // Deterministic spread around the median, newest first. Every seventh
  // record has no peak memory.
  return Array.from({ length: count }, (_, i) => {
    const runtime = Math.round(median * (0.6 + ((i * 37) % 80) / 100));
    const completed = NOW - i * 1800 - (LEVELS.findIndex((l) => l.level === level) + 1) * 60;
    const cluster = 81200 + Math.floor(i / 10);
    const peak = mem === null || i % 7 === 6 ? null : Math.round(mem * (0.7 + ((i * 53) % 70) / 100));
    return {
      id: `${cluster}.${i % 10}`, cluster, proc: i % 10, submitted: completed - runtime - 300, completed, runtime, exit_code: 0,
      peak_memory_mib: peak,
    };
  });
}

// The level every fixture estimate is answered from.
const ESTIMATE_LEVEL: EstimateLevel = 'template';

// JobGroup is the group behind a job's estimate: its runtimes and its
// peak memory (null when no run has one).
export interface JobGroup {
  runtimes: Quantiles;
  memory: Quantiles | null;
}

// levelGroup is a level's group as the fixture draws it.
function levelGroup(l: (typeof LEVELS)[number]): JobGroup {
  const m = l.median;
  const all = jobsFor(l.level, l.count ?? 0, l.median, l.mem);
  return {
    runtimes: { count: l.count ?? 0, p10: m * 0.6, p25: m * 0.8, p50: m, p75: m * 1.2, p90: m * 1.5 },
    memory:
      l.mem === null
        ? null
        : {
            count: all.filter((j) => j.peak_memory_mib !== null).length,
            p10: Math.round(l.mem * 0.75),
            p25: Math.round(l.mem * 0.88),
            p50: l.mem,
            p75: Math.round(l.mem * 1.15),
            p90: Math.round(l.mem * 1.3),
          },
  };
}

// estimateGroup is the group the fixture's estimates answer from, unless
// a test gives its own.
export function estimateGroup(): JobGroup {
  return levelGroup(LEVELS.find((l) => l.level === ESTIMATE_LEVEL)!);
}

// groupJobs is a group's finished jobs, spread around its medians.
function groupJobs(g: JobGroup): SimilarJob[] {
  return jobsFor(ESTIMATE_LEVEL, g.runtimes.count, g.runtimes.p50, g.memory?.p50 ?? null);
}

// similarFixture is GET /similar. group, when given, replaces the group
// at the estimate's level, so it matches an estimateFixture built from
// the same group.
export function similarFixture(
  jobID: string,
  opts: { level?: EstimateLevel; offset?: number; page_size?: number } = {},
  group?: JobGroup,
): SimilarJobsResponse {
  const level = opts.level ?? ESTIMATE_LEVEL;
  const l = LEVELS.find((x) => x.level === level) ?? LEVELS[1];
  const own = level === ESTIMATE_LEVEL && group !== undefined;
  const g = own ? group : levelGroup(l);
  const all = own ? groupJobs(group) : jobsFor(level, l.count ?? 0, l.median, l.mem);
  const offset = opts.offset ?? 0;
  const size = Math.min(opts.page_size ?? 50, 200);
  const page = all.slice(offset, offset + size);
  return {
    job_id: jobID,
    level,
    description: l.description,
    estimate_level: ESTIMATE_LEVEL,
    levels: [
      { level: 'cluster', description: 'same cluster', applies: false, count: null },
      ...LEVELS.map((x) => ({
        level: x.level,
        description: x.description,
        applies: true,
        count: x.level === ESTIMATE_LEVEL && group ? group.runtimes.count : x.count,
      })),
    ],
    window: { days: 30, max_jobs: 500 },
    runtimes: g.runtimes,
    memory: g.memory,
    total: all.length,
    offset,
    next_offset: offset + size < all.length ? offset + size : null,
    jobs: page,
  };
}

export function forJobFixture(jobID: string, over: Partial<UtilizationForJob> = {}): UtilizationForJob {
  return {
    job_id: jobID,
    key: 'wf-blast',
    name: 'blast-search',
    executable: 'run_blast.sh',
    owner: 'e2e',
    has_history: true,
    ...over,
  };
}

// What a test sets about the job itself: how far a running job has got,
// its peak and request, and whether it is unusual.
export interface EstimateFor {
  elapsed_seconds?: number;
  remaining_seconds?: number;
  exceeded_history?: boolean;
  peak_mib?: number;
  requested_mib?: number;
  above_usual?: boolean;
}

// estimateFixture is GET /runtime-estimate for a job answered from group
// at the estimate's level: the typical runtime and range are the group's,
// as are its memory figures, and the count above the request is counted
// from the same jobs similarFixture lists.
export function estimateFixture(jobID: string, job: EstimateFor = {}, group: JobGroup = estimateGroup()): RuntimeEstimate {
  const r = group.runtimes;
  const m = group.memory;
  const peaks = groupJobs(group).flatMap((j) => (j.peak_memory_mib === null ? [] : [j.peak_memory_mib]));
  return {
    job_id: jobID,
    available: true,
    estimate_seconds: r.p50,
    p10_seconds: r.p10,
    p90_seconds: r.p90,
    basis: { level: ESTIMATE_LEVEL, sample_count: r.count },
    rough: false,
    elapsed_seconds: job.elapsed_seconds,
    remaining_seconds: job.remaining_seconds,
    exceeded_history: job.exceeded_history ?? false,
    memory: m
      ? {
          sample_count: m.count,
          p10_mib: m.p10,
          p25_mib: m.p25,
          p50_mib: m.p50,
          p75_mib: m.p75,
          p90_mib: m.p90,
          peak_mib: job.peak_mib,
          requested_mib: job.requested_mib,
          above_requested:
            job.requested_mib === undefined ? undefined : peaks.filter((p) => p > job.requested_mib!).length,
          rough: false,
          above_usual: job.above_usual ?? false,
        }
      : undefined,
    model: { trained_through: '2026-10-10T12:00:00Z', jobs_ingested: 5000 },
  };
}
