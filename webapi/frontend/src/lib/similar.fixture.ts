import type { EstimateLevel, SimilarJob, SimilarJobsResponse, UtilizationForJob } from './similar';

// Sample answers for GET /api/v1/jobs/{id}/similar and
// /api/v1/utilization/for-job/{id}, for the component tests, the smoke
// suite and a dev mock. Only type imports, so Node can load it directly.

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

export function similarFixture(
  jobID: string,
  opts: { level?: EstimateLevel; offset?: number; page_size?: number } = {},
): SimilarJobsResponse {
  const level = opts.level ?? 'template';
  const l = LEVELS.find((x) => x.level === level) ?? LEVELS[1];
  const all = jobsFor(level, l.count ?? 0, l.median, l.mem);
  const offset = opts.offset ?? 0;
  const size = Math.min(opts.page_size ?? 50, 200);
  const page = all.slice(offset, offset + size);
  const m = l.median;
  return {
    job_id: jobID,
    level,
    description: l.description,
    estimate_level: 'template',
    levels: [
      { level: 'cluster', description: 'same cluster', applies: false, count: null },
      ...LEVELS.map((x) => ({ level: x.level, description: x.description, applies: true, count: x.count })),
    ],
    window: { days: 30, max_jobs: 500 },
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
