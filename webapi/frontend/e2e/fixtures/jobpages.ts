import path from 'node:path';
import type { Page } from '@playwright/test';

import type { ClassAd } from '../../src/lib/api';
import type { MetricsResponse } from '../../src/lib/metrics';
import { CONTAINER_GPU_REQUIREMENTS } from '../../src/lib/requirements.fixture';
import { SMOKE_NOW } from './clock';

// The job and archive pages' resource sections, against mocked responses.

const MEMORY_RULE = 'ifthenelse(MemoryUsage =!= undefined,max({ 2048,3 * MemoryUsage / 2 }),2048)';
export const ARCHIVE_RUNS = 68;

// A finished job restarted 68 times, whose memory request is a rule over
// its own usage. The ad is as the archive endpoint sends it with
// projection=*: the rule as "/Expr(...)/", usage evaluated, and the
// evaluated requests beside the raw attributes.
export const archivedRestartedJob: ClassAd = {
  ClusterId: 9301,
  ProcId: 0,
  Owner: 'e2e',
  JobStatus: 4,
  JobUniverse: 5,
  ExitCode: 0,
  Cmd: '/home/e2e/bin/simulate',
  QDate: SMOKE_NOW - (ARCHIVE_RUNS + 2) * 3600,
  JobStartDate: SMOKE_NOW - 2 * 3600,
  CompletionDate: SMOKE_NOW - 600,
  RemoteWallClockTime: ARCHIVE_RUNS * 3000,
  NumJobStarts: ARCHIVE_RUNS,
  RequestMemory: `/Expr(${MEMORY_RULE})/`,
  MemoryUsage: 7325,
  ResidentSetSize: 7500000,
  MemoryProvisioned: 11008,
  RequestCpus: 4,
  CpusProvisioned: 4,
  RequestDisk: 6291456,
  DiskProvisioned: 6291456,
  RequestGPUs: 1,
  GPUsProvisioned: 1,
  Requirements: CONTAINER_GPU_REQUIREMENTS,
  evaluated: { RequestMemory: 10987, RequestCpus: 4, RequestDisk: 6291456, RequestGPUs: 1 },
};

// A running job that asked for no GPUs, and holds none.
export const runningNoGpuJob: ClassAd = {
  ClusterId: 9302,
  ProcId: 0,
  Owner: 'e2e',
  JobStatus: 2,
  JobUniverse: 5,
  Cmd: '/home/e2e/bin/train',
  QDate: SMOKE_NOW - 3 * 3600,
  JobCurrentStartDate: SMOKE_NOW - 2 * 3600,
  JobCurrentStartExecutingDate: SMOKE_NOW - 2 * 3600 + 60,
  RequestCpus: 1,
  CpusProvisioned: 1,
  RequestMemory: 2048,
  MemoryProvisioned: 2048,
  MemoryUsage: 900,
  RequestDisk: 1048576,
  RequestGPUs: 0,
  GPUsProvisioned: 0,
};

// job_metrics for the restarted job: two 15-minute samples per run, one run
// an hour, the last finishing as the job did.
export function restartedJobMetrics(): MetricsResponse {
  const rows: string[][] = [];
  for (let run = 1; run <= ARCHIVE_RUNS; run++) {
    const start = SMOKE_NOW - 600 - (ARCHIVE_RUNS - run + 1) * 3600;
    for (let k = 0; k < 2; k++) {
      rows.push(
        [run, start + k * 900, 5000 + run * 30 + k * 200, 3.2, 0, 0, 10987, 4, 6291456, 1].map(String),
      );
    }
  }
  return {
    enabled: true,
    table: 'job_metrics',
    time_attr: 'SampleTime',
    bucket_seconds: 900,
    columns: [
      { name: 'RunInstanceID', kind: 'group' },
      { name: 'SampleTime', kind: 'group', bucket_seconds: 900 },
      { name: 'max_MemoryUsage', kind: 'metric' },
      { name: 'avg_CpuUtil', kind: 'metric' },
      { name: 'max_DiskUsage', kind: 'metric' },
      { name: 'avg_GpuUtil', kind: 'metric' },
      { name: 'max_RequestMemory', kind: 'metric' },
      { name: 'max_RequestCpus', kind: 'metric' },
      { name: 'max_RequestDisk', kind: 'metric' },
      { name: 'max_RequestGpus', kind: 'metric' },
    ],
    rows,
  };
}

// placeholderRoute answers /<route>/<id> with the static export's
// placeholder page, as the Go SPA handler does in production.
async function placeholderRoute(page: Page, route: 'jobs' | 'archive', id: string) {
  const placeholder = path.join(__dirname, '..', '..', 'out', route, '_.html');
  await page.route(`**/${route}/${id}`, async (r) => {
    if (r.request().resourceType() !== 'document') {
      await r.fallback();
      return;
    }
    await r.fulfill({ path: placeholder, contentType: 'text/html; charset=utf-8' });
  });
}

export async function openArchivedRestartedJob(page: Page) {
  await placeholderRoute(page, 'archive', '9301.0');
  await page.route('**/api/v1/jobs/archive**', (r) => r.fulfill({ json: { ads: [archivedRestartedJob] } }));
  await page.route('**/api/v1/metrics/job_metrics?**', (r) => r.fulfill({ json: restartedJobMetrics() }));
  await page.goto('/archive/9301.0');
}

export async function openRunningNoGpuJob(page: Page) {
  await placeholderRoute(page, 'jobs', '9302.0');
  await page.route('**/api/v1/jobs/9302.0', (r) => r.fulfill({ json: runningNoGpuJob }));
  await page.goto('/jobs/9302.0');
}
