import { expect, test, type Page } from '@playwright/test';
import path from 'node:path';

import { installApiFixtures } from './fixtures/api';
import { SMOKE_NOW } from './fixtures/clock';

// /batches/<id>: one batch or DAG in one place. The fixtures are in
// src/lib/batchPage.fixture.ts and answer through installApiFixtures.

// The static export has one page for the route; the Go server serves it
// for every /batches/<id>, and so does this.
async function openBatchPage(page: Page, id: string | number) {
  const placeholder = path.join(__dirname, '..', 'out', 'batches', '_.html');
  await page.route(/\/batches\/\d+$/, async (route) => {
    if (route.request().resourceType() !== 'document') {
      await route.fallback();
      return;
    }
    await route.fulfill({ path: placeholder, contentType: 'text/html; charset=utf-8' });
  });
  await page.goto(`/batches/${id}`);
}

// The live usage section reads the batch's jobs from the queue listing.
async function routeQueueAds(page: Page) {
  await page.route('**/api/v1/jobs?*', async (route) => {
    const q = new URL(route.request().url()).searchParams;
    if (!q.get('constraint')?.includes('blast-run')) {
      await route.fallback();
      return;
    }
    const ads = Array.from({ length: 12 }, (_, i) => ({
      ClusterId: 301,
      ProcId: i,
      JobStatus: 2,
      RequestCpus: 4,
      RequestMemory: 4096,
      CpusProvisioned: 4,
      MemoryProvisioned: 4096,
      MemoryUsage: 1100 + i * 40,
      ResidentSetSize_RAW: (1100 + i * 40) * 1024,
      CurrentResidentSetSize: (1000 + i * 40) * 1024,
      RemoteUserCpu: 3.2 * 1800,
      JobCurrentStartDate: SMOKE_NOW - 1800,
      JobStartDate: SMOKE_NOW - 1800,
      LastJobStatus: 1,
    })).concat(
      Array.from({ length: 30 }, (_, i) => ({
        ClusterId: 301,
        ProcId: 12 + i,
        JobStatus: 1,
        RequestCpus: 4,
        RequestMemory: 4096,
      })) as never[],
    );
    await route.fulfill({ json: { jobs: ads, has_more: false } });
  });
}

// Estimates for the batch's waiting and running jobs, as the fixture
// rows have them: the running ones started 20m, 25m, ... ago.
async function routeEstimates(page: Page, asked: string[][]) {
  await page.route('**/api/v1/jobs/runtime-estimates', (route) => {
    const ids = (route.request().postDataJSON() as { jobs: string[] }).jobs;
    asked.push(ids);
    const estimates: Record<string, object> = {};
    for (const id of ids) {
      const proc = Number(id.split('.')[1]);
      const base = { available: true, estimate_seconds: 2700, p10_seconds: 1800, p90_seconds: 4200, rough: false, exceeded_history: false };
      if (proc < 12) {
        const elapsed = 1200 + proc * 300;
        estimates[id] = { ...base, elapsed_seconds: elapsed, remaining_seconds: Math.max(300, 2700 - elapsed) };
      } else estimates[id] = base;
    }
    return route.fulfill({ json: { available: true, estimates, model: { jobs_ingested: 5000 } } });
  });
}

const shots = process.env.BATCH_SHOTS;
async function shot(page: Page, name: string) {
  if (!shots) return;
  await page.screenshot({ path: path.join(shots, `b-${name}.png`), fullPage: true });
  await page.evaluate(() => window.scrollTo(0, 0));
  await page.screenshot({ path: path.join(shots, `b-${name}-top.png`) });
}

test.beforeEach(async ({ page }) => {
  await installApiFixtures(page);
});

test('a batch in progress: progress, outcomes, holds, resources and its jobs', async ({ page }) => {
  await routeQueueAds(page);
  const asked: string[][] = [];
  await routeEstimates(page, asked);
  await openBatchPage(page, 300);

  await expect(page.getByRole('heading', { level: 1, name: 'blast-run' })).toBeVisible();
  await expect(page.getByTestId('batch-time-left')).toBeVisible();
  // Every running and waiting job, running first; never the held ones.
  expect(asked[0]).toHaveLength(42);
  expect(asked[0][0]).toBe('301.0');
  expect(asked[0]).not.toContain('301.42');
  const progress = page.getByTestId('batch-progress');
  await expect(progress).toContainText('55 of 100 jobs done');
  await expect(progress.getByTestId('live-counts')).toContainText('12 Running');
  await expect(page.getByTestId('batch-actions').getByRole('button', { name: 'Remove batch' })).toBeVisible();
  await expect(page.getByTestId('batch-actions').getByRole('button', { name: 'Release 3 held' })).toBeVisible();

  const outcomes = page.getByTestId('batch-outcomes');
  await expect(outcomes).toContainText('50 succeeded');
  await expect(outcomes.getByTestId('outcomes')).toContainText('3 · exit code 1');
  await expect(outcomes).toContainText('Typically 45m');

  const holds = page.getByTestId('batch-holds');
  await expect(holds).toContainText('Memory limit exceeded');
  await expect(holds.getByRole('link', { name: '301.4' })).toHaveAttribute('href', '/jobs/301.4');
  await expect(holds).toContainText('Job has gone over cgroup memory limit of 4096 megabytes.');
  expect(await holds.textContent()).not.toContain('*');

  await expect(page.getByTestId('batch-workflows').getByRole('link', { name: 'blastn' })).toHaveAttribute(
    'href',
    '/utilization?w=wf-blast&days=30',
  );

  const jobs = page.getByTestId('batch-jobs');
  await expect(jobs.getByTestId('batch-job-row')).toHaveCount(50);
  await jobs.getByRole('button', { name: 'Show more (50 of 100)' }).click();
  await expect(jobs.getByTestId('batch-job-row')).toHaveCount(100);
  await jobs.getByRole('button', { name: /^Finished/ }).click();
  await expect(jobs.getByTestId('batch-job-row')).toHaveCount(50);
  await expect(jobs.getByTestId('batch-job-row').first()).toContainText('Completed');
  await jobs.getByRole('button', { name: /^Held/ }).click();
  await expect(jobs.getByTestId('batch-job-row')).toHaveCount(3);
  await expect(jobs.getByTestId('batch-job-row').first().getByRole('link')).toHaveAttribute('href', '/jobs/301.42');
  await jobs.getByRole('button', { name: /^All/ }).click();
  await shot(page, 'live-desktop');
});

test('a link from any cluster of the batch moves to the batch id', async ({ page }) => {
  await openBatchPage(page, 301);
  await expect(page).toHaveURL(/\/batches\/300$/);
  await expect(page.getByRole('heading', { level: 1, name: 'blast-run' })).toBeVisible();
});

test('a DAG shows its nodes and its graph panel', async ({ page }) => {
  await openBatchPage(page, 500);
  await expect(page.getByText('DAG', { exact: true })).toBeVisible();
  const dag = page.getByTestId('batch-dag');
  await expect(dag.getByTestId('dag-nodes')).toContainText('3 done');
  await expect(dag.getByTestId('dag-nodes')).toContainText('2 waiting on parents');
  await expect(dag.getByTestId('workflow-graph-panel')).toBeVisible();
  await expect(page.getByTestId('batch-progress')).toContainText('3 of 8 nodes done');
  await expect(page.getByTestId('batch-jobs').getByRole('columnheader', { name: 'Node' })).toBeVisible();
  await shot(page, 'dag-desktop');
});

test('a finished batch has no actions and lists its finished jobs', async ({ page }) => {
  await openBatchPage(page, 410);
  await expect(page.getByTestId('batch-progress')).toContainText('20 of 20 jobs done');
  await expect(page.getByTestId('batch-actions')).toHaveCount(0);
  await expect(page.getByTestId('batch-jobs').getByTestId('batch-job-row')).toHaveCount(20);
  await shot(page, 'finished-desktop');
});

test('an unknown batch says so', async ({ page }) => {
  await openBatchPage(page, 999);
  await expect(page.getByTestId('batch-error')).toContainText('No batch with this id is visible to you');
});

test.describe('on a phone', () => {
  test.use({ viewport: { width: 390, height: 844 } });

  test('jobs are compact entries and nothing scrolls sideways', async ({ page }) => {
    await routeQueueAds(page);
    await openBatchPage(page, 300);
    const cards = page.getByTestId('batch-job-card');
    await expect(cards.first()).toBeVisible();
    await expect(page.getByTestId('batch-job-row')).toHaveCount(0);
    await expect(cards.first().getByRole('link')).toHaveAttribute('href', '/jobs/301.0');
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
    expect(overflow).toBeLessThanOrEqual(0);
    await shot(page, 'live-390');
  });

  test('a DAG fits too', async ({ page }) => {
    await openBatchPage(page, 500);
    await expect(page.getByTestId('batch-job-card').first()).toBeVisible();
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
    expect(overflow).toBeLessThanOrEqual(0);
    await shot(page, 'dag-390');
  });
});

test.describe('on a tablet', () => {
  test.use({ viewport: { width: 768, height: 1024 } });

  test('the page fits', async ({ page }) => {
    await routeQueueAds(page);
    await openBatchPage(page, 300);
    await expect(page.getByTestId('batch-job-card').first()).toBeVisible();
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
    expect(overflow).toBeLessThanOrEqual(0);
    await shot(page, 'live-768');
  });
});
