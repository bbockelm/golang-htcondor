import { expect, test, type Page } from '@playwright/test';
import path from 'node:path';

import { installApiFixtures } from './fixtures/api';
import { SMOKE_NOW } from './fixtures/clock';
import { forJobFixture } from '../src/lib/similar.fixture';
import { routeJobGroup } from './fixtures/estimates';

// From one job back to the groups it belongs to: the Related row at the
// top of its page, and the similar jobs its runtime estimate is based on.

const startedRecently = SMOKE_NOW - 1800;

const runningAd = {
  ClusterId: 81291,
  ProcId: 4,
  JobStatus: 2,
  JobUniverse: 5,
  Owner: 'e2e',
  Cmd: '/home/e2e/run_blast.sh',
  Args: 'chunk-0004.fa',
  JobBatchName: 'blast-search',
  QDate: startedRecently - 120,
  JobStartDate: startedRecently,
  RequestMemory: 2048,
  ResidentSetSize_RAW: 1536 * 1024,
};

// The static export has one page per route; /jobs/<id> is served by the
// /jobs/_ placeholder, as in render.smoke.spec.ts.
async function openJobPage(page: Page, id: string, ad: Record<string, unknown>) {
  const placeholder = path.join(__dirname, '..', 'out', 'jobs', '_.html');
  await page.route(`**/jobs/${id}`, async (route) => {
    if (route.request().resourceType() !== 'document') {
      await route.fallback();
      return;
    }
    await route.fulfill({ path: placeholder, contentType: 'text/html; charset=utf-8' });
  });
  await page.route(`**/api/v1/jobs/${id}`, (route) => route.fulfill({ json: ad }));
  await page.goto(`/jobs/${id}`);
}

test.beforeEach(async ({ page }) => {
  await installApiFixtures(page);
});

test("a job's page links its batch, its workflow and the jobs its estimate is based on", async ({ page }) => {
  await page.route('**/api/v1/utilization/for-job/**', (route) => route.fulfill({ json: forJobFixture('81291.4') }));
  // Half an hour into a typical 45m; peaked at 1.5 GB of the 2 GB requested.
  await routeJobGroup(page, '81291.4', { elapsed_seconds: 1800, remaining_seconds: 900, peak_mib: 1536, requested_mib: 2048 });
  await openJobPage(page, '81291.4', runningAd);

  const related = page.getByTestId('job-related');
  await expect(related.getByRole('link', { name: 'Batch 81291' })).toHaveAttribute('href', '/batches/81291');
  await expect(related.getByTestId('related-utilization')).toHaveAttribute('href', '/utilization?days=30&w=wf-blast');

  // The estimate's basis opens the jobs it names.
  await page.getByTestId('runtime-basis-link').click();
  const similar = page.getByTestId('similar-jobs');
  await expect(similar.getByRole('radio', { checked: true })).toContainText('same command, numbers ignored');
  await expect(similar.getByRole('link').first()).toHaveAttribute('href', /^\/archive\/\d+\.\d+$/);
  // This job on the run times, as the cards draw it: a green fill and dot.
  const runtimePlot = similar.getByTestId('runtime-spread-plot');
  await expect(runtimePlot.locator('[data-part="job-end"]')).toBeVisible();
  await expect(runtimePlot.locator('[data-part="box"]')).toBeVisible();
  // The plot's own key: no request on a run time plot.
  await similar.getByTestId('runtime-spread').getByRole('button', { name: 'How to read' }).click();
  await expect(similar.getByTestId('runtime-spread').getByTestId('range-legend').getByRole('listitem')).toHaveText([
    'Most similar jobs', 'Half of similar jobs', 'Typical', 'This job', 'This job, unusually high',
  ]);
  // Under the run times, the same group's peak memory: this job's peak
  // so far and its request on the same axis.
  const memory = similar.getByTestId('memory-spread');
  await expect(memory.locator('[data-part="job-end"]')).toBeVisible();
  await expect(memory.locator('[data-part="ref"]')).toBeVisible();
  await expect(memory.getByText('Requested', { exact: true })).toBeVisible();
  await expect(memory).toContainText('Half of these 36 jobs peaked at 1 GB to 1.3 GB (typically 1.2 GB); 9 in 10 stayed under 1.5 GB. This job so far: 1.5 GB. Requested: 2 GB.');
  await expect(similar.getByRole('columnheader', { name: 'Peak memory' })).toBeVisible();

  // Wider: every job running the same program.
  await similar.getByRole('radio', { name: /same program/ }).click();
  await expect(similar.getByRole('radio', { checked: true })).toContainText('same program, any arguments · 150');
  await expect(similar.getByRole('button', { name: /Show more \(50 of 150\)/ })).toBeVisible();

  // The widest: all of the owner's jobs of the kind, never anyone else's.
  await similar.getByRole('radio', { name: /all your jobs of this kind/ }).click();
  await expect(similar.getByRole('radio', { checked: true })).toContainText('all your jobs of this kind · 400');
  await expect(similar.getByRole('radio', { name: /access point/ })).toHaveCount(0);
});

test('a job whose workflow has nothing to show offers no workflow link', async ({ page }) => {
  // The default fixture: has_history false.
  await openJobPage(page, '81291.4', runningAd);
  const related = page.getByTestId('job-related');
  await expect(related.getByRole('button', { name: 'Similar jobs' })).toBeVisible();
  await expect(related.getByTestId('related-utilization')).toHaveCount(0);
  // The Related row's own way in.
  await related.getByRole('button', { name: 'Similar jobs' }).click();
  await expect(page.getByTestId('similar-jobs')).toBeVisible();
});

// A DAG node's batch is its whole DAG, named by the root DAGMan cluster
// the way the /jobs table names it.
test("a DAG node's page links its DAG's batch", async ({ page }) => {
  await page.route('**/api/v1/utilization/for-job/**', (route) => route.fulfill({ status: 404, json: {} }));
  await openJobPage(page, '81295.0', {
    ...runningAd,
    ClusterId: 81295,
    ProcId: 0,
    JobBatchName: 'pipeline.dag+81290',
    DAGManJobId: 81293,
  });
  await expect(page.getByTestId('job-related').getByRole('link', { name: 'Batch 81290' })).toHaveAttribute(
    'href',
    '/batches/81290',
  );
});
