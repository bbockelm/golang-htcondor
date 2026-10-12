import { expect, test, type Page } from '@playwright/test';
import path from 'node:path';

import { installApiFixtures } from './fixtures/api';
import { SMOKE_NOW } from './fixtures/clock';
import { forJobFixture } from '../src/lib/similar.fixture';

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
  await page.route('**/api/v1/jobs/81291.4/runtime-estimate', (route) =>
    route.fulfill({
      json: {
        job_id: '81291.4',
        available: true,
        estimate_seconds: 2700,
        p10_seconds: 1600,
        p90_seconds: 4000,
        basis: { level: 'template', sample_count: 41 },
        elapsed_seconds: 1800,
        remaining_seconds: 900,
        exceeded_history: false,
        model: { jobs_ingested: 5000 },
      },
    }),
  );
  await openJobPage(page, '81291.4', runningAd);

  const related = page.getByTestId('job-related');
  await expect(related.getByRole('link', { name: 'Batch 81291' })).toHaveAttribute('href', /\/jobs\?constraint=ClusterId/);
  await expect(related.getByTestId('related-utilization')).toHaveAttribute('href', '/utilization?days=30&w=wf-blast');

  // The estimate's basis opens the jobs it names.
  await page.getByTestId('runtime-basis-link').click();
  const similar = page.getByTestId('similar-jobs');
  await expect(similar.getByRole('radio', { checked: true })).toContainText('same command, numbers ignored');
  await expect(similar.getByRole('link').first()).toHaveAttribute('href', /^\/archive\/\d+\.\d+$/);
  await expect(similar.getByTestId('spread-mark')).toBeVisible();

  // Wider: every job running the same program.
  await similar.getByRole('radio', { name: /same program/ }).click();
  await expect(similar.getByRole('radio', { checked: true })).toContainText('same program, any arguments · 150');
  await expect(similar.getByRole('button', { name: /Show more \(50 of 150\)/ })).toBeVisible();

  // The whole access point: its spread, not other people's jobs.
  await similar.getByRole('radio', { name: /every job of this kind on this access point/ }).click();
  await expect(similar.getByTestId('aggregate-only')).toBeVisible();
  await expect(similar.locator('table')).toHaveCount(0);
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
