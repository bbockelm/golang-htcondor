import { expect, test, type Page } from '@playwright/test';

import { installApiFixtures, installJobsProgressFixtures } from './fixtures/api';

// The /jobs Progress column and the two single-status views, against a
// mocked queue (see installJobsProgressFixtures for what is in it).

// The row for one batch, found by its name.
function batchRow(page: Page, name: string) {
  return page.getByRole('row').filter({ hasText: name }).first();
}

// A status chip in the strip above the table.
function chip(page: Page, label: string) {
  return page.getByRole('button', { name: new RegExp(`^${label}\\b`) }).first();
}

test.describe('progress', () => {
  test.beforeEach(async ({ page }) => {
    await installApiFixtures(page);
    await installJobsProgressFixtures(page);
  });

  test('counts finished jobs that have left the queue', async ({ page }) => {
    await page.goto('/jobs');
    await expect(page.getByRole('button', { name: /Progress/ })).toBeVisible();
    // 100 submitted, 12 still queued.
    await expect(batchRow(page, 'smoke-sweep')).toContainText('88 / 100');
    // A factory counts only the jobs it has queued: 40 so far, 10 here.
    await expect(batchRow(page, 'smoke-factory')).toContainText('30 / 1,000');
    // A DAG counts nodes, from its root job.
    const dag = batchRow(page, 'smoke-pipeline.dag');
    await expect(dag).toContainText('17 / 40');
    await expect(dag).toContainText('3 failed');
  });

  test('the held view shows why, and leaves progress alone', async ({ page }) => {
    await page.goto('/jobs');
    await expect(batchRow(page, 'smoke-sweep')).toContainText('88 / 100');
    await chip(page, 'Held').click();
    await expect(page.getByRole('button', { name: /Hold reason/ })).toBeVisible();
    await expect(page.getByRole('button', { name: /Command/ })).toHaveCount(0);
    const sweep = batchRow(page, 'smoke-sweep');
    // The problem, without the "Error from <slot>:" in front of it.
    await expect(sweep).toContainText('memory usage exceeded request_memory');
    await expect(sweep).not.toContainText('Error from');
    await expect(sweep).toContainText('×2');
    await expect(sweep).toContainText('+1 other reason');
    // Hiding the running and idle jobs does not make the batch done.
    await expect(sweep).toContainText('88 / 100');
  });

  test('the running view shows memory and CPU against the request', async ({ page }) => {
    await page.goto('/jobs');
    await chip(page, 'Running').click();
    await expect(page.getByRole('button', { name: /Memory \(peak\)/ })).toBeVisible();
    await expect(page.getByRole('button', { name: /CPU \(recent\)/ })).toBeVisible();
    const sweep = batchRow(page, 'smoke-sweep');
    await expect(sweep).toContainText(/median .* · max 2\.3 of 2\.0 GB/);
    await expect(sweep).toContainText(/mean [\d.]+ of 1 core/);
    await sweep.click();
    // The job over its request, flagged with the percentage...
    await expect(page.getByText('2.3 / 2.0 GB · 115%')).toBeVisible();
    // ...and the one that has not reported, which is not a zero.
    const unreported = page.getByRole('row').filter({ hasText: '500.4' });
    await expect(unreported.getByText('not reported yet')).toHaveCount(2);
  });
});

test('a partial listing still shows the exact count', async ({ page }) => {
  const exactQueries: string[] = [];
  await installApiFixtures(page);
  await installJobsProgressFixtures(page, { partial: true, exactQueries });
  await page.goto('/jobs');
  // The listing holds 10 of the sweep's 12 queued jobs; counting those
  // would say 90. The narrow query counts all twelve.
  await expect(batchRow(page, 'smoke-sweep')).toContainText('88 / 100');
  expect(exactQueries.some((c) => /member\(ClusterId, \{[^}]*\b500\b/.test(c))).toBe(true);
});
