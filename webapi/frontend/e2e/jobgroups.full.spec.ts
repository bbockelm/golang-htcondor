import { expect, test, type Page } from '@playwright/test';

import { adminPassword, loginAsAdmin } from './fixtures/login';
import { serverLog } from './fixtures/serverlog';

// From one job to the groups it belongs to, against a real access point:
// six short jobs with the same command and different numbers finish, a
// seventh like them is submitted, and its page links to its workflow and
// lists the six as its similar jobs at the "numbers ignored" level.

const password = adminPassword(serverLog());

const RUN_TIMEOUT_MS = 100_000;

async function submit(page: Page, lines: string[]): Promise<number> {
  const res = await page.request.post('/api/v1/jobs', { data: { submit_file: lines.join('\n') } });
  expect(res.status(), `submit failed: ${await res.text()}`).toBeLessThan(400);
  const created = await res.json();
  const cluster = Number(created.cluster_id ?? created.ClusterId ?? created.cluster);
  expect(cluster).toBeGreaterThan(0);
  return cluster;
}

test("a job's page leads to its workflow and to the finished jobs like it", async ({ page }) => {
  test.setTimeout(RUN_TIMEOUT_MS + 40_000);
  await loginAsAdmin(page, password);

  const batch = `groups-e2e-${Date.now().toString(36)}`;
  const common = [
    'executable = /bin/sleep',
    // Nothing to upload: a one-step submit (see lifecycle.full.spec.ts).
    'transfer_executable = false',
    `batch_name = ${batch}`,
    // History is where finished jobs are looked for.
    'leave_in_queue = false',
    'request_memory = 64 MB',
  ];
  // Six jobs, one command, different numbers: sleep 0 .. sleep 5.
  const done = await submit(page, [...common, 'arguments = $(Process)', 'queue 6']);

  const deadline = Date.now() + RUN_TIMEOUT_MS;
  let finished = 0;
  while (Date.now() < deadline) {
    const res = await page.request.get(
      `/api/v1/jobs/archive?owned_by_me=false&constraint=${encodeURIComponent(`ClusterId == ${done}`)}`,
    );
    if (res.status() === 200) {
      const ads: Record<string, unknown>[] = (await res.json()).ads ?? [];
      finished = ads.filter((a) => Number(a.JobStatus) === 4).length;
      if (finished === 6) break;
    }
    await page.waitForTimeout(3000);
  }
  expect(finished, 'the six jobs did not all finish').toBe(6);

  // A seventh like them, still in the queue while its page is read.
  const next = await submit(page, [...common, 'arguments = 90', 'queue 1']);
  await page.goto(`/jobs/${next}.0`);

  // The Related row: the batch, and the workflow, which now has finished
  // jobs to show.
  const related = page.getByTestId('job-related');
  await expect(related.getByRole('link', { name: `Batch ${next}` })).toBeVisible();
  const workflowLink = related.getByTestId('related-utilization');
  await expect(workflowLink).toBeVisible({ timeout: 20_000 });
  await expect(workflowLink).toHaveAttribute('href', /^\/utilization\?days=30&w=/);

  // The similar jobs, with numbers ignored: the six that finished.
  await related.getByRole('button', { name: 'Similar jobs' }).click();
  const similar = page.getByTestId('similar-jobs');
  await similar.getByRole('radio', { name: /same command, numbers ignored/ }).click();
  await expect(similar.getByRole('radio', { checked: true })).toContainText('same command, numbers ignored');
  // Other tests on the same server run `sleep N` too, so the group may
  // hold more than these six; it must hold all of them.
  const ids = similar.locator('tbody tr td:first-child a');
  await expect(ids.filter({ hasText: new RegExp(`^${done}\\.`) })).toHaveCount(6);
  const listed = await ids.allTextContents();
  for (let p = 0; p < 6; p++) expect(listed).toContain(`${done}.${p}`);

  // And the workflow link opens that workflow.
  await workflowLink.click();
  await expect(page).toHaveURL(/\/utilization\?days=30&w=/);
  await expect(page.getByRole('heading', { level: 2, name: batch })).toBeVisible();
});
