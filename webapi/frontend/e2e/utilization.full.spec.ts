import { expect, test } from '@playwright/test';

import { adminPassword, loginAsAdmin } from './fixtures/login';
import { serverLog } from './fixtures/serverlog';

// The Utilization page against a real access point: jobs that ran show
// up as a workflow, and the workflow opens.
//
// The smoke suite covers every rendering case from a fixture; what only
// a live server can show is that finished jobs actually reach the
// analysis -- the page reads history, so a job that never leaves the
// queue never appears there at all.

const password = adminPassword(serverLog());

// A real negotiation cycle plus four short jobs, bounded so a stuck job
// fails the test instead of hanging it.
const RUN_TIMEOUT_MS = 100_000;

test('finished jobs appear as a workflow on the Utilization page', async ({ page }) => {
  test.setTimeout(RUN_TIMEOUT_MS + 40_000);
  await loginAsAdmin(page, password);

  const batch = `util-e2e-${Date.now().toString(36)}`;
  const submit = await page.request.post('/api/v1/jobs', {
    data: {
      submit_file: [
        'executable = /bin/sleep',
        'arguments = 5',
        // Nothing to upload, so the submit is one step (see
        // lifecycle.full.spec.ts).
        'transfer_executable = false',
        `batch_name = ${batch}`,
        // A remote submission is kept in the queue for days after it
        // completes so its output can be fetched. The analysis reads
        // history, which a job only enters on leaving the queue.
        'leave_in_queue = false',
        'request_memory = 64 MB',
        'queue 4',
      ].join('\n'),
    },
  });
  expect(submit.status(), `submit failed: ${await submit.text()}`).toBeLessThan(400);
  const created = await submit.json();
  const cluster = created.cluster_id ?? created.ClusterId ?? created.cluster;
  expect(cluster).toBeTruthy();

  // Wait until all four are in history as completed.
  const deadline = Date.now() + RUN_TIMEOUT_MS;
  let lastSeen = 'never queried';
  let finished = 0;
  while (Date.now() < deadline) {
    const res = await page.request.get(
      `/api/v1/jobs/archive?owned_by_me=false&constraint=${encodeURIComponent(`ClusterId == ${cluster}`)}`,
    );
    if (res.status() === 200) {
      const ads: Record<string, unknown>[] = (await res.json()).ads ?? [];
      finished = ads.filter((a) => Number(a.JobStatus) === 4).length;
      lastSeen = `${ads.length} in history, ${finished} completed`;
      if (finished === 4) break;
    } else {
      lastSeen = `archive answered ${res.status()}`;
    }
    await page.waitForTimeout(3000);
  }
  expect(finished, `jobs did not all finish (${lastSeen})`).toBe(4);

  await page.goto('/utilization?days=1');
  const row = page.getByRole('row', { name: new RegExp(`^${batch}: 4 jobs`) });
  await expect(row).toBeVisible();
  await expect(row).toContainText('sleep');

  await row.click();
  await expect(page).toHaveURL(/[?&]w=/);
  await expect(page.getByRole('heading', { level: 2, name: batch })).toBeVisible();
  await expect(page.getByText('Jobs finished in the last day')).toBeVisible();
});
