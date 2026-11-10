import { expect, test } from '@playwright/test';

import { adminPassword, loginAsAdmin } from './fixtures/login';
import { serverLog } from './fixtures/serverlog';

// The /jobs Progress column and Held view against a real schedd.
//
// The smoke suite covers the arithmetic against made-up ads; this is the
// part only a real queue can check: that the schedd really hands back
// TotalSubmitProcs on a REST-submitted cluster, and what a real
// transfer-failure hold message looks like once the view has tidied it.

const password = adminPassword(serverLog());

// One negotiation cycle (~20s) to match, a moment for the shadow to fail
// the transfer, and slack.
const HOLD_TIMEOUT_MS = 90_000;

test('a held batch shows its progress and its hold reason', async ({ page }) => {
  test.setTimeout(HOLD_TIMEOUT_MS + 60_000);
  await loginAsAdmin(page, password);

  const name = `e2e-progress-${Date.now()}`;
  const submit = await page.request.post('/api/v1/jobs', {
    data: {
      submit_file: [
        'executable = /bin/true',
        'transfer_executable = false',
        'should_transfer_files = YES',
        // A file that is not there: input transfer fails and holds every
        // job, which is the hold this test reads.
        `transfer_input_files = /nonexistent/${name}/input.dat`,
        `batch_name = ${name}`,
        'queue 3',
      ].join('\n'),
    },
  });
  expect(submit.status(), `submit failed: ${await submit.text()}`).toBeLessThan(400);
  const created = await submit.json();
  const cluster = created.cluster_id ?? created.ClusterId ?? created.cluster;
  expect(cluster).toBeTruthy();

  try {
    // Any transfer_input_files makes the submission wait for an input
    // upload (HoldReasonCode 16). Spool an empty tar for the whole
    // cluster to release it; the missing file is not in it, so the jobs
    // get matched and then fail to transfer it.
    const spool = await page.request.put(`/api/v1/jobs/${cluster}/input`, {
      headers: { 'Content-Type': 'application/x-tar' },
      // An empty tar archive is two 512-byte zero blocks.
      data: Buffer.alloc(1024),
    });
    expect(spool.status(), `input spool failed: ${await spool.text()}`).toBeLessThan(400);

    // All three held for the transfer, not the transient spool hold
    // (code 16) every submission passes through.
    await expect
      .poll(
        async () => {
          const r = await page.request.get(
            `/api/v1/jobs?owned_by_me=false&limit=*&constraint=${encodeURIComponent(`ClusterId == ${cluster}`)}`,
          );
          const jobs: Record<string, unknown>[] = (await r.json()).jobs ?? [];
          return jobs.filter((j) => Number(j.JobStatus) === 5 && Number(j.HoldReasonCode) !== 16)
            .length;
        },
        { timeout: HOLD_TIMEOUT_MS, intervals: [3000] },
      )
      .toBe(3);

    await page.goto('/jobs');
    const row = page.getByRole('row').filter({ hasText: name }).first();
    // Three submitted, three still in the queue: none done.
    await expect(row).toContainText('0 / 3');

    await page.getByRole('button', { name: /^Held\b/ }).first().click();
    await expect(page.getByRole('button', { name: /Hold reason/ })).toBeVisible();
    // The cell leads with the problem; the message's own text, not a
    // label the UI made up.
    const reason = row.locator('[title*="Transfer input files failure"]').first();
    await expect(reason).toHaveText(/^Transfer input files failure/);
    // Holding them did not make them look done.
    await expect(row).toContainText('0 / 3');
  } finally {
    await page.request.delete('/api/v1/jobs', {
      data: { constraint: `ClusterId == ${cluster}`, reason: 'e2e cleanup' },
    });
  }
});
