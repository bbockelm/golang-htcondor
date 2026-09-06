import { expect, test } from '@playwright/test';
import { adminPassword, loginAsAdmin } from './fixtures/login';
import { serverLog } from './fixtures/serverlog';

const password = adminPassword(serverLog());

// Holding a job that is already held affected zero jobs and answered
// 500 "action failed: result=0". The schedd said why; the handler threw
// it away. Racing the spool window on a fresh submission is enough to
// hit it, so an operator saw a server error for a benign condition --
// and could not tell it from a schedd that was actually broken.
test('holding an already-held job is a conflict, not a server error', async ({ page }) => {
  test.setTimeout(120_000);
  await loginAsAdmin(page, password);

  const submit = await page.request.post('/api/v1/jobs', {
    data: {
      submit_file: [
        'executable = /bin/sleep',
        'arguments = 120',
        'transfer_executable = false',
        'queue 1',
      ].join('\n'),
    },
  });
  expect(submit.status(), await submit.text()).toBeLessThan(400);
  const id = `${(await submit.json()).cluster_id}.0`;

  // Out of the transient spool hold first, so the hold under test is
  // ours rather than the one every submission passes through.
  await expect
    .poll(
      async () => {
        const r = await page.request.get(`/api/v1/jobs?owned_by_me=false&limit=*`);
        const j = ((await r.json()).jobs ?? []).find(
          (a: Record<string, unknown>) => `${a.ClusterId}.${a.ProcId}` === id,
        );
        return j ? Number(j.JobStatus) : -1;
      },
      { timeout: 30_000 },
    )
    .not.toBe(5);

  const first = await page.request.post(`/api/v1/jobs/${id}/hold`, { data: { reason: 'e2e' } });
  expect(first.status(), `first hold failed: ${await first.text()}`).toBeLessThan(400);

  // The same hold again: zero jobs affected, and the schedd knows why.
  const second = await page.request.post(`/api/v1/jobs/${id}/hold`, { data: { reason: 'e2e' } });
  const body = await second.text();
  expect(second.status(), `expected a 4xx conflict, got ${second.status()}: ${body}`).toBe(409);
  expect(second.status(), 'must not be reported as a server fault').toBeLessThan(500);

  await page.request.delete(`/api/v1/jobs/${id}`);
});
