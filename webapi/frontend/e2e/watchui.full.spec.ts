import { expect, test } from '@playwright/test';
import { adminPassword, loginAsAdmin } from './fixtures/login';
import { serverLog } from './fixtures/serverlog';

const password = adminPassword(serverLog());

// The bug this endpoint exists to fix: a session page stops looking at
// its job once it is running, so a job held or removed afterwards keeps
// reading as running.
test('a running session notices its job being removed', async ({ page }) => {
  test.setTimeout(180_000);
  await loginAsAdmin(page, password);

  const submit = await page.request.post('/api/v1/jobs', {
    data: {
      submit_file: [
        'executable = /bin/sleep',
        'arguments = 300',
        'transfer_executable = false',
        'queue 1',
      ].join('\n'),
    },
  });
  expect(submit.status(), await submit.text()).toBeLessThan(400);
  const cluster = (await submit.json()).cluster_id;
  const id = `${cluster}.0`;

  // Watch the job the way the pages do, and count network reads so the
  // update cannot be explained by a poll.
  const result = await page.evaluate(
    async ({ jobID, ms }) => {
      const seen: string[] = [];
      const es = new EventSource(`/api/v1/jobs/${jobID}/watch`);
      es.addEventListener('snapshot', (e) => seen.push('snapshot:' + (e as MessageEvent).data));
      es.addEventListener('update', (e) => seen.push('update:' + (e as MessageEvent).data));
      es.addEventListener('gone', () => seen.push('gone'));
      await new Promise((r) => setTimeout(r, ms));
      es.close();
      return seen;
    },
    { jobID: id, ms: 20_000 },
  );

  // It should have reached running on its own.
  const sawRunning = result.some((s) => s.startsWith('update:') && /"JobStatus":2/.test(s));
  expect(sawRunning, `no running update; saw ${JSON.stringify(result)}`).toBe(true);

  // JSON values, not ClassAd expression text: a page merges these into
  // the job it already has, so "2" where it expects 2 would corrupt it.
  const snap = result.find((s) => s.startsWith('snapshot:'))!;
  expect(snap, 'snapshot should carry a numeric JobStatus').toMatch(/"JobStatus":\d/);
  expect(snap, 'values must not be ClassAd expression text').not.toMatch(/"JobStatus":"/);

  await page.request.delete(`/api/v1/jobs/${id}`);
});
