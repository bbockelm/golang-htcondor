import { expect, test } from '@playwright/test';
import { adminPassword, loginAsAdmin } from './fixtures/login';
import { serverLog } from './fixtures/serverlog';

const password = adminPassword(serverLog());

// The reported symptom: a running session sat on "Transferring input"
// forever. The page leaves that state when JobCurrentStartExecutingDate
// appears, and the projection did not carry it -- so the stream was
// healthy and delivering the wrong columns.
test('the stream carries the attribute that ends "transferring input"', async ({ page }) => {
  test.setTimeout(180_000);
  await loginAsAdmin(page, password);

  const submit = await page.request.post('/api/v1/jobs', {
    data: {
      submit_file: [
        'executable = /bin/sleep',
        'arguments = 60',
        'transfer_executable = false',
        'queue 1',
      ].join('\n'),
    },
  });
  expect(submit.status(), await submit.text()).toBeLessThan(400);
  const id = `${(await submit.json()).cluster_id}.0`;

  const events = await page.evaluate(
    async ({ jobID, ms }) => {
      const seen: Record<string, unknown>[] = [];
      // No attrs param: this asserts the SERVER default is sufficient,
      // which is the half a client-side list cannot cover.
      const es = new EventSource(`/api/v1/jobs/${jobID}/watch`);
      for (const n of ['snapshot', 'update']) {
        es.addEventListener(n, (e) => seen.push(JSON.parse((e as MessageEvent).data)));
      }
      await new Promise((r) => setTimeout(r, ms));
      es.close();
      return seen;
    },
    { jobID: id, ms: 40_000 },
  );

  const merged: Record<string, unknown> = {};
  for (const e of events) Object.assign(merged, e);

  expect(Number(merged.JobStatus), `never reached running: ${JSON.stringify(events)}`).toBe(2);
  expect(
    merged.JobCurrentStartExecutingDate,
    `the stream never carried JobCurrentStartExecutingDate, so the page cannot leave ` +
      `"transferring input": ${JSON.stringify(events)}`,
  ).toBeTruthy();

  await page.request.delete(`/api/v1/jobs/${id}`);
});
