import { expect, test } from '@playwright/test';
import { adminPassword, loginAsAdmin } from './fixtures/login';
import { serverLog } from './fixtures/serverlog';

const password = adminPassword(serverLog());

test('the job watch streams a snapshot then updates as the job runs', async ({ page }) => {
  test.setTimeout(180_000);
  await loginAsAdmin(page, password);

  const submit = await page.request.post('/api/v1/jobs', {
    data: {
      submit_file: [
        'executable = /bin/sleep',
        'arguments = 8',
        'transfer_executable = false',
        'queue 1',
      ].join('\n'),
    },
  });
  expect(submit.status(), await submit.text()).toBeLessThan(400);
  const cluster = (await submit.json()).cluster_id;
  const id = `${cluster}.0`;

  // Consume the stream with EventSource, the way the SPA will.
  const events = await page.evaluate(
    async ({ jobID, ms }) => {
      const seen: { event: string; data: unknown }[] = [];
      const es = new EventSource(`/api/v1/jobs/${jobID}/watch`);
      for (const name of ['snapshot', 'update', 'gone']) {
        es.addEventListener(name, (e) =>
          seen.push({ event: name, data: JSON.parse((e as MessageEvent).data) }),
        );
      }
      await new Promise((r) => setTimeout(r, ms));
      es.close();
      return seen;
    },
    { jobID: id, ms: 45_000 },
  );

  console.log('EVENTS:', JSON.stringify(events, null, 1).slice(0, 900));

  // A snapshot must arrive first and carry the projection.
  expect(events.length, 'expected at least a snapshot').toBeGreaterThan(0);
  expect(events[0].event).toBe('snapshot');
  expect(events[0].data).toHaveProperty('JobStatus');

  // And at least one update: the job goes idle -> running -> completed
  // inside the window, so a stream that only ever sends the snapshot is
  // not watching anything.
  const updates = events.filter((e) => e.event === 'update');
  expect(updates.length, `expected updates, saw: ${JSON.stringify(events)}`).toBeGreaterThan(0);

  // Updates carry only what changed, not the whole projection.
  const keys = Object.keys(updates[0].data as Record<string, unknown>);
  expect(keys.length, 'an update should be a delta').toBeLessThan(12);
});
