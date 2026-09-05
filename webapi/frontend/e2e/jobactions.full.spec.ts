import { expect, test } from '@playwright/test';

import { adminPassword, loginAsAdmin } from './fixtures/login';
import { serverLog } from './fixtures/serverlog';

// Job actions land in the schedd, not just in the React list.
//
// #278 changed how remove/hold/release are confirmed in the UI. Nothing
// checked that the action itself takes effect: a row disappearing from
// a client-side list looks the same whether the schedd acted or not.

const password = adminPassword(
  serverLog(),
);

type Ad = Record<string, unknown>;

async function queue(page: import('@playwright/test').Page): Promise<Ad[]> {
  const res = await page.request.get('/api/v1/jobs?owned_by_me=false&limit=*');
  expect(res.status()).toBe(200);
  return (await res.json()).jobs ?? [];
}

async function submit(
  page: import('@playwright/test').Page,
  extra: string[] = [],
  count = 1,
): Promise<number> {
  const res = await page.request.post('/api/v1/jobs', {
    data: {
      submit_file: [
        'executable = /bin/sleep',
        // Short on purpose. The demo pool has very few slots, so a
        // long-running leftover from a failed test starves every test
        // that follows it -- which is how this suite first "found" a
        // job that would not run.
        'arguments = 45',
        // Keeps this about the action under test: without it the job
        // waits on an input upload and is held for an unrelated reason.
        'transfer_executable = false',
        ...extra,
        `queue ${count}`,
      ].join('\n'),
    },
  });
  expect(res.status(), `submit failed: ${await res.text()}`).toBeLessThan(400);
  const b = await res.json();
  return b.cluster_id ?? b.ClusterId ?? b.cluster;
}

function ids(ads: Ad[]): string[] {
  return ads.map((j) => `${j.ClusterId}.${j.ProcId}`);
}

test('removing a job takes it out of the queue and into the archive', async ({ page }) => {
  await loginAsAdmin(page, password);
  const cluster = await submit(page);
  const id = `${cluster}.0`;

  expect(ids(await queue(page)), 'the new job should be queued').toContain(id);

  const del = await page.request.delete(`/api/v1/jobs/${id}`);
  expect(del.status(), `remove failed: ${await del.text()}`).toBe(200);

  await expect
    .poll(async () => ids(await queue(page)), { timeout: 30_000 })
    .not.toContain(id);

  // Gone from the queue is not the same as removed: the archive is
  // where a removed job is supposed to end up, with status 3.
  const arch = await page.request.get(
    `/api/v1/jobs/archive?owned_by_me=false&limit=50&constraint=${encodeURIComponent(`ClusterId == ${cluster}`)}`,
  );
  expect(arch.status()).toBe(200);
  const ads: Ad[] = (await arch.json()).ads ?? [];
  const row = ads.find((a) => Number(a.ClusterId) === cluster);
  expect(row, `removed job ${id} should be in the archive`).toBeTruthy();
  expect(Number(row!.JobStatus), 'archived as Removed (3)').toBe(3);
});

test('holding a job holds it, and releasing it lets it run again', async ({ page }) => {
  await loginAsAdmin(page, password);
  const cluster = await submit(page);
  const id = `${cluster}.0`;

  // Wait until the job is out of the spool hold before holding it.
  // Every submission passes through JobStatus 5 / code 16 for a moment,
  // and holding an already-held job affects zero jobs.
  await expect
    .poll(
      async () => {
        const j = (await queue(page)).find((a) => `${a.ClusterId}.${a.ProcId}` === id);
        return j ? Number(j.JobStatus) : -1;
      },
      { timeout: 30_000 },
    )
    .not.toBe(5);

  const hold = await page.request.post(`/api/v1/jobs/${id}/hold`, {
    data: { reason: 'e2e' },
  });
  expect(hold.status(), `hold failed: ${await hold.text()}`).toBeLessThan(400);

  // Status 5 with a hold reason that is not the spool hold: this must be
  // our hold, not the transient one every submission passes through.
  await expect
    .poll(
      async () => {
        const j = (await queue(page)).find((a) => `${a.ClusterId}.${a.ProcId}` === id);
        return j ? `${j.JobStatus}/${Number(j.HoldReasonCode ?? 0)}` : 'absent';
      },
      { timeout: 30_000 },
    )
    .toBe('5/1');

  const rel = await page.request.post(`/api/v1/jobs/${id}/release`, { data: {} });
  expect(rel.status(), `release failed: ${await rel.text()}`).toBeLessThan(400);

  await expect
    .poll(
      async () => {
        const j = (await queue(page)).find((a) => `${a.ClusterId}.${a.ProcId}` === id);
        return j ? Number(j.JobStatus) : -1;
      },
      { timeout: 30_000 },
    )
    .not.toBe(5);

  // Assert the cleanup rather than firing and forgetting: a silent
  // failure here leaves the job holding a slot for the rest of the run.
  const cleanup = await page.request.delete(`/api/v1/jobs/${id}`);
  expect(cleanup.status(), `cleanup remove failed: ${await cleanup.text()}`).toBe(200);
});

test('removing by constraint removes every job it matches', async ({ page }) => {
  await loginAsAdmin(page, password);
  const cluster = await submit(page, [], 3);

  await expect
    .poll(async () => (await queue(page)).filter((j) => Number(j.ClusterId) === cluster).length, {
      timeout: 30_000,
    })
    .toBe(3);

  const del = await page.request.delete('/api/v1/jobs', {
    data: { constraint: `ClusterId == ${cluster}`, reason: 'e2e batch' },
  });
  expect(del.status(), `constraint remove failed: ${await del.text()}`).toBe(200);

  // All three, not just the first: a loop that removes one and reports
  // success would pass a single-job check.
  await expect
    .poll(async () => (await queue(page)).filter((j) => Number(j.ClusterId) === cluster).length, {
      timeout: 30_000,
    })
    .toBe(0);
});
