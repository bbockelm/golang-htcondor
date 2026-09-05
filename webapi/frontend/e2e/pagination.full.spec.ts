import { readFileSync } from 'node:fs';

import { expect, test } from '@playwright/test';

import { adminPassword, loginAsAdmin } from './fixtures/login';

// Paging, and the honesty of a truncated answer.
//
// Two different contracts, because the two listings differ:
//
//   /api/v1/jobs      a live schedd has no cursor. When the answer is
//                     truncated the server must SAY so, because a
//                     silently short list is indistinguishable from a
//                     complete one.
//   /api/v1/jobs/archive  keyset cursor on (cluster, proc). Paging must
//                     not drop or repeat records.

const password = adminPassword(
  readFileSync(process.env.E2E_SERVER_LOG ?? '/tmp/e2e-server.log', 'utf8'),
);

type Ad = Record<string, unknown>;

async function submitN(page: import('@playwright/test').Page, n: number): Promise<number> {
  const res = await page.request.post('/api/v1/jobs', {
    data: {
      submit_file: [
        'executable = /bin/true',
        'transfer_executable = false',
        `queue ${n}`,
      ].join('\n'),
    },
  });
  expect(res.status(), `submit failed: ${await res.text()}`).toBeLessThan(400);
  const b = await res.json();
  return b.cluster_id ?? b.ClusterId ?? b.cluster;
}

test('a truncated job listing admits that it is truncated', async ({ page }) => {
  await loginAsAdmin(page, password);
  await submitN(page, 3);

  const res = await page.request.get('/api/v1/jobs?owned_by_me=false&limit=1');
  expect(res.status()).toBe(200);
  const body = await res.json();

  expect((body.jobs ?? []).length, 'limit should be honoured').toBe(1);
  expect(body.has_more, 'more jobs matched than were returned').toBe(true);

  // The important half. A schedd cannot be paged through, so the server
  // owes the caller an explanation instead of a short list that looks
  // complete. Silent truncation is the failure mode that reads as
  // success at every layer above it.
  expect(
    body.pagination_unavailable,
    'a truncated, unpageable answer must say why',
  ).toBeTruthy();
  expect(body.next_page_token, 'a schedd has no cursor to offer').toBeFalsy();
});

test('archive keyset paging neither drops nor repeats records', async ({ page }) => {
  test.setTimeout(120_000);
  await loginAsAdmin(page, password);

  // Removed jobs are what lands in the archive, so make some.
  const cluster = await submitN(page, 4);
  await expect
    .poll(
      async () => {
        const q = await page.request.get(
          `/api/v1/jobs?owned_by_me=false&limit=*&constraint=${encodeURIComponent(`ClusterId == ${cluster}`)}`,
        );
        return ((await q.json()).jobs ?? []).length;
      },
      { timeout: 30_000 },
    )
    .toBe(4);

  const del = await page.request.delete('/api/v1/jobs', {
    data: { constraint: `ClusterId == ${cluster}`, reason: 'e2e paging' },
  });
  expect(del.status()).toBe(200);

  const constraint = `ClusterId == ${cluster}`;
  await expect
    .poll(
      async () => {
        const a = await page.request.get(
          `/api/v1/jobs/archive?owned_by_me=false&limit=50&constraint=${encodeURIComponent(constraint)}`,
        );
        return ((await a.json()).ads ?? []).length;
      },
      { timeout: 60_000 },
    )
    .toBe(4);

  // Page through two at a time using the documented keyset: pass the
  // (cluster, proc) of the LAST record of the previous page.
  const seen: string[] = [];
  let before: { c: number; p: number } | undefined;
  for (let guard = 0; guard < 10; guard++) {
    const qs = new URLSearchParams({
      owned_by_me: 'false',
      limit: '2',
      constraint,
    });
    if (before) {
      qs.set('before_cluster', String(before.c));
      qs.set('before_proc', String(before.p));
    }
    const res = await page.request.get(`/api/v1/jobs/archive?${qs.toString()}`);
    expect(res.status()).toBe(200);
    const ads: Ad[] = (await res.json()).ads ?? [];
    if (ads.length === 0) break;

    for (const ad of ads) seen.push(`${ad.ClusterId}.${ad.ProcId}`);
    const last = ads[ads.length - 1];
    before = { c: Number(last.ClusterId), p: Number(last.ProcId) };
  }

  // Both halves matter. Duplicates mean a page re-served what the last
  // one already had; a short union means a record fell between pages.
  // A cursor that is off by one produces exactly one of these, and
  // checking only the count would miss a swap.
  expect(new Set(seen).size, `paging repeated records: ${seen.join(',')}`).toBe(seen.length);
  expect(seen.sort(), 'paging should yield every archived proc exactly once').toEqual(
    [0, 1, 2, 3].map((p) => `${cluster}.${p}`).sort(),
  );
});
