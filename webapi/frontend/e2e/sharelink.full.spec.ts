import { readFileSync } from 'node:fs';

import { expect, test } from '@playwright/test';

import { adminPassword, loginAsAdmin } from './fixtures/login';

// Redeeming a share link.
//
// The existing share tests assert the URL's *shape*. This asserts it
// works, and that a forged one does not -- which is the part that
// matters, because handleSharedOutput says of itself:
//
//   Possession of the URL is the only auth -- the SPA's session cookie
//   is intentionally ignored.
//
// So the link is a bearer secret that mints a JWT for the embedded
// owner. Every assertion below is made with the cookie-less `request`
// fixture: sending a session would let the session explain a success
// and hide whether the token did anything.

const password = adminPassword(
  readFileSync(process.env.E2E_SERVER_LOG ?? '/tmp/e2e-server.log', 'utf8'),
);

async function mintShare(page: import('@playwright/test').Page): Promise<string> {
  const submit = await page.request.post('/api/v1/jobs', {
    data: {
      submit_file: [
        'executable = /bin/echo',
        'arguments = share-me',
        'transfer_executable = false',
        'queue 1',
      ].join('\n'),
    },
  });
  expect(submit.status(), `submit failed: ${await submit.text()}`).toBeLessThan(400);
  const created = await submit.json();
  const cluster = created.cluster_id ?? created.ClusterId ?? created.cluster;

  const share = await page.request.post(`/api/v1/jobs/${cluster}.0/output/share`, {
    data: {},
  });
  expect(share.status(), `share mint failed: ${await share.text()}`).toBe(200);
  const { url } = await share.json();
  expect(url).toBeTruthy();
  return url;
}

test('a share link is redeemable with no session at all', async ({ page, request }) => {
  await loginAsAdmin(page, password);
  const url = await mintShare(page);

  const res = await request.get(url);
  expect(
    res.status(),
    `an anonymous holder of the link should be served: ${(await res.text()).slice(0, 200)}`,
  ).toBe(200);

  // It streams the sandbox as a tar; assert we got a body of some kind
  // rather than an error document that happened to be 200.
  const body = await res.body();
  expect(body.byteLength, 'expected a non-empty sandbox stream').toBeGreaterThan(0);
});

test('a tampered share token is refused', async ({ page, request }) => {
  await loginAsAdmin(page, password);
  const url = await mintShare(page);

  const parsed = new URL(url);
  const tok = parsed.searchParams.get('t')!;
  expect(tok.length, 'token should be long enough to perturb').toBeGreaterThan(8);

  // Flip one character in the middle. The signature must not survive it.
  const at = Math.floor(tok.length / 2);
  const flipped = tok[at] === 'a' ? 'b' : 'a';
  parsed.searchParams.set('t', tok.slice(0, at) + flipped + tok.slice(at + 1));

  const res = await request.get(parsed.toString());
  expect(res.status(), 'a forged token must not be honoured').toBe(401);
});

test('a share link with no token is refused', async ({ request }) => {
  // Guards the obvious hole: if the handler treated a missing token as
  // an empty-but-valid one, the tamper test above would still pass.
  const res = await request.get('/api/v1/share/output');
  expect(res.status()).toBeGreaterThanOrEqual(400);
  expect(res.status()).toBeLessThan(500);
});
