import { expect, test } from '@playwright/test';

import { adminPassword, loginAsAdmin } from './fixtures/login';
import { serverLog } from './fixtures/serverlog';

// API keys: mint -> authenticate -> revoke -> refused.
//
// The Web UI states the security property in its own copy: "Deleting is
// a soft-delete — the key stops authenticating immediately." That is a
// testable claim about a credential, and "immediately" is exactly the
// word that quietly becomes "once some cache expires".

const password = adminPassword(
  serverLog(),
);

// A READ-scoped endpoint the key is expected to reach.
const PROBE = '/api/v1/jobs?owned_by_me=false';

test('an API key authenticates until it is revoked, then immediately does not', async ({
  page,
  request,
}) => {
  await loginAsAdmin(page, password);

  const mint = await page.request.post('/api/v1/admin/api-keys', {
    data: { name: `e2e-${Date.now()}`, scopes: ['condor:/READ'] },
  });
  expect(mint.status(), `mint failed: ${await mint.text()}`).toBe(201);
  const minted = await mint.json();
  const secret = minted.key;
  const keyID = minted.api_key?.key_id ?? minted.api_key?.KeyID;
  expect(secret, 'mint should return the full key exactly once').toBeTruthy();
  expect(keyID, 'mint should return the key id').toBeTruthy();

  // The `request` fixture carries no cookies -- deliberately. Using
  // page.request here would send the admin session alongside the bearer
  // header, and a 200 would prove nothing about the key: the session
  // would be doing the work, and the post-revocation check would still
  // pass on the session too.
  const withKey = { Authorization: `Bearer ${secret}` };

  const before = await request.get(PROBE, { headers: withKey });
  expect(before.status(), `a fresh key should authenticate: ${await before.text()}`).toBe(200);

  // Sanity: the same request without the key is refused, so the 200
  // above is attributable to the key rather than to the endpoint being
  // open to anyone.
  const anon = await request.get(PROBE);
  expect(anon.status(), 'the probe endpoint should not be open to anonymous callers')
    .toBeGreaterThanOrEqual(400);

  const del = await page.request.delete(
    `/api/v1/admin/api-keys/${encodeURIComponent(keyID)}`,
  );
  expect(del.status(), `revoke failed: ${await del.text()}`).toBeLessThan(400);

  // "Immediately": no sleep, no retry loop. If this needs a wait to
  // pass, the property the UI advertises is not the property it has.
  const after = await request.get(PROBE, { headers: withKey });
  expect(after.status(), 'a revoked key must stop authenticating at once').toBe(401);
});

test('listing keys never returns the secret', async ({ page }) => {
  await loginAsAdmin(page, password);

  const mint = await page.request.post('/api/v1/admin/api-keys', {
    data: { name: `e2e-secrecy-${Date.now()}`, scopes: ['metrics'] },
  });
  expect(mint.status()).toBe(201);
  const secret = (await mint.json()).key as string;
  expect(secret).toBeTruthy();

  // The full key is shown once, at creation. If it reappears in the
  // listing then every admin page view is handing it out again.
  const list = await page.request.get('/api/v1/admin/api-keys');
  expect(list.status()).toBe(200);
  expect(
    await list.text(),
    'the listing must not echo the secret',
  ).not.toContain(secret);
});
