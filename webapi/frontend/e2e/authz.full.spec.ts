import { readFileSync } from 'node:fs';

import { expect, test } from '@playwright/test';

import { adminPassword, loginAs, loginAsAdmin, userPassword } from './fixtures/login';

// Authorization boundaries, from a browser.
//
// Demo mode seeds two accounts: "admin" (state=admin, so the IDP's
// userinfo emits groups=["admin"], matching WebUIAdminGroup) and "user"
// (state=active, no groups). Without a second identity none of this is
// testable, which is why nothing covered it before.

const serverLog = readFileSync(process.env.E2E_SERVER_LOG ?? '/tmp/e2e-server.log', 'utf8');
const adminPw = adminPassword(serverLog);
const userPw = userPassword(serverLog);

// Paths the admin UI actually calls. Worth naming carefully: an
// endpoint that does not exist is served the SPA shell with a 200, so a
// typo here turns "refuses a non-admin" into a test of nothing.
const ADMIN_ENDPOINTS = ['/api/v1/admin/oauth2/clients', '/api/v1/admin/api-keys'];

test('the two demo accounts are actually different identities', async ({ browser }) => {
  // Guards the rest of this file. If both logins resolved to the same
  // account -- a fixture reading the wrong password line, say -- every
  // assertion below would pass while testing nothing.
  //
  // Two contexts, not two logins in one: the session cookie survives, so
  // a second /login in the same context is redirected straight through
  // the IDP without ever showing a form, and the "second" identity is
  // silently the first one.
  const ctxA = await browser.newContext({ ignoreHTTPSErrors: true });
  const ctxB = await browser.newContext({ ignoreHTTPSErrors: true });
  const pageA = await ctxA.newPage();
  const pageB = await ctxB.newPage();

  await loginAsAdmin(pageA, adminPw);
  const asAdmin = await (await pageA.request.get('/api/v1/whoami')).json();

  await loginAs(pageB, 'user', userPw);
  const asUser = await (await pageB.request.get('/api/v1/whoami')).json();

  await ctxA.close();
  await ctxB.close();

  expect(asAdmin.authenticated).toBe(true);
  expect(asUser.authenticated).toBe(true);
  expect(asUser.user, 'the two logins must not resolve to the same user').not.toBe(
    asAdmin.user,
  );
});

test('a non-admin does not get the admin nav', async ({ page }) => {
  await loginAs(page, 'user', userPw);
  await page.goto('/');

  // The dashboard renders for them...
  await expect(page.getByRole('heading', { name: /dashboard/i })).toBeVisible();
  // ...but the admin section is not offered.
  await expect(page.getByRole('link', { name: /^OAuth2 Clients$/i })).toHaveCount(0);
  await expect(page.getByRole('link', { name: /^API Keys$/i })).toHaveCount(0);
});

test('a non-admin is refused the admin APIs', async ({ page }) => {
  await loginAs(page, 'user', userPw);

  // Hiding the nav is presentation; the server is the boundary. Ask it
  // directly, which is what a determined caller would do.
  for (const path of ADMIN_ENDPOINTS) {
    const res = await page.request.get(path);
    expect(
      res.status(),
      `${path} should refuse a non-admin, got ${res.status()}: ${(await res.text()).slice(0, 120)}`,
    ).toBeGreaterThanOrEqual(400);
  }
});

test('an admin is allowed the admin APIs', async ({ page }) => {
  // The negative test above passes just as well if the endpoints are
  // broken for everyone. This is the control.
  await loginAsAdmin(page, adminPw);
  for (const path of ADMIN_ENDPOINTS) {
    const res = await page.request.get(path);
    expect(res.status(), `${path} should serve an admin`).toBe(200);
    // The SPA is served from a catch-all, so a wrong path answers 200
    // with the HTML shell. An admin endpoint must return JSON -- without
    // this the negative test above could be "passing" against a route
    // that does not exist.
    expect(
      res.headers()['content-type'] ?? '',
      `${path} should be a JSON API, not the SPA catch-all`,
    ).toContain('json');
  }
});

test('signing out clears the session', async ({ page }) => {
  await loginAsAdmin(page, adminPw);
  expect((await (await page.request.get('/api/v1/whoami')).json()).authenticated).toBe(true);

  await page.goto('/');
  await page.getByRole('button', { name: /sign out/i }).or(
    page.getByRole('link', { name: /sign out/i }),
  ).first().click();

  // The session cookie must be gone server-side, not merely hidden in
  // the UI: ask the API, which is what any later request would do.
  await page.waitForTimeout(500);
  const after = await (await page.request.get('/api/v1/whoami')).json();
  expect(after.authenticated, 'the session should not survive sign-out').toBe(false);
});
