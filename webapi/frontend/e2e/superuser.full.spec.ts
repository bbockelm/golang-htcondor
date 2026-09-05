import { readFileSync } from 'node:fs';

import { expect, test } from '@playwright/test';

import { adminPassword, loginAsAdmin } from './fixtures/login';

// Superuser mode: the largest privilege the server grants -- acting on
// another user's jobs as that user.
//
// The handler describes the intent it is built around:
//
//   Arming is an explicit act with an explicit expiry rather than a
//   standing property of being an admin. The mode changes what an
//   ordinary-looking click does -- a remove button starts landing on
//   other people's jobs.
//
// Each property below is one that intent depends on, and none was
// covered. Demo mode now sets SuperuserGroup so the feature is
// reachable without a real pool and a real IDP group.

const password = adminPassword(
  readFileSync(process.env.E2E_SERVER_LOG ?? '/tmp/e2e-server.log', 'utf8'),
);

const ARM = '/api/v1/admin/superuser';
const ME = '/api/v1/auth/me';

test('arming is off until asked for, and reports a bounded expiry', async ({ page }) => {
  await loginAsAdmin(page, password);

  // Being allowed to arm is not the same as being armed. If these were
  // conflated, every admin session would silently be a superuser
  // session -- exactly what the explicit-act design is avoiding.
  const before = await (await page.request.get(ME)).json();
  expect(before.superuser_allowed, 'an admin should be permitted to arm').toBe(true);
  expect(before.superuser_active, 'nobody should start out armed').toBe(false);

  const armed = await page.request.post(ARM, { data: { enabled: true } });
  expect(armed.status(), `arm failed: ${await armed.text()}`).toBe(200);
  const body = await armed.json();
  expect(body.active).toBe(true);
  expect(body.expires_at, 'arming must carry an expiry').toBeTruthy();

  // The expiry is the safety property: the mode is supposed to turn
  // itself off. A far-future or absent one would mean it does not.
  const ms = new Date(body.expires_at).getTime() - Date.now();
  expect(ms, 'expiry should be in the future').toBeGreaterThan(0);
  expect(ms, 'expiry should be minutes away, not hours').toBeLessThan(60 * 60 * 1000);

  const after = await (await page.request.get(ME)).json();
  expect(after.superuser_active, 'auth/me should report the armed state').toBe(true);
});

test('disarming turns it back off', async ({ page }) => {
  await loginAsAdmin(page, password);

  await page.request.post(ARM, { data: { enabled: true } });
  expect((await (await page.request.get(ME)).json()).superuser_active).toBe(true);

  const off = await page.request.post(ARM, { data: { enabled: false } });
  expect(off.status()).toBe(200);
  expect((await off.json()).active).toBe(false);

  expect(
    (await (await page.request.get(ME)).json()).superuser_active,
    'disarm should take effect immediately',
  ).toBe(false);
});

test('arming one session does not arm another', async ({ browser }) => {
  // Arming is keyed on the session, not the account. A second browser
  // -- same user, different session -- must not inherit it, or "the
  // operator can see they turned it on" stops being true for the window
  // they are looking at.
  const armedCtx = await browser.newContext({ ignoreHTTPSErrors: true });
  const otherCtx = await browser.newContext({ ignoreHTTPSErrors: true });
  const armedPage = await armedCtx.newPage();
  const otherPage = await otherCtx.newPage();

  await loginAsAdmin(armedPage, password);
  await loginAsAdmin(otherPage, password);

  await armedPage.request.post(ARM, { data: { enabled: true } });

  expect(
    (await (await armedPage.request.get(ME)).json()).superuser_active,
    'the session that armed should be armed',
  ).toBe(true);
  expect(
    (await (await otherPage.request.get(ME)).json()).superuser_active,
    'a different session of the same user must not be armed',
  ).toBe(false);

  await armedCtx.close();
  await otherCtx.close();
});

test('arming is written to the audit log', async ({ page }) => {
  await loginAsAdmin(page, password);
  await page.request.post(ARM, { data: { enabled: true } });

  // The handler calls this out as the point: arming "may be the only
  // entry if they then do nothing". An unaudited privilege escalation
  // is one nobody can review after the fact.
  const logs = await page.request.get('/api/v1/admin/logs?limit=200');
  expect(logs.status(), `logs query failed: ${await logs.text()}`).toBe(200);
  const text = await logs.text();

  expect(text, 'arming should be recorded').toContain('Superuser mode armed');
  expect(text, 'the record should name the operator').toContain('admin');
});
