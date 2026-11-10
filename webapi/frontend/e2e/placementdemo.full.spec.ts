import { expect, test } from '@playwright/test';

import { loginAs, userPassword } from './fixtures/login';
import { serverLog } from './fixtures/serverlog';

// Placement in demo mode. Demo mode runs a condor_placementd only when the
// HTCondor it starts has one, and seeds "newbie" only then; the released
// HTCondor the CI image installs has none, so there this file skips.
//
// What it checks holds for any placementd API version: the demo's "user"
// is mapped and gets a token, and "newbie" is mapped by nothing and gets
// the placement page alone.

const log = serverLog();
const newbie = log.match(/^NewbiePassword:\s*(\S+)\s*$/m)?.[1];

test.skip(!newbie, 'demo mode found no condor_placementd in this HTCondor, so placement is off');

test('the demo user gets a placement token', async ({ page }) => {
  await loginAs(page, 'user', userPassword(log));
  await page.goto('/');
  await page.getByRole('link', { name: 'Placement token' }).click();
  await expect(page).toHaveURL(/\/placement\/?$/);
  await expect(page.getByRole('heading', { name: 'Placement token' })).toBeVisible();

  const resp = await page.request.post('/api/v1/placement/me/token', {
    headers: { 'X-Requested-With': 'XMLHttpRequest' },
    data: { project: 'Demo', authorizations: ['READ', 'WRITE'] },
  });
  expect(resp.status(), (await resp.text()).slice(0, 200)).toBe(201);
  const issued = await resp.json();
  expect(issued.token).toBeTruthy();
  expect(issued.ap_user_id).toMatch(/^user@/);
});

test('an identity nothing maps gets only the placement page', async ({ page }) => {
  await loginAs(page, 'newbie', newbie!);
  await expect(page).toHaveURL(/\/placement\/?$/);
  await expect(page.getByRole('heading', { name: 'Placement token' })).toBeVisible();
  await expect(page.getByText('newbie is not authorized to use this access point.')).toBeVisible();
  await expect(page.getByRole('link', { name: 'Jobs' })).toHaveCount(0);
});
