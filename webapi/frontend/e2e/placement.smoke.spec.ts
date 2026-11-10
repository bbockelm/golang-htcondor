import { expect, test } from '@playwright/test';

import { installApiFixtures } from './fixtures/api';
import {
  installPlacementFixtures,
  onboardedSession,
  placementIssuedFixture,
  placementOnlySession,
} from './fixtures/placementOnboarding';

// Placement onboarding against mocked responses: the token page and the
// device confirmation page, for a session with no local account.

function watchForErrors(page: import('@playwright/test').Page) {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(String(e)));
  page.on('console', (m) => {
    if (m.type() === 'error') errors.push(m.text());
  });
  return errors;
}

test.beforeEach(async ({ page }) => {
  await installApiFixtures(page);
  await installPlacementFixtures(page, { placementOnly: true });
});

test('placement: a token is requested and offered for download', async ({ page }) => {
  const errors = watchForErrors(page);
  await page.goto('/placement');
  await expect(page.getByRole('heading', { name: 'Placement token' })).toBeVisible();
  // The reduced shell: the person's name, and none of the AP's pages.
  await expect(page.getByText('Zoe Q')).toBeVisible();
  await expect(page.getByRole('link', { name: 'Jobs' })).toHaveCount(0);
  await expect(page.getByText('Write: Submit and manage jobs')).toBeVisible();
  await expect(page.locator('option', { hasText: 'RetiredProject (disabled)' })).toHaveAttribute('disabled', '');

  await page.getByRole('button', { name: 'Request token' }).click();
  await expect(page.getByRole('heading', { name: 'Token granted' })).toBeVisible();
  await expect(page.getByText('ap.smoke.example', { exact: true })).toBeVisible();
  await expect(page.getByLabel('Token')).toHaveValue(placementIssuedFixture.token as string);
  await expect(page.getByText(/COLLECTOR_HOST = cm\.smoke\.example/)).toBeVisible();

  const download = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Download token' }).click();
  expect((await download).suggestedFilename()).toBe('Placement.token');
  expect(errors).toEqual([]);
});

test('placement: any other page sends a placement-only session to /placement', async ({ page }) => {
  await page.goto('/jobs');
  await expect(page).toHaveURL(/\/placement\/?$/);
});

test('placement: onboarded while signed in, the full navigation appears', async ({ page }) => {
  const errors = watchForErrors(page);
  let onboarded = false;
  await page.route('**/api/v1/auth/me', (route) =>
    route.fulfill({ json: onboarded ? onboardedSession : placementOnlySession }),
  );
  await page.goto('/placement');
  const check = page.getByRole('button', { name: 'Check again' });
  await expect(check).toBeVisible();
  await expect(page.getByRole('link', { name: 'Jobs' })).toHaveCount(0);

  onboarded = true;
  await check.click();
  await expect(page.getByRole('link', { name: 'Jobs' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Placement token' })).toBeVisible();
  await expect(check).toHaveCount(0);
  expect(errors).toEqual([]);
});

test('placement device: confirm a request', async ({ page }) => {
  const errors = watchForErrors(page);
  await page.goto('/placement/device?user_code=bcdf-ghjk');
  await expect(page.getByRole('heading', { name: 'Confirm token request' })).toBeVisible();
  await expect(page.getByText('Placement Client', { exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Request token' }).click();
  await expect(page.getByText('The token will be provided to Placement Client.')).toBeVisible();
  // The token goes to the device, never to this page.
  await expect(page.getByLabel('Token')).toHaveCount(0);
  expect(errors).toEqual([]);
});

test('placement device: deny a request', async ({ page }) => {
  await page.goto('/placement/device?user_code=BCDF-GHJK');
  page.once('dialog', (d) => d.accept());
  await page.getByRole('button', { name: 'Deny request' }).click();
  await expect(page.getByText('You have canceled the request.')).toBeVisible();
});

test('placement device: a code can be typed in', async ({ page }) => {
  await page.goto('/placement/device');
  await expect(page.getByRole('heading', { name: 'Enter code' })).toBeVisible();
  await page.getByPlaceholder('XXXX-XXXX').fill('bcdf-ghjk');
  await page.getByRole('button', { name: 'Continue' }).click();
  await expect(page.getByRole('heading', { name: 'Confirm token request' })).toBeVisible();
});
