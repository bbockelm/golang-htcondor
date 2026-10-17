import { expect, test } from '@playwright/test';

import { installApiFixtures } from './fixtures/api';
import { installPlacementFixtures } from './fixtures/placement';

// A placementd advertising API version 2: the Users tab becomes Directory,
// with the map file status above it.

test('placement directory lists entries by source and onboards a user', async ({ page }) => {
  await installApiFixtures(page);
  const { edits } = await installPlacementFixtures(page);
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(String(e)));
  page.on('console', (m) => {
    if (m.type() === 'error') errors.push(m.text());
  });

  await page.goto('/admin/placement');
  await expect(page.getByRole('button', { name: 'Directory' })).toBeVisible();
  await expect(page.getByTestId('mapfile-status')).toContainText('Quarantined');
  await expect(page.getByTestId('mapfile-status')).toContainText('1 problem');

  const mapRow = page.getByTestId('dir-row-6f1c2c1e-1111-4a3b-9c1d-000000000001');
  await expect(mapRow).toContainText('alice@wisc.edu');
  await expect(mapRow.getByRole('button', { name: 'Adopt' })).toBeVisible();
  await expect(mapRow.getByRole('button', { name: 'Edit' })).toHaveCount(0);

  const intRow = page.getByTestId('dir-row-6f1c2c1e-1111-4a3b-9c1d-000000000002');
  await expect(intRow.getByRole('button', { name: 'Edit' })).toBeVisible();

  await page.getByRole('tab', { name: 'Accounts' }).click();
  await expect(page.getByText('bob@ap.smoke.example').first()).toBeVisible();

  await page.getByRole('button', { name: 'Onboard user' }).click();
  const dialog = page.getByRole('dialog', { name: 'Onboard user' });
  await dialog.getByLabel('Identity', { exact: true }).fill('carol@wisc.edu');
  await dialog.getByLabel(/^Account/).fill('carol@ap.smoke.example');
  await dialog.getByRole('button', { name: 'Onboard' }).click();
  await expect(dialog).toHaveCount(0);
  await expect(page.getByText('User onboarded.')).toBeVisible();

  const batch = edits.find((e) => e.path === '/api/v1/placement/admin/batch');
  expect(batch?.body).toMatchObject({
    dry_run: false,
    operations: [
      { operation: 'Create', target_type: 'Account' },
      { operation: 'Create', target_type: 'Identity', fields: { identity: 'carol@wisc.edu' } },
    ],
  });
  expect(errors).toEqual([]);
});
