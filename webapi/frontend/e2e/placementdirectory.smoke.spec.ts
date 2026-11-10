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

  await intRow.getByRole('button', { name: 'History' }).click();
  const history = page.getByRole('dialog', { name: 'History of bob@cilogon.org' });
  await expect(history.getByTestId('history-120')).toContainText('by e2e');
  await expect(history.getByTestId('history-120')).toContainText('spring term');
  await expect(history.getByTestId('history-7')).toContainText('by Import');
  await history.getByRole('button', { name: 'Close' }).click();

  await page.getByRole('tab', { name: 'Accounts' }).click();
  await expect(page.getByText('bob@ap.smoke.example').first()).toBeVisible();

  await page.getByRole('button', { name: 'Onboard user' }).click();
  const dialog = page.getByRole('dialog', { name: 'Onboard user' });
  await dialog.getByLabel('Identity', { exact: true }).fill('carol@wisc.edu');
  await dialog.getByLabel(/^Account/).fill('carol@ap.smoke.example');
  await dialog.getByLabel('Change comment (optional)').fill('new student');
  await dialog.getByRole('button', { name: 'Onboard' }).click();
  await expect(dialog).toHaveCount(0);
  await expect(page.getByText('User onboarded.')).toBeVisible();

  const batch = edits.find((e) => e.path === '/api/v1/placement/admin/batch');
  expect(batch?.body).toMatchObject({
    dry_run: false,
    change_comment: 'new student',
    operations: [
      { operation: 'Create', target_type: 'Account' },
      { operation: 'Create', target_type: 'Identity', fields: { identity: 'carol@wisc.edu' } },
    ],
  });
  expect(errors).toEqual([]);
});

test('placement requests: approve opens the onboarding form pre-filled, deny takes a reason', async ({ page }) => {
  await installApiFixtures(page);
  const { edits } = await installPlacementFixtures(page);
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(String(e)));
  page.on('console', (m) => {
    if (m.type() === 'error') errors.push(m.text());
  });

  await page.goto('/admin/placement');
  // The pending count, beside the tab and in the sidebar.
  await expect(page.getByRole('button', { name: /^Requests/ }).getByLabel('1 pending')).toBeVisible();
  await expect(page.getByRole('link', { name: /Placement/ }).getByLabel('1 pending access requests')).toBeVisible();
  await page.getByRole('button', { name: /^Requests/ }).click();

  const row = page.getByTestId('request-row-3');
  await expect(row).toContainText('dana@wisc.edu');
  // Markup the requester typed is text.
  await expect(row.getByText('Starting in the <i>B</i> lab')).toBeVisible();
  await expect(row.getByText('Dana <b>R</b>')).toBeVisible();

  await row.getByRole('button', { name: 'Approve' }).click();
  const dialog = page.getByRole('dialog', { name: 'Approve access request' });
  await expect(dialog.getByLabel('Identity', { exact: true })).toHaveValue('dana@wisc.edu');
  await expect(dialog.getByLabel(/^Account/)).toHaveValue('dana@ap.smoke.example');
  await expect(dialog.getByRole('checkbox', { name: 'Read' })).toBeChecked();
  await expect(dialog.getByRole('checkbox', { name: 'Write' })).toBeChecked();
  await expect(dialog.getByRole('checkbox', { name: 'Chem101' })).toBeChecked();
  await expect(dialog.getByText('Requested, not in the directory:')).toBeVisible();
  await dialog.getByLabel('Change comment (optional)').fill('welcome');
  await dialog.getByRole('button', { name: 'Approve' }).click();
  await expect(dialog).toHaveCount(0);
  await expect(page.getByText('Request approved.')).toBeVisible();
  expect(edits.find((e) => e.path === '/api/v1/placement/admin/requests/3/approve')?.body).toMatchObject({
    account: 'dana@ap.smoke.example',
    authorizations: ['READ', 'WRITE'],
    projects: ['Chem101'],
    default_project: 'Chem101',
    comment: 'welcome',
    dry_run: false,
  });
  expect(edits.some((e) => e.path === '/api/v1/placement/admin/batch')).toBe(false);

  await row.getByRole('button', { name: 'Deny' }).click();
  const deny = page.getByRole('dialog', { name: 'Deny access request' });
  await deny.getByLabel('Reason (shown to the requester)').fill('Ask your PI.');
  await deny.getByRole('button', { name: 'Deny' }).click();
  await expect(page.getByText('Request denied.')).toBeVisible();
  expect(edits.find((e) => e.path === '/api/v1/placement/admin/requests/3/deny')?.body).toEqual({ reason: 'Ask your PI.' });
  expect(errors).toEqual([]);
});
