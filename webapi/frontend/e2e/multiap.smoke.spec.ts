import { expect, test } from '@playwright/test';

import { installApiFixtures } from './fixtures/api';

// Multi-AP mode against mocked responses: the pages render, name the
// access point of every job, say which access point is behind, and
// submit to the caller's home access point or an alternate.

test.beforeEach(async ({ page }) => {
  await installApiFixtures(page, { multiAP: true });
});

function watchForErrors(page: import('@playwright/test').Page) {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(String(e)));
  page.on('console', (m) => {
    if (m.type() === 'error') errors.push(m.text());
  });
  return errors;
}

for (const path of ['/', '/jobs', '/archive', '/utilization', '/aps', '/submit']) {
  test(`multi-AP: renders ${path} without page errors`, async ({ page }) => {
    const errors = watchForErrors(page);
    const res = await page.goto(path);
    expect(res?.status(), `${path} should not 4xx/5xx`).toBeLessThan(400);
    await expect(page.locator('body')).toBeVisible();
    expect(errors, `${path} raised page errors`).toEqual([]);
  });
}

test('multi-AP: the jobs page shows both access points and the one behind', async ({ page }) => {
  await page.goto('/jobs');
  await expect(page.getByText('smoke-ap1-batch')).toBeVisible();
  await expect(page.getByText('smoke-ap2-batch')).toBeVisible();
  await expect(page.getByRole('cell', { name: 'ap2.smoke.example' })).toBeVisible();
  await expect(page.getByRole('status')).toContainText('ap2.smoke.example (stale, 412 s behind)');
  await expect(page.getByText('+ Submit a batch')).toHaveCount(0);
  await expect(page.getByTitle(/Remove batch/)).toHaveCount(0);
});

test('multi-AP: the sidebar offers the pages multi-AP mode serves', async ({ page }) => {
  await page.goto('/jobs');
  await expect(page.getByRole('link', { name: 'Access Points' })).toBeVisible();
  await expect(page.getByRole('link', { name: 'Submit', exact: true })).toBeVisible();
  await expect(page.getByRole('link', { name: 'Interactive', exact: true })).toHaveCount(0);
});

test('multi-AP: the submit page names the access point and offers the alternates', async ({ page }) => {
  await page.goto('/submit');
  await expect(page.getByText('Will submit to')).toBeVisible();
  const select = page.getByRole('combobox', { name: 'Access point' });
  await expect(select).toHaveValue('ap1.smoke.example');
  await expect(select.locator('option')).toHaveText(['ap1.smoke.example (home)', 'ap2.smoke.example']);
  await select.selectOption('ap2.smoke.example');
  await expect(select).toHaveValue('ap2.smoke.example');
});

test('multi-AP: the access points page marks where the caller may submit', async ({ page }) => {
  await page.goto('/aps');
  await expect(page.getByText('your home')).toBeVisible();
  await expect(page.getByText('you may submit')).toBeVisible();
});

test('multi-AP: the archive names the access point and links the complete id', async ({ page }) => {
  await page.goto('/archive');
  const link = page.getByRole('link', { name: '39.0@ap1.smoke.example' });
  await expect(link).toBeVisible();
  await expect(link).toHaveAttribute('href', '/archive/39.0%40ap1.smoke.example');
});
