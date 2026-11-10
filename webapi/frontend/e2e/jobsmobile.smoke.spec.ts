import { expect, test, type Page } from '@playwright/test';
import path from 'node:path';

import { installApiFixtures, installJobsProgressFixtures } from './fixtures/api';

// /jobs and /users/<owner> on a phone and a tablet: batches are cards,
// the page never scrolls sideways, a card opens in place, and its actions
// are there to tap.

// /users/<owner> is one exported page answering every owner in
// production; do the same here (see openJobPage in render.smoke.spec.ts).
async function openUserPage(page: Page, owner: string) {
  const placeholder = path.join(__dirname, '..', 'out', 'users', '_.html');
  await page.route(`**/users/${owner}`, async (route) => {
    if (route.request().resourceType() !== 'document') {
      await route.fallback();
      return;
    }
    await route.fulfill({ path: placeholder, contentType: 'text/html; charset=utf-8' });
  });
  await page.goto(`/users/${owner}`);
}

async function noSidewaysScroll(page: Page) {
  const [scroll, client] = await page.evaluate(() => [
    document.documentElement.scrollWidth,
    document.documentElement.clientWidth,
  ]);
  expect(scroll, `the page is ${scroll}px wide in a ${client}px viewport`).toBeLessThanOrEqual(client);
}

for (const viewport of [
  { width: 390, height: 844 },
  { width: 768, height: 1024 },
]) {
  test.describe(`${viewport.width}x${viewport.height}`, () => {
    test.use({ viewport });

    test.beforeEach(async ({ page }) => {
      await installApiFixtures(page);
      await installJobsProgressFixtures(page);
    });

    for (const where of ['/jobs', '/users/e2e']) {
      test(`${where} lists batches as cards that open in place`, async ({ page }) => {
        if (where === '/jobs') await page.goto('/jobs');
        else await openUserPage(page, 'e2e');

        const card = page.getByTestId('batch-card').filter({ hasText: 'smoke-sweep' });
        await expect(card).toBeVisible();
        await expect(page.locator('table').filter({ hasText: 'Batch' })).toHaveCount(0);
        await expect(page.getByRole('combobox', { name: /Sort by/ })).toBeVisible();
        await noSidewaysScroll(page);

        // Actions: a finger-sized menu with Resource utilization, and
        // Remove, inside the viewport.
        const menu = card.getByRole('button', { name: 'More actions for batch smoke-sweep' });
        const box = await menu.boundingBox();
        expect(box!.height, 'the actions button is too small to tap').toBeGreaterThanOrEqual(36);
        expect(box!.x + box!.width).toBeLessThanOrEqual(viewport.width);
        // Reachable by scrolling down, never sideways.
        const remove = card.getByTitle(/Remove batch smoke-sweep/);
        await remove.scrollIntoViewIfNeeded();
        await expect(remove).toBeInViewport();
        await noSidewaysScroll(page);
        await menu.click();
        await expect(card.getByRole('menuitem', { name: 'Resource utilization' })).toBeVisible();
        await expect(card.getByRole('menuitem', { name: 'Open batch page' })).toHaveAttribute('href', '/batches/500');
        await page.keyboard.press('Escape');

        // The name is the batch page's link; the caret beside it opens
        // the card, and is big enough to tap.
        await expect(card.getByRole('link', { name: 'smoke-sweep' })).toHaveAttribute('href', '/batches/500');
        const caret = await card.getByRole('button', { name: 'Jobs in batch smoke-sweep' }).boundingBox();
        expect(caret!.height, 'the caret is too small to tap').toBeGreaterThanOrEqual(36);
        expect(caret!.width, 'the caret is too small to tap').toBeGreaterThanOrEqual(36);

        // Tap the card itself: it opens to its jobs, still without
        // widening the page.
        await card.getByText(/^12 jobs$/).click();
        await expect(card.getByTestId('job-card').first()).toBeVisible();
        await expect(card.getByRole('link', { name: '500.0' })).toBeVisible();
        await noSidewaysScroll(page);
      });
    }

    test("tapping a card's name opens the batch page, not the card", async ({ page }) => {
      await page.goto('/jobs');
      const card = page.getByTestId('batch-card').filter({ hasText: 'smoke-sweep' });
      await card.getByRole('link', { name: 'smoke-sweep' }).click();
      await page.waitForURL('**/batches/500');
    });

    test('the held and running views keep their content on cards', async ({ page }) => {
      await page.goto('/jobs');
      const card = page.getByTestId('batch-card').filter({ hasText: 'smoke-sweep' });
      await page.getByRole('button', { name: /^Held\b/ }).first().click();
      await expect(card).toContainText('memory usage exceeded request_memory');
      await page.getByRole('button', { name: /^Held\b/ }).first().click();
      await page.getByRole('button', { name: /^Running\b/ }).first().click();
      await expect(card).toContainText('Memory (peak)');
      await expect(card).toContainText(/median .* of 2\.0 GB/);
      await noSidewaysScroll(page);
    });
  });
}

test.describe('1500px', () => {
  test.use({ viewport: { width: 1500, height: 1000 } });
  test('/jobs keeps its table on a wide screen', async ({ page }) => {
    await installApiFixtures(page);
    await installJobsProgressFixtures(page);
    await page.goto('/jobs');
    await expect(page.getByRole('button', { name: /^Progress/ })).toBeVisible();
    await expect(page.getByTestId('batch-card')).toHaveCount(0);
    await noSidewaysScroll(page);
  });
});
