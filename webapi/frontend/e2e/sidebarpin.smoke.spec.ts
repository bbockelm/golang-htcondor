import { expect, test, type Page } from '@playwright/test';

import { installApiFixtures, sessionFixture } from './fixtures/api';
import { SMOKE_NOW } from './fixtures/clock';

// The desktop sidebar is pinned to the viewport, so its account controls
// -- the user's name, Sign out, superuser mode -- are on screen however
// long the page. And the one list that loads more as it scrolls, a
// Utilization workflow's jobs, scrolls in its own area, so the page under
// it has an end.

test.beforeEach(async ({ page }) => {
  await installApiFixtures(page);
  await page.route('**/api/v1/auth/me', (route) =>
    route.fulfill({ json: { ...sessionFixture, superuser_allowed: true, superuser_active: false } }),
  );
});

async function accountControlsInView(page: Page) {
  const aside = page.locator('aside');
  await expect(aside.getByRole('button', { name: 'Sign out' })).toBeInViewport();
  await expect(aside.getByRole('button', { name: /^Superuser mode/ })).toBeInViewport();
  await expect(aside.getByText('e2e', { exact: true })).toBeInViewport();
}

const pageHeight = (page: Page) => page.evaluate(() => document.documentElement.scrollHeight);

test("a workflow's job list loads to its end inside its own area, and the page stays the same height", async ({
  page,
}) => {
  await page.goto('/utilization?w=wf-assemble');
  const list = page.getByTestId('workflow-jobs');
  const area = list.getByTestId('workflow-jobs-scroll');
  await expect(list).toContainText('100 of 310 shown');
  const before = await pageHeight(page);

  // Scroll the list's area to its end until every job has loaded.
  for (const shown of ['200 of 310', '300 of 310', '310 of 310']) {
    await area.evaluate((e) => e.scrollTo(0, e.scrollHeight));
    await expect(list).toContainText(`${shown} shown`);
  }
  await expect(list.getByRole('button', { name: 'Load more' })).toHaveCount(0);
  // 310 rows later, the page is no taller: they are in the area.
  expect(await pageHeight(page)).toBe(before);
  const box = (await area.boundingBox())!;
  expect(box.height).toBeLessThanOrEqual(0.7 * 720 + 2);
  // Its header stays at the top of the area while the rows scroll under it.
  const headTop = await area.locator('thead').evaluate((e) => e.getBoundingClientRect().top);
  expect(Math.abs(headTop - box.y)).toBeLessThanOrEqual(2);

  // The page's end, with the account controls on screen.
  await page.evaluate(() => window.scrollTo(0, document.documentElement.scrollHeight));
  await expect(page.locator('footer')).toBeInViewport();
  await accountControlsInView(page);
  if (process.env.PIN_SHOTS) await page.screenshot({ path: `${process.env.PIN_SHOTS}/pin-workflow-scrolled.png` });
});

test('the sidebar stays in view on a long page', async ({ page }) => {
  // Two hundred one-job batches: a long /jobs page.
  const jobs = Array.from({ length: 200 }, (_, i) => ({
    ClusterId: 5000 + i,
    ProcId: 0,
    JobStatus: 1,
    Owner: 'e2e',
    Cmd: '/bin/sleep',
    QDate: SMOKE_NOW - 600 - i,
  }));
  await page.route('**/api/v1/jobs?*', (route) => route.fulfill({ json: { jobs, has_more: false } }));
  await page.goto('/jobs');
  await expect(page.getByRole('link', { name: '5000', exact: true }).first()).toBeVisible();
  expect(await pageHeight(page)).toBeGreaterThan(720 + 400);
  await page.evaluate(() => window.scrollTo(0, document.documentElement.scrollHeight));
  expect(await page.evaluate(() => window.scrollY)).toBeGreaterThan(400);
  await accountControlsInView(page);
  await expect(page.locator('aside').getByRole('link', { name: 'Dashboard' })).toBeInViewport();
});

test.describe('in a short window', () => {
  test.use({ viewport: { width: 1280, height: 420 } });

  test('every link in the sidebar can still be reached', async ({ page }) => {
    await page.goto('/utilization?w=wf-assemble');
    const aside = page.locator('aside');
    await accountControlsInView(page);
    const last = aside.getByRole('link', { name: 'Logs' });
    await last.scrollIntoViewIfNeeded();
    await expect(last).toBeInViewport();
    await accountControlsInView(page);
  });
});

test.describe('on a phone', () => {
  test.use({ viewport: { width: 390, height: 844 } });

  test("a workflow's job list is bounded there too, and the menu still opens as a drawer", async ({ page }) => {
    await page.goto('/utilization?w=wf-assemble');
    const list = page.getByTestId('workflow-jobs');
    const area = list.getByTestId('workflow-jobs-scroll');
    await expect(list).toContainText('100 of 310 shown');
    const before = await pageHeight(page);
    await area.evaluate((e) => e.scrollTo(0, e.scrollHeight));
    await expect(list).toContainText('200 of 310 shown');
    expect(await pageHeight(page)).toBe(before);

    const aside = page.locator('aside');
    await expect(aside).not.toBeInViewport();
    await page.getByRole('button', { name: /open menu/i }).click();
    await accountControlsInView(page);
  });
});
