import { expect, test } from '@playwright/test';

import { installApiFixtures } from './fixtures/api';
import type { Branding } from '../src/lib/branding';

// A site's own branding, in a browser.
//
// The server splices these values into the <head> of the page it serves,
// as a script that runs before React hydrates. Nothing but a real
// browser can say whether that survives hydration: the exported markup
// says "HTCondor", the client render says the site's name, and React
// errors on a mismatch it is not told to expect. `serve out` cannot
// inject anything, so the init script stands in for the server --
// running at the same point, before the page's own scripts.
const site: Branding = {
  site_name: 'UChicago ATLAS Analysis Facility',
  site_tagline: 'Analysis Facility',
  page_title: 'UChicago ATLAS Analysis Facility',
  footer_logos: [{ src: '/logos/CHTC_Logo_Full_Color.svg', alt: 'ATLAS AF', href: 'https://af.example/' }],
  software_credit: true,
};

test.beforeEach(async ({ page }) => {
  await installApiFixtures(page);
});

test('a site renames the access point and keeps the HTCondor credit', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(String(e)));
  page.on('console', (m) => {
    if (m.type() === 'error') errors.push(m.text());
  });
  await page.addInitScript((b) => {
    (window as unknown as { __HTCONDOR_BRANDING__: unknown }).__HTCONDOR_BRANDING__ = b;
  }, site);

  await page.goto('/');
  const sidebar = page.locator('aside');
  await expect(sidebar.getByText('UChicago ATLAS Analysis Facility', { exact: true })).toBeVisible();
  await expect(sidebar.getByText('Analysis Facility', { exact: true })).toBeVisible();

  // The site's band, and not the one that says who runs CHTC's.
  await expect(page.getByAltText('ATLAS AF')).toBeVisible();
  await expect(page.getByAltText('University of Wisconsin–Madison')).toHaveCount(0);
  // Who wrote the software is still said.
  await expect(page.getByRole('link', { name: 'HTCondor', exact: true })).toHaveAttribute(
    'href',
    'https://htcondor.org/',
  );

  // Client-side navigation re-applies the layout's metadata, so the
  // title has to survive it.
  await sidebar.getByRole('link', { name: 'Jobs', exact: true }).click();
  await expect(page).toHaveURL(/\/jobs$/);
  await expect(page).toHaveTitle('UChicago ATLAS Analysis Facility');

  // Hydration is the point of this test: a mismatch between the
  // exported markup and the branded render lands here.
  expect(errors, 'branding raised page errors').toEqual([]);
});

test('an unconfigured deployment is unchanged', async ({ page }) => {
  await page.goto('/');
  await expect(page.locator('aside').getByText('HTCondor', { exact: true })).toBeVisible();
  await expect(page.getByAltText('University of Wisconsin–Madison')).toBeVisible();
  await expect(page.getByText(/Powered by/)).toHaveCount(0);
  await expect(page).toHaveTitle('HTCondor Access Point');
});
