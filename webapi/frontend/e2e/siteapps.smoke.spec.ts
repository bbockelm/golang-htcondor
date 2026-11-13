import { expect, test } from '@playwright/test';

import { installApiFixtures } from './fixtures/api';

// The site apps admin page, drawn by a real browser.
//
// This page was once written against class names -- card, muted,
// table, badge -- that no stylesheet in this project defines, so every
// unit test passed against a page that rendered as unstyled text. A
// browser is the only thing that notices.
//
// What a frozen fixture can state honestly is the read-only half: an
// app the configuration publishes, its settings named as the
// configuration names them, and what has been served. The editable
// half needs a server that will accept the change, which is the full
// suite's business.
// A console error fails the test: a page that throws while rendering
// still shows most of itself, and "it looked fine" is exactly how the
// unstyled version shipped.
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
});

test('an app row opens onto its settings and its history', async ({ page }) => {
  const errors = watchForErrors(page);
  await page.goto('/admin/site-apps');

  const row = page.getByTestId('app-cryoem');
  await expect(row).toBeVisible();
  await expect(page.getByTestId('details-cryoem')).toHaveCount(0);

  // The row itself, not a button at the end of it.
  await row.click();
  await expect(page.getByTestId('details-cryoem')).toBeVisible();

  // The settings are the configuration's parameters, under the names
  // condor_config_val would answer to.
  await expect(page.getByTestId('config-groups')).toContainText(
    'HTTP_API_SITE_APP_CRYOEM_GROUPS',
  );
  await expect(page.getByTestId('config-groups')).toContainText('smith_lab');
  // And the page does not pretend they can be changed here.
  await expect(page.getByTestId('config-readonly')).toContainText('condor_reconfig');
  await expect(page.getByTestId('config-edit')).toHaveCount(0);

  // The audit trail beneath it: the earlier period's wider groups are
  // the whole reason it is recorded per period.
  await expect(page.getByTestId('history-table')).toContainText('2.0.0');
  await expect(page.getByTestId('history-table')).toContainText('jones_lab');

  expect(errors).toEqual([]);
});

test('who may see an app is a checkbox and pills, not a typed list', async ({ page }) => {
  await page.goto('/admin/site-apps');

  // A NEW app: the form opens on replacing one, because that is the
  // commoner act and the one that must not be mistyped.
  await page.getByTestId('mode-new').check();
  const groups = page.getByTestId('upload-groups');
  await groups.fill('smith_lab');
  await groups.press('Enter');
  await expect(page.getByTestId('group-pill-smith_lab')).toBeVisible();

  // Removing one is a click, not an edit of a comma-separated string.
  await page.getByTestId('group-remove-smith_lab').click();
  await expect(page.getByTestId('group-pill-smith_lab')).toHaveCount(0);

  // "Everyone" is a different decision from "these groups", so the
  // box replaces the list rather than sitting beside it.
  await page.getByTestId('upload-everyone').check();
  await expect(page.getByTestId('upload-groups')).toHaveCount(0);
});

test('the form refuses an id the server would refuse', async ({ page }) => {
  await page.goto('/admin/site-apps');

  // Leaving the field is enough: the bundle input is required, so a
  // browser refuses the submit before the form's own checks run, and
  // an id error that only fired on submit would never be seen.
  await page.getByTestId('mode-new').check();
  await page.getByTestId('upload-id').fill('CryoEM');
  await page.getByTestId('upload-id').blur();
  await expect(page.getByTestId('upload-id-error')).toContainText('lowercase');
});

test('replacing an app is chosen from a list, not typed', async ({ page }) => {
  // Reported: meaning to replace `demos`, an administrator typed
  // `demo` and got a second app. Both ids are valid, so nothing
  // refused it and nothing said anything.
  await page.goto('/admin/site-apps');

  // The form opens on replacing, with the app named and its own
  // audience already in the box -- replacing a bundle is not a
  // decision about who may see it.
  await expect(page.getByTestId('mode-update')).toBeChecked();
  await expect(page.getByTestId('upload-target')).toHaveValue('seq-qc');
  await expect(page.getByTestId('upload-replacing')).toContainText('/site/seq-qc/');
  await expect(page.getByTestId('group-pill-jones_lab')).toBeVisible();
  // No id field at all in this mode, so there is nothing to mistype.
  await expect(page.getByTestId('upload-id')).toHaveCount(0);
  await expect(page.getByTestId('upload-submit')).toContainText('Replace bundle');

  // And a new app whose id is nearly one that exists is questioned
  // before the bundle goes up -- a question, not a refusal, with the
  // intended act one click away.
  await page.getByTestId('mode-new').check();
  await page.getByTestId('upload-id').fill('seq-qa');
  await expect(page.getByTestId('upload-near-miss')).toContainText('seq-qc');
  await page.getByTestId('upload-near-miss-switch').click();
  await expect(page.getByTestId('mode-update')).toBeChecked();
  await expect(page.getByTestId('upload-target')).toHaveValue('seq-qc');
});
