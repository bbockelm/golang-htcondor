import { expect, test } from '@playwright/test';

import { installApiFixtures } from './fixtures/api';

// The submission page's manual table. The shared fixture publishes no
// templates, so this installs one with columns -- without columns the
// page renders the single-job fallback and there is no table at all.

test.beforeEach(async ({ page }) => {
  await installApiFixtures(page);
  await page.route('**/api/v1/templates', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        templates: [
          {
            id: 'sweep',
            name: 'Sweep',
            columns: [{ name: 'name' }, { name: 'seconds' }],
            contents: 'executable = /bin/sleep\ntransfer_executable = false\narguments = $(seconds)\n',
            source: 'builtin',
          },
        ],
      }),
    }),
  );
});

// Fills the table with `count` rows and returns the cell locator factory.
async function fillRows(page: import('@playwright/test').Page, count: number) {
  const cells = () => page.locator('table input[type="text"]');
  for (let i = 1; i < count; i++) {
    await page.getByRole('button', { name: '+ Add row' }).click();
  }
  for (let i = 0; i < count; i++) {
    await cells().nth(i * 2).fill(`job-${i}`);
    await cells().nth(i * 2 + 1).fill(`${i * 10}`);
  }
  return cells;
}

// Reported: clearing the table took one click per row. The per-row ×
// stops at the last row and cannot empty it, so a 50-row sweep was 49
// clicks and still left a filled row behind.
test('the table clears in one click', async ({ page }) => {
  await page.goto('/submit');
  const cells = await fillRows(page, 3);
  await expect(cells()).toHaveCount(6);

  await page.getByRole('button', { name: 'Clear table' }).click();

  // One blank row is left: a table with no rows would submit no jobs
  // and give the user nowhere to type.
  await expect(cells()).toHaveCount(2);
  await expect(cells().nth(0)).toHaveValue('');
  await expect(cells().nth(1)).toHaveValue('');
});

// Nothing to clear is not an action: the button would otherwise look
// broken, having no visible effect on an already-empty table.
test('Clear table is disabled when the table is already empty', async ({ page }) => {
  await page.goto('/submit');
  const clear = page.getByRole('button', { name: 'Clear table' });
  await expect(clear).toBeDisabled();

  await page.locator('table input[type="text"]').first().fill('something');
  await expect(clear).toBeEnabled();
});

// One misclick must not be the end of a hand-typed parameter sweep.
test('a cleared table can be undone', async ({ page }) => {
  await page.goto('/submit');
  const cells = await fillRows(page, 3);

  await page.getByRole('button', { name: 'Clear table' }).click();
  await expect(page.getByText('Cleared 3 rows.')).toBeVisible();

  await page.getByRole('button', { name: 'Undo' }).click();
  await expect(cells()).toHaveCount(6);
  await expect(cells().nth(0)).toHaveValue('job-0');
  await expect(cells().nth(5)).toHaveValue('20');
  await expect(page.getByRole('button', { name: 'Undo' })).toBeHidden();
});

// Undo restores what was cleared, so offering it after the user has
// started typing again would discard the new work instead of restoring
// the old. It expires on the first keystroke rather than on a timer.
test('Undo disappears once the user types again', async ({ page }) => {
  await page.goto('/submit');
  await fillRows(page, 2);

  await page.getByRole('button', { name: 'Clear table' }).click();
  await expect(page.getByRole('button', { name: 'Undo' })).toBeVisible();

  await page.locator('table input[type="text"]').first().fill('starting over');
  await expect(page.getByRole('button', { name: 'Undo' })).toBeHidden();
  await expect(page.getByText(/^Cleared /)).toBeHidden();
});
