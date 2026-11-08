import { expect, test } from '@playwright/test';

import { installApiFixtures } from './fixtures/api';
import { installReservationFixtures } from './fixtures/reservations';
import type { AdminReservation } from '../src/lib/api';

// The admin reservations page against mocked responses.
//
// The clock, timezone and locale are pinned (fixtures/clock.ts), so the
// rendered window times are exact rather than "something date-shaped":
// the page's job is to turn `0 14 * * 1,3` into "Thu, Oct 15, 2:00 PM",
// and an assertion that does not name the time is not testing that.

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

test('reservations: the list shows each hold and its shape', async ({ page }) => {
  const errors = watchForErrors(page);
  await installReservationFixtures(page);

  await page.goto('/admin/reservations');
  await expect(page.getByRole('heading', { name: 'Reservations' })).toBeVisible();

  const cs301 = page.getByTestId('reservation-cs301');
  await expect(cs301).toContainText('cs301-f26');
  await expect(cs301).toContainText('0 14 * * 1,3');
  await expect(cs301).toContainText('America/Chicago');
  // Seconds on the wire, hours and minutes on the page.
  await expect(cs301).toContainText('1 h');
  await expect(cs301).toContainText('held 15 min past the bell');
  await expect(cs301).toContainText('6 h before');
  await expect(cs301).toContainText('48');
  await expect(cs301).toContainText('Enabled');

  const astro = page.getByTestId('reservation-astro-lab');
  await expect(astro).toContainText('2 h 30 min');
  await expect(astro).toContainText('1 h 30 min before');
  await expect(astro).toContainText('Disabled');

  expect(errors).toEqual([]);
});

test('reservations: the preview names the drain and the bell separately', async ({ page }) => {
  const errors = watchForErrors(page);
  await installReservationFixtures(page);

  await page.goto('/admin/reservations');
  await page
    .getByTestId('reservation-cs301')
    .getByRole('button', { name: 'Upcoming' })
    .click();

  const preview = page.getByTestId('windows-cs301');
  await expect(preview).toBeVisible();
  await expect(preview.getByRole('columnheader', { name: 'Draining starts' })).toBeVisible();
  await expect(preview.getByRole('columnheader', { name: 'Seats held' })).toBeVisible();

  // Thursday's window: the bell is 2:00 PM, and with a six-hour lead the
  // pool starts being steered away from those machines at 8:00 AM.
  const thursday = preview.getByRole('row').nth(1);
  await expect(thursday).toContainText('Oct 15');
  await expect(thursday).toContainText('8:00 AM');
  await expect(thursday).toContainText('2:00 PM');
  await expect(thursday).toContainText('3:00 PM');

  // Monday's is two scheduled starts held as one.
  const monday = preview.getByRole('row').nth(2);
  await expect(monday).toContainText('Oct 19');
  await expect(monday).toContainText('3:00 AM');
  await expect(monday).toContainText('9:00 AM');
  await expect(monday).toContainText('2 occurrences held as one');

  // The horizon is the operator's to widen.
  await preview.getByLabel('Preview horizon').selectOption('30');
  await expect(preview.getByRole('row')).toHaveCount(3);

  await page
    .getByTestId('reservation-cs301')
    .getByRole('button', { name: 'Hide upcoming' })
    .click();
  await expect(page.getByTestId('windows-cs301')).toHaveCount(0);

  expect(errors).toEqual([]);
});

test("reservations: a rejected save shows the server's own reason", async ({ page }) => {
  const errors = watchForErrors(page);
  const { writes } = await installReservationFixtures(page);

  await page.goto('/admin/reservations');
  await page.getByRole('button', { name: 'New reservation' }).click();
  const form = page.getByTestId('reservation-form');

  await form.getByLabel('Name', { exact: true }).fill('phys200');
  await form.getByLabel('Project', { exact: true }).fill('phys200-f26');
  await form.getByLabel('Schedule', { exact: true }).fill('every tuesday');
  await form.getByRole('button', { name: 'Create reservation' }).click();

  // Verbatim, including the quoting: the server is the authority on what
  // a schedule may be, and paraphrasing it here would drift.
  await expect(page.getByTestId('reservation-error')).toHaveText(
    'parsing schedule "every tuesday": expected 5 fields, got 2',
  );
  // Nothing was stored, and the form kept what was typed.
  await expect(page.getByTestId('reservation-phys200')).toHaveCount(0);
  await expect(form.getByLabel('Project', { exact: true })).toHaveValue('phys200-f26');

  // Fix it, and set the two durations in hours and minutes.
  await form.getByLabel('Schedule', { exact: true }).fill('0 10 * * 2');
  await form.getByLabel('Window length hours').fill('1');
  await form.getByLabel('Window length minutes').fill('30');
  await form.getByLabel('Drain lead hours').fill('4');
  await form.getByLabel('Drain lead minutes').fill('0');
  // Not exact: a wrapping label's accessible name picks up the
  // textarea's own contents.
  await form
    .getByLabel('Submit file')
    .fill('executable = /usr/bin/python3\nqueue\n');
  await form.getByRole('button', { name: 'Create reservation' }).click();

  const row = page.getByTestId('reservation-phys200');
  await expect(row).toContainText('1 h 30 min');
  await expect(row).toContainText('4 h before');

  // Seconds went over the wire.
  const created = writes.filter((w) => w.method === 'POST').pop()!
    .body as AdminReservation;
  expect(created.duration_seconds).toBe(5400);
  expect(created.lead_seconds).toBe(4 * 3600);
  expect(created.schedule).toBe('0 10 * * 2');

  // A save opens the preview on what was saved: the schedule was typed
  // as cron a second ago, so this is when it is worth reading.
  const preview = page.getByTestId('windows-phys200');
  await expect(preview).toBeVisible();
  // Four hours before the 2:00 PM bell.
  await expect(preview.getByRole('row').nth(1)).toContainText('10:00 AM');

  // The refused save is a 400 by design, and the browser logs every
  // failed request; everything else still has to be clean.
  expect(errors.filter((e) => !e.includes('400 (Bad Request)'))).toEqual([]);
});

test('reservations: disable and delete', async ({ page }) => {
  const errors = watchForErrors(page);
  const { writes, stored } = await installReservationFixtures(page);

  await page.goto('/admin/reservations');
  const cs301 = page.getByTestId('reservation-cs301');
  await cs301.getByRole('button', { name: 'Disable' }).click();
  await expect(cs301).toContainText('Disabled');
  expect((writes.at(-1)!.body as AdminReservation).enabled).toBe(false);

  await cs301.getByRole('button', { name: /^Delete reservation "cs301"/ }).click();
  await cs301.getByRole('button', { name: 'Delete', exact: true }).click();
  await expect(page.getByTestId('reservation-cs301')).toHaveCount(0);
  expect(stored().map((r) => r.id)).toEqual(['astro-lab']);

  expect(errors).toEqual([]);
});
