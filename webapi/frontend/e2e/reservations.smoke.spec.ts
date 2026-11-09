import { expect, test } from '@playwright/test';

import { installApiFixtures } from './fixtures/api';
import { cs301Fixture, installReservationFixtures } from './fixtures/reservations';
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
  await expect(cs301).toContainText('unclaimed slots held 15 min past the start');
  await expect(cs301).toContainText('6 h before');
  await expect(cs301).toContainText('48');
  await expect(cs301).toContainText('Enabled');

  const astro = page.getByTestId('reservation-astro-lab');
  await expect(astro).toContainText('2 h 30 min');
  await expect(astro).toContainText('1 h 30 min before');
  await expect(astro).toContainText('Disabled');

  expect(errors).toEqual([]);
});

test('reservations: the preview names the drain and the start separately', async ({ page }) => {
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
  await expect(preview.getByRole('columnheader', { name: 'Slots held' })).toBeVisible();

  // Thursday's hold: the reservation starts at 2:00 PM, and with a six-hour lead the
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

  // Fix it, and set the two durations in hours and minutes. The minute
  // boxes step in quarter hours, which is a spinner's increment and not
  // a restriction: a 50-minute reservation still types.
  await form.getByLabel('Schedule', { exact: true }).fill('0 10 * * 2');
  await expect(form.getByLabel('Reservation length minutes')).toHaveAttribute('step', '15');
  await form.getByLabel('Reservation length hours').fill('1');
  await form.getByLabel('Reservation length minutes').fill('50');
  await expect(form.getByLabel('Reservation length minutes')).toHaveValue('50');
  await form.getByLabel('Reservation length minutes').fill('30');
  await form.getByLabel('Drain lead hours').fill('4');
  await form.getByLabel('Drain lead minutes').fill('0');
  // The slot's shape is the same resource request the submit page asks
  // for, since the file a new reservation starts from is one the fields
  // can state.
  await expect(form.getByTestId('reservation-submit-fields')).toBeVisible();
  await form.getByLabel('CPUs').fill('2');
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
  // Only the number that was typed changed; the rest of the file is the
  // one the form opened on.
  expect(created.submit).toBe(
    'executable = /usr/bin/python3\nrequest_cpus = 2\nrequest_memory = 4096\nqueue\n',
  );

  // A save opens the preview on what was saved: the schedule was typed
  // as cron a second ago, so this is when it is worth reading.
  const preview = page.getByTestId('windows-phys200');
  await expect(preview).toBeVisible();
  // Four hours before the 2:00 PM start.
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

// The two ways a reservation holds nothing while looking fine. Neither
// shows up anywhere else: no reservation reports an error, no job
// fails, and every class quietly starts on a pool that was never
// drained.

test('reservations: a refused machine-ad update is surfaced', async ({ page }) => {
  const errors = watchForErrors(page);
  await installReservationFixtures(page, undefined, {
    running: true,
    healthy: false,
    outcome: 'denied',
    machine: 'wn07.example.edu',
    detail: 'startd: CA_UPDATE_MACHINE_AD refused (NotAuthorized): denied',
    checked_at: '2026-10-14T11:58:00-05:00',
  });

  await page.goto('/admin/reservations');
  await expect(page.getByText('could not update wn07.example.edu')).toBeVisible();
  await expect(page.getByText('NotAuthorized')).toBeVisible();
  expect(errors).toEqual([]);
});

test('reservations: execute points without the stanza are named, with the line to add', async ({
  page,
}) => {
  const errors = watchForErrors(page);
  await installReservationFixtures(page, undefined, {
    running: true,
    // Healthy on purpose: this access point is working. What is missing
    // is a line in somebody else's configuration file, and saying the
    // access point is broken sends an admin to the wrong place.
    healthy: true,
    outcome: 'unprovisioned',
    machine: 'wn04.example.edu',
    unprovisioned: ['wn04.example.edu', 'wn09.example.edu'],
    stanza: 'START = $(START) && ( ReservationStart ?: True )',
    checked_at: '2026-10-14T11:58:00-05:00',
  });

  await page.goto('/admin/reservations');
  await expect(
    page.getByText('2 execute points are not set up for reservations'),
  ).toBeVisible();
  await expect(page.getByText('START = $(START) && ( ReservationStart ?: True )')).toBeVisible();
  await expect(page.getByText('wn04.example.edu')).toBeVisible();
  await expect(page.getByText('wn09.example.edu')).toBeVisible();
  // The access point itself is fine, so the other banner must not fire.
  await expect(page.getByText('could not update')).toHaveCount(0);
  expect(errors).toEqual([]);
});

test('reservations: a healthy pool shows no warning at all', async ({ page }) => {
  await installReservationFixtures(page);
  await page.goto('/admin/reservations');
  await expect(page.getByRole('heading', { name: 'Reservations' })).toBeVisible();
  await expect(page.getByText('not set up for reservations')).toHaveCount(0);
  await expect(page.getByText('could not update')).toHaveCount(0);
});

// What the submit file does on the way in and out. It is stored as a
// file and parsed by the server, so the fields are shown only over a
// file they can hand back unchanged; everything else is text. Saving
// without touching it has to return the stored bytes either way.

test('reservations: a submit file the fields can state is saved unchanged', async ({
  page,
}) => {
  const errors = watchForErrors(page);
  const { writes } = await installReservationFixtures(page);

  await page.goto('/admin/reservations');
  await page.getByTestId('reservation-cs301').getByRole('button', { name: 'Edit' }).click();
  const form = page.getByTestId('reservation-form');

  const fields = form.getByTestId('reservation-submit-fields');
  await expect(fields).toBeVisible();
  await expect(fields.getByLabel('CPUs')).toHaveValue('4');
  await expect(fields.getByLabel('Memory (MiB)', { exact: true })).toHaveValue('16384');
  await expect(fields.getByLabel('GPUs', { exact: true })).toHaveValue('1');
  // Whatever the fields have no box for is still in the file, and still
  // editable.
  await expect(fields.getByRole('textbox', { name: /Other submit commands/ })).toHaveValue(
    'executable = /usr/bin/jupyter',
  );

  await form.getByRole('button', { name: 'Save changes' }).click();

  const saved = writes.filter((w) => w.method === 'POST').pop()!
    .body as AdminReservation;
  expect(saved.submit).toBe(cs301Fixture.submit);

  expect(errors).toEqual([]);
});

test('reservations: a submit file the fields would reformat stays text', async ({
  page,
}) => {
  const errors = watchForErrors(page);
  // The same commands, written without the spaces the fields would put
  // back. Nothing about it is invalid; it simply is not the form's own
  // spelling, and a save must not make it so.
  const stored = 'executable = /bin/sleep\nrequest_cpus=4\nqueue\n';
  const { writes } = await installReservationFixtures(page, [
    { ...cs301Fixture, submit: stored },
  ]);

  await page.goto('/admin/reservations');
  await page.getByTestId('reservation-cs301').getByRole('button', { name: 'Edit' }).click();
  const form = page.getByTestId('reservation-form');

  await expect(form.getByTestId('reservation-submit-fields')).toHaveCount(0);
  await expect(form.getByTestId('reservation-submit-text')).toBeVisible();
  await expect(form.getByText('Edited as text')).toBeVisible();

  await form.getByRole('button', { name: 'Save changes' }).click();
  const saved = writes.filter((w) => w.method === 'POST').pop()!
    .body as AdminReservation;
  expect(saved.submit).toBe(stored);

  expect(errors).toEqual([]);
});

test('reservations: the schedule is picked, and the expression follows', async ({
  page,
}) => {
  const errors = watchForErrors(page);
  const { writes } = await installReservationFixtures(page);

  await page.goto('/admin/reservations');
  await page.getByTestId('reservation-cs301').getByRole('button', { name: 'Edit' }).click();
  const form = page.getByTestId('reservation-form');

  // The stored reservation, as a calendar reads it: Mondays and
  // Wednesdays at two, from the start of term to the end of it.
  await expect(form.getByLabel('Monday')).toHaveAttribute('aria-pressed', 'true');
  await expect(form.getByLabel('Wednesday')).toHaveAttribute('aria-pressed', 'true');
  await expect(form.getByLabel('Friday')).toHaveAttribute('aria-pressed', 'false');
  await expect(form.getByLabel('Start time')).toHaveValue('14:00');
  await expect(form.getByLabel('Start date')).toHaveValue('2026-09-02');
  await expect(form.getByLabel('Repeat until')).toHaveValue('2026-12-11');
  await expect(form.getByLabel('Schedule', { exact: true })).toHaveValue('0 14 * * 1,3');

  // Add Friday and move the bell by a quarter hour.
  await form.getByLabel('Friday').click();
  await form.getByLabel('Start time').fill('14:15');
  await expect(form.getByLabel('Schedule', { exact: true })).toHaveValue(
    '15 14 * * 1,3,5',
  );

  await form.getByRole('button', { name: 'Save changes' }).click();

  const saved = writes.filter((w) => w.method === 'POST').pop()!
    .body as AdminReservation;
  expect(saved.schedule).toBe('15 14 * * 1,3,5');
  // The bounds are written with the reservation's own offset, not the
  // browser's, and only one of them is ever set.
  expect(saved.starts_at).toBe('2026-09-02T14:15:00-05:00');
  expect(saved.ends_at).toBe('2026-12-11T23:59:59-06:00');
  expect(saved.occurrences).toBe(0);

  // And the row says what stops it.
  await expect(page.getByTestId('reservation-cs301')).toContainText(
    'Sep 2, 2026 – Dec 11, 2026',
  );

  expect(errors).toEqual([]);
});

test('reservations: a hand-written expression is left alone', async ({ page }) => {
  const errors = watchForErrors(page);
  const { writes } = await installReservationFixtures(page);

  await page.goto('/admin/reservations');
  await page.getByTestId('reservation-cs301').getByRole('button', { name: 'Edit' }).click();
  const form = page.getByTestId('reservation-form');

  await form.getByLabel('Schedule', { exact: true }).fill('*/15 9-17 * * 1-5');
  await expect(form.getByLabel('Custom')).toBeChecked();
  await expect(form.getByLabel('Start time')).toBeDisabled();

  // The bound is not part of the expression, so it is still the
  // operator's to set.
  await form.getByLabel('Number of windows').fill('4');
  await form.getByRole('button', { name: 'Save changes' }).click();

  const saved = writes.filter((w) => w.method === 'POST').pop()!
    .body as AdminReservation;
  expect(saved.schedule).toBe('*/15 9-17 * * 1-5');
  expect(saved.occurrences).toBe(4);
  expect(saved.ends_at).toBe('');

  expect(errors).toEqual([]);
});
