import { expect, test } from '@playwright/test';

import { installApiFixtures } from './fixtures/api';
import { cs301Fixture, installReservationFixtures } from './fixtures/reservations';
import type { AdminReservation } from '../src/lib/api';

// The admin reservations page against mocked responses.
//
// The clock, timezone and locale are pinned (fixtures/clock.ts), so the
// rendered window times are exact rather than "something date-shaped":
// the page's job is to turn a schedule into "Thu, Oct 15, 2:00 PM", and
// an assertion that does not name the time is not testing that.

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
  // A recurrence reads as what it is, not as an expression nobody
  // typed.
  await expect(cs301).toContainText('Every week on Monday and Wednesday');
  await expect(cs301).toContainText('America/Chicago');
  // Seconds on the wire, hours and minutes on the page.
  await expect(cs301).toContainText('1 h');
  await expect(cs301).toContainText('unclaimed slots held 15 min past the start');
  await expect(cs301).toContainText('6 h before');
  await expect(cs301).toContainText('48');
  await expect(cs301).toContainText('Enabled');

  // A hand-written expression stays an expression.
  const astro = page.getByTestId('reservation-astro-lab');
  await expect(astro).toContainText('30 9 * * 5');
  await expect(astro).toContainText('2 h 30 min');
  await expect(astro).toContainText('1 h 30 min before');
  await expect(astro).toContainText('Disabled');

  // And a reservation that never stops says so instead of a schedule.
  const openlab = page.getByTestId('reservation-openlab');
  await expect(openlab).toContainText('Always on');

  expect(errors).toEqual([]);
});

test('reservations: an always-on reservation has no windows, and says why', async ({
  page,
}) => {
  const errors = watchForErrors(page);
  await installReservationFixtures(page);

  await page.goto('/admin/reservations');
  await page
    .getByTestId('reservation-openlab')
    .getByRole('button', { name: 'Upcoming' })
    .click();

  // An empty list means two different things, and this is the one that
  // is holding capacity right now.
  const preview = page.getByTestId('windows-openlab');
  await expect(preview).toContainText('held continuously');
  await expect(preview).not.toContainText('Nothing scheduled');

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
  // The expression box appears with the repeat that uses it, and not
  // before: it is the one control here anybody has to learn.
  await expect(form.getByLabel('Schedule', { exact: true })).toHaveCount(0);
  await form.getByLabel('Custom').check();
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
  expect(stored().map((r) => r.id)).toEqual(['astro-lab', 'openlab']);

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

test('reservations: the schedule is picked, and previewed as it is picked', async ({
  page,
}) => {
  const errors = watchForErrors(page);
  const { writes, previews } = await installReservationFixtures(page);

  await page.goto('/admin/reservations');
  await page.getByTestId('reservation-cs301').getByRole('button', { name: 'Edit' }).click();
  const form = page.getByTestId('reservation-form');

  // The stored reservation, as a calendar reads it: Mondays and
  // Wednesdays at two, from the start of term to the end of it.
  await expect(form.getByLabel('Weekly')).toBeChecked();
  await expect(form.getByLabel('Monday')).toHaveAttribute('aria-pressed', 'true');
  await expect(form.getByLabel('Wednesday')).toHaveAttribute('aria-pressed', 'true');
  await expect(form.getByLabel('Friday')).toHaveAttribute('aria-pressed', 'false');
  await expect(form.getByLabel('Start time')).toHaveValue('14:00');
  await expect(form.getByLabel('Start date')).toHaveValue('2026-09-02');
  await expect(form.getByLabel('Repeat until')).toHaveValue('2026-12-11');

  // The days it lands on, under the controls, from the server.
  const preview = form.getByTestId('reservation-window-preview');
  await expect(preview.getByRole('row').nth(1)).toContainText('Oct 15');
  await expect(preview.getByRole('row').nth(1)).toContainText('2:00 PM');

  // Add Friday, move the bell by a quarter hour, and make it every
  // other week -- which cron has no way to say at all.
  await form.getByLabel('Friday').click();
  await form.getByLabel('Start time').fill('14:15');
  await form.getByLabel('Repeat every').fill('2');

  // The preview follows, once the typing has stopped. It is of the
  // draft in the boxes, not of the stored reservation.
  await expect
    .poll(() => previews.at(-1)!.recurrence)
    .toEqual({
      freq: 'weekly',
      interval: 2,
      by_weekday: [1, 3, 5],
      time_of_day: '14:15',
    });

  await form.getByRole('button', { name: 'Save changes' }).click();

  const saved = writes.filter((w) => w.method === 'POST').pop()!
    .body as AdminReservation;
  expect(saved.schedule_kind).toBe('recurrence');
  expect(saved.recurrence).toEqual({
    freq: 'weekly',
    interval: 2,
    by_weekday: [1, 3, 5],
    time_of_day: '14:15',
  });
  // Nothing generated an expression from it. A recurrence saying "every
  // other week" has no cron spelling, and writing the nearest one would
  // run it on different days.
  expect(saved.schedule).toBe('');
  // The bounds are written with the reservation's own offset, not the
  // browser's, and only one of them is ever set.
  expect(saved.starts_at).toBe('2026-09-02T14:15:00-05:00');
  expect(saved.ends_at).toBe('2026-12-11T23:59:59-06:00');
  expect(saved.occurrences).toBe(0);

  // And the row says what it is and what stops it.
  await expect(page.getByTestId('reservation-cs301')).toContainText(
    'Every 2 weeks on Monday, Wednesday and Friday',
  );
  await expect(page.getByTestId('reservation-cs301')).toContainText(
    'Sep 2, 2026 \u2013 Dec 11, 2026',
  );

  expect(errors).toEqual([]);
});

test('reservations: a monthly schedule can count a day within the month', async ({
  page,
}) => {
  const errors = watchForErrors(page);
  const { writes } = await installReservationFixtures(page);

  await page.goto('/admin/reservations');
  await page.getByTestId('reservation-cs301').getByRole('button', { name: 'Edit' }).click();
  const form = page.getByTestId('reservation-form');

  await form.getByLabel('Monthly').check();
  // It opens on the start date's own day of the month, which is what
  // somebody choosing "monthly" almost always means.
  await expect(form.getByLabel('Day 2 of the month')).toHaveAttribute(
    'aria-pressed',
    'true',
  );
  await form.getByLabel('Day 16 of the month').click();

  await form.getByRole('button', { name: 'Save changes' }).click();
  expect(
    (writes.filter((w) => w.method === 'POST').pop()!.body as AdminReservation).recurrence,
  ).toEqual({ freq: 'monthly', interval: 1, by_monthday: [2, 16], time_of_day: '14:00' });

  // And the other way of saying a monthly day: the last Friday.
  await page.getByTestId('reservation-cs301').getByRole('button', { name: 'Edit' }).click();
  await form.getByLabel('Monthly').check();
  await form.getByLabel('On the', { exact: true }).check();
  await form.getByLabel('Which one in the month').selectOption('-1');
  await form.getByLabel('Day of the month to count').selectOption('5');
  await form.getByRole('button', { name: 'Save changes' }).click();

  expect(
    (writes.filter((w) => w.method === 'POST').pop()!.body as AdminReservation).recurrence,
  ).toEqual({
    freq: 'monthly',
    interval: 1,
    by_setpos: -1,
    by_weekday: [5],
    time_of_day: '14:00',
  });
  await expect(page.getByTestId('reservation-cs301')).toContainText(
    'The last Friday of every month',
  );

  expect(errors).toEqual([]);
});

test('reservations: choosing the expression is undone by choosing a repeat', async ({
  page,
}) => {
  const errors = watchForErrors(page);
  const { writes } = await installReservationFixtures(page);

  await page.goto('/admin/reservations');
  await page.getByTestId('reservation-cs301').getByRole('button', { name: 'Edit' }).click();
  const form = page.getByTestId('reservation-form');

  await form.getByLabel('Custom').check();
  await form.getByLabel('Schedule', { exact: true }).fill('*/15 9-17 * * 1-5');
  await expect(form.getByLabel('Monday')).toHaveCount(0);

  // The bound is not part of the expression, so it is still the
  // operator's to set.
  await form.getByLabel('Number of windows').fill('4');

  // And the way back is the way in. Nothing was lost on either leg, so
  // a mistaken click costs a click.
  await form.getByLabel('Weekly').check();
  await expect(form.getByLabel('Monday')).toHaveAttribute('aria-pressed', 'true');
  await expect(form.getByLabel('Wednesday')).toHaveAttribute('aria-pressed', 'true');
  await expect(form.getByLabel('Start time')).toHaveValue('14:00');
  await form.getByLabel('Custom').check();
  await expect(form.getByLabel('Schedule', { exact: true })).toHaveValue(
    '*/15 9-17 * * 1-5',
  );

  await form.getByRole('button', { name: 'Save changes' }).click();
  const saved = writes.filter((w) => w.method === 'POST').pop()!
    .body as AdminReservation;
  expect(saved.schedule_kind).toBe('cron');
  expect(saved.schedule).toBe('*/15 9-17 * * 1-5');
  expect(saved.recurrence).toBeNull();
  expect(saved.occurrences).toBe(4);
  expect(saved.ends_at).toBe('');

  expect(errors).toEqual([]);
});

test('reservations: an always-on reservation asks for no window at all', async ({
  page,
}) => {
  const errors = watchForErrors(page);
  const { writes } = await installReservationFixtures(page);

  await page.goto('/admin/reservations');
  await page.getByTestId('reservation-cs301').getByRole('button', { name: 'Edit' }).click();
  const form = page.getByTestId('reservation-form');

  await form.getByLabel('Always on').check();
  // Nothing that describes a window is asked for, because there is no
  // window to describe.
  await expect(form.getByLabel('Reservation length hours')).toHaveCount(0);
  await expect(form.getByLabel('Drain lead hours')).toHaveCount(0);
  await expect(form.getByLabel('Number of windows')).toHaveCount(0);
  await expect(form.getByLabel('Schedule', { exact: true })).toHaveCount(0);
  await expect(form.getByTestId('reservation-window-preview')).toContainText(
    'held continuously',
  );

  await form.getByRole('button', { name: 'Save changes' }).click();
  const saved = writes.filter((w) => w.method === 'POST').pop()!
    .body as AdminReservation;
  expect(saved.schedule_kind).toBe('always');
  expect(saved.schedule).toBe('');
  expect(saved.recurrence).toBeNull();
  // An end date was on the stored reservation and still bounds it; a
  // count of windows is refused for one that has none.
  expect(saved.ends_at).toBe('2026-12-11T23:59:59-06:00');
  expect(saved.occurrences).toBe(0);

  await expect(page.getByTestId('reservation-cs301')).toContainText('Always on');

  expect(errors).toEqual([]);
});

test('reservations: an interval above one is asked for a start date, not refused later', async ({
  page,
}) => {
  const errors = watchForErrors(page);
  await installReservationFixtures(page);

  await page.goto('/admin/reservations');
  await page.getByRole('button', { name: 'New reservation' }).click();
  const form = page.getByTestId('reservation-form');

  // A new reservation starts on the controls, and says which day it
  // still needs rather than leaving the operator to find out from a
  // rejected save.
  await expect(form.getByLabel('Weekly')).toBeChecked();
  // Said twice: against the control that needs it, and against the
  // button that is waiting on it.
  await expect(form.getByText('Choose at least one day of the week.')).toHaveCount(2);
  await expect(form.getByRole('button', { name: 'Create reservation' })).toBeDisabled();

  await form.getByLabel('Tuesday').click();
  await expect(form.getByRole('button', { name: 'Create reservation' })).toBeEnabled();

  // Every other week needs a week to count from, so one is filled in
  // where it can be seen and changed.
  await form.getByLabel('Repeat every').fill('2');
  await expect(form.getByLabel('Start date')).toHaveValue('2026-10-14');

  // Cleared anyway, the form asks for it instead of sending a
  // reservation the server would refuse.
  await form.getByLabel('Start date').fill('');
  await expect(form.getByText(/needs a start date to count from/)).toHaveCount(2);
  await expect(form.getByRole('button', { name: 'Create reservation' })).toBeDisabled();

  expect(errors).toEqual([]);
});

test('reservations: the minute spinner rolls over into the hour', async ({ page }) => {
  const errors = watchForErrors(page);
  await installReservationFixtures(page);

  await page.goto('/admin/reservations');
  await page.getByTestId('reservation-cs301').getByRole('button', { name: 'Edit' }).click();
  const form = page.getByTestId('reservation-form');

  const hours = form.getByLabel('Drain lead hours');
  const minutes = form.getByLabel('Drain lead minutes');
  await expect(minutes).toHaveAttribute('step', '15');

  // Up from 45 is the next hour at zero; the arrow used to do nothing.
  await minutes.fill('45');
  await minutes.press('ArrowUp');
  await expect(hours).toHaveValue('7');
  await expect(minutes).toHaveValue('0');

  // And down from zero is the previous hour at 45.
  await minutes.press('ArrowDown');
  await expect(hours).toHaveValue('6');
  await expect(minutes).toHaveValue('45');

  // A value that is not a quarter hour is still typeable, which is why
  // the box steps rather than offering a list.
  await minutes.fill('50');
  await expect(minutes).toHaveValue('50');

  expect(errors).toEqual([]);
});
