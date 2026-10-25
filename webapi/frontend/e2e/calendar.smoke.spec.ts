import { expect, test } from '@playwright/test';

import { installApiFixtures } from './fixtures/api';
import { CALENDAR_PAST_DAY, CALENDAR_PAST_DAY_END, CALENDAR_QUIET_DAY } from './fixtures/calendar';

// The dashboard's calendar against a fixed 90-day fixture: that it
// renders, that a quiet day and a busy day do not look alike, that the
// derived queue depth does not present itself as a measurement, and that
// a square leads to the jobs it counted.
//
// Everything here is pinned to the suite's instant and timezone (see
// fixtures/clock.ts). The calendar names weekdays and months, so a
// fixture measured from the real clock would move every square and fail
// this file at midnight UTC on somebody else's pull request.

test.beforeEach(async ({ page }) => {
  await installApiFixtures(page);
});

test('the calendar renders a grid per flow over the window', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(String(e)));
  await page.goto('/');

  const panel = page.locator('section', { has: page.getByText('Daily activity') });
  await expect(panel).toBeVisible();
  await expect(panel.getByText('last 90 days, UTC')).toBeVisible();
  // One titled grid per flow, each with the window's own total beside
  // it, and both ends of the shading named.
  await expect(panel.locator('figcaption', { hasText: '13,491 jobs' })).toBeVisible();
  await expect(panel.getByTestId('calendar-scale')).toContainText('4,120 a day');
  expect(errors).toEqual([]);
});

test('a day with no jobs is a zero, not a hole in the calendar', async ({ page }) => {
  await page.goto('/');
  const panel = page.locator('section', { has: page.getByText('Daily activity') });

  // The quiet day is present in all three grids, drawn as an empty
  // square rather than left out.
  const quiet = panel.locator(`[data-day="${CALENDAR_QUIET_DAY}"]`);
  await expect(quiet).toHaveCount(3);
  for (const state of await quiet.evaluateAll((els) => els.map((e) => e.getAttribute('data-day-state')))) {
    expect(state).toBe('zero');
  }
  // And nothing in this window is a gap, because the server answered for
  // every day of it.
  await expect(panel.locator('[data-day-state="uncounted"]')).toHaveCount(0);
  // A busy day beside it wears a count.
  await expect(
    panel.locator(`[data-day="${CALENDAR_PAST_DAY}"][data-day-state="count"]`).first(),
  ).toBeVisible();
});

test('the derived queue depth says it is an estimate and has nothing to click but today', async ({
  page,
}) => {
  await page.goto('/');
  const depth = page.getByTestId('queue-depth');
  await expect(depth).toHaveAttribute('data-derived', 'true');
  await expect(depth).toContainText('estimated; only the figure for today was counted');
  // The one counted figure is the one link: a past day's depth names no
  // set of jobs to show.
  await expect(depth.getByRole('link')).toHaveCount(1);
  await expect(depth.getByTestId('queue-depth-anchor')).toHaveText('1,240 in the queue now');

  // And the key beside it names the mark that means "not counted".
  await page.getByRole('button', { name: 'How to read' }).first().click();
  await expect(page.getByTestId('range-legend').first()).toContainText('Rough guess');
});

test('a day drills through to the jobs it counted', async ({ page }) => {
  await page.goto('/');
  // Finished work, a month back: the archive is where those jobs are,
  // and the constraint is bounded by the day that was clicked.
  const cell = page.getByRole('link', { name: 'Mon, Sep 14, 2026: 29 jobs finished' });
  await expect(cell).toBeVisible();
  await cell.click();
  await expect(page).toHaveURL(/\/archive\?constraint=/);
  const constraint = new URL(page.url()).searchParams.get('constraint') ?? '';
  // On EnteredHistoryTime: the drill-down has to match on the attribute
  // the server bucketed the day by, or the list that opens disagrees with
  // the figure that was clicked.
  expect(constraint).toBe(
    `JobStatus == 4 && EnteredHistoryTime >= ${CALENDAR_PAST_DAY} && EnteredHistoryTime < ${CALENDAR_PAST_DAY_END}`,
  );
  // The page says what it was asked, rather than leaving an unexplained
  // filter on an archive listing.
  await expect(page.getByText('jobs that finished Mon, Sep 14, 2026')).toBeVisible();
});
