import type { Page } from '@playwright/test';

// The instant the smoke suite lives at, and where.
//
// Pages print clock times relative to now -- "started 9:45 AM", "done
// by ~12:30 PM" -- and name the day when a time is not today ("started
// Sun 10:14 PM"). Fixtures built from the real clock therefore rendered
// differently depending on when CI ran: a job that started 2h15m ago
// started yesterday for the first 2h15m after midnight, and the
// assertions on its start time failed every night.
//
// So the fixtures, the browser's clock and the browser's timezone are
// all fixed: midday on a weekday, far enough from midnight that any
// fixture a few hours either side of now is still today. The smoke
// project sets the timezone and locale (playwright.config.ts);
// installApiFixtures pins the clock.
export const SMOKE_TIMEZONE = 'America/Chicago';
export const SMOKE_LOCALE = 'en-US';
// Wed Oct 14 2026, 12:00 PM in SMOKE_TIMEZONE, in unix seconds.
export const SMOKE_NOW = Date.parse('2026-10-14T12:00:00-05:00') / 1000;

// pinClock fixes the page's Date at SMOKE_NOW. Timers keep running, so
// polling and debouncing behave as they do for real; only the wall
// clock stands still. Call it before the first navigation. A test that
// needs a different instant (or timezone) sets its own after
// installApiFixtures -- the later setFixedTime wins -- and builds its
// fixtures from that instant; see the run time card tests in
// jobfollowups.smoke.spec.ts.
export async function pinClock(page: Page) {
  await page.clock.setFixedTime(SMOKE_NOW * 1000);
}
