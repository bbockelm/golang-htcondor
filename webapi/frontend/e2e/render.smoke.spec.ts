import { expect, test } from '@playwright/test';
import { installApiFixtures } from './fixtures/api';

// Fail-fast suite: does each page render against known-good data?
//
// NOTE for whoever runs this by hand: serve the export with `serve out`,
// NOT `serve -s out`. The -s flag rewrites every path to index.html,
// which a Next.js static export does not want -- it emits a real file
// per route. With -s these tests all load the dashboard and pass while
// testing nothing, which is exactly what happened when they were
// written.
//
// It runs before the full suite so an obviously broken build does not
// pay for a container start and a personal HTCondor. It also asserts no
// uncaught page error, which is the cheapest way to catch the class the
// Web UI had no coverage for at all until now.

test.beforeEach(async ({ page }) => {
  await installApiFixtures(page);
});

// Collect page-level failures so a test can assert none happened. A
// React render error shows up here even when the DOM still has enough
// content for a naive selector to pass.
function watchForErrors(page: import('@playwright/test').Page) {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(String(e)));
  page.on('console', (m) => {
    if (m.type() === 'error') errors.push(m.text());
  });
  return errors;
}

for (const path of ['/', '/jobs', '/submit']) {
  test(`renders ${path} without page errors`, async ({ page }) => {
    const errors = watchForErrors(page);
    const res = await page.goto(path);
    expect(res?.status(), `${path} should not 4xx/5xx`).toBeLessThan(400);
    await expect(page.locator('body')).toBeVisible();
    expect(errors, `${path} raised page errors`).toEqual([]);
  });
}

test('jobs page binds data from the API rather than rendering empty', async ({ page }) => {
  await page.goto('/jobs');
  // The fixture's batch name is distinctive, so this can only pass if
  // the response was fetched, parsed and rendered. A page that loads
  // but never binds shows an empty table and fails here.
  await expect(page.getByText(/smoke-batch/).first()).toBeVisible();
});

// Regression for the /admin/logs column collapse (#224): the message
// span had flex-basis 0 while the trailing fields span kept basis auto,
// so a line carrying a full user_agent squeezed "HTTP request" down to
// one character per line.
//
// Asserting on the rendered geometry rather than the class list: the
// bug was a layout outcome, and a future refactor that changes the
// classes but keeps the layout correct should not fail here.
test('admin log message column is not squeezed to a sliver', async ({ page }) => {
  await page.goto('/admin/logs');

  const message = page.getByText('HTTP request', { exact: true }).first();
  // Attached rather than visible: a span squeezed to zero width reads
  // as not visible, so asserting visibility here would fail with
  // "element not visible" and bury the actual measurement. Waiting for
  // attachment lets the geometry assertions below report the width.
  await expect(message).toBeAttached();

  const box = await message.boundingBox();
  expect(box, 'message span rendered with no box at all (fully collapsed)').not.toBeNull();

  // "HTTP request" at any sane font size needs well over 40px. The
  // broken layout rendered it around one character wide.
  expect(
    box!.width,
    `message column collapsed to ${box!.width}px (the #224 failure mode)`,
  ).toBeGreaterThan(40);

  // And it should not have wrapped into a tall thin ribbon: one or two
  // lines is fine, ten is the bug.
  expect(box!.height, `message wrapped to ${box!.height}px tall`).toBeLessThan(80);
});

// The two components #240 refactored that nothing else reaches.
//
// That PR rewrote effect timing in ChatPanel (a ref assigned during
// render, and a snap-to-full-text effect that was removed entirely) and
// in JupyterDetailClient (status derived during render instead of
// assigned from an effect). Both were verified only by the type checker
// and the compiler; neither is on a page the rest of this suite loads.

test('the chat surface mounts without page errors', async ({ page }) => {
  const errors = watchForErrors(page);
  await page.goto('/jobs');

  // ChatPanel is gated on chat/info reporting enabled AND the queue
  // having at least one job, both of which the fixtures provide. If it
  // renders nothing the gate changed, and this test is no longer
  // covering the component it names.
  await expect(
    page.getByPlaceholder(/ask|message|chat/i).first().or(page.getByRole('button', { name: /ask|chat|assistant/i }).first()),
  ).toBeVisible();

  expect(errors, 'chat surface raised page errors').toEqual([]);
});

// The dashboard's activity panels are fed by a separate half of the
// response from the status tiles, and they render conditionally. A page
// that fetched the response, drew the tiles, and dropped every activity
// list would pass the render check above -- so assert on a string only
// the fixture's activity carries.
test('dashboard binds the activity panels, not just the status tiles', async ({ page }) => {
  await page.goto('/');
  await expect(page.getByText(/smoke-submitted/).first()).toBeVisible();
  // The hold breakdown is the panel most likely to be dropped: it is the
  // only one keyed off a numeric code rather than a list of jobs.
  await expect(page.getByText(/Failed to transfer output/).first()).toBeVisible();
});

// The ticker is the one part of the dashboard fed by an EventSource
// rather than by the query client, so it is the one part the other
// assertions cannot reach. Its component tests render it from props;
// this is what proves the stream is subscribed to, parsed and bound.
test('dashboard live ticker renders events from the stream', async ({ page }) => {
  await page.goto('/');
  await expect(page.getByText(/smoke-live-host/).first()).toBeVisible();
});

test('dashboard goodput panel binds the history summary', async ({ page }) => {
  await page.goto('/');
  // The wall-clock share is computed in the component rather than sent,
  // so this covers the arithmetic as well as the binding: 90000 good of
  // 120000 total.
  await expect(page.getByText(/75% of/)).toBeVisible();
  await expect(page.getByText('exit 127')).toBeVisible();
});

// The tiles and the panels are two requests now, and the point of the
// split is that the first does not wait for the second. Delaying the
// activity response proves the tiles are not behind it: before the
// split this page rendered nothing until every query had finished.
test('status tiles render before the activity panels arrive', async ({ page }) => {
  await page.route('**/api/v1/dashboard/activity*', async (route) => {
    await new Promise((r) => setTimeout(r, 3000));
    await route.fallback();
  });
  await page.goto('/');

  // Visible well inside the 3s the panels are held back for.
  await expect(page.getByText('Total')).toBeVisible({ timeout: 1500 });
  await expect(page.getByText(/Why jobs are held now/)).toBeHidden();

  // And they do arrive.
  await expect(page.getByText(/Why jobs are held now/)).toBeVisible({ timeout: 10000 });
});

// The hold breakdown covers a window and the HELD tile does not, so the
// two are meant to disagree. Saying which span is the difference between
// a reader trusting the panel and filing a bug about it.
test('hold breakdown states the window it covers', async ({ page }) => {
  await page.goto('/');
  await expect(page.getByText(/still held, entered in the last/)).toBeVisible();
});

// Clicking a hold reason has to land on a jobs page that is actually
// narrowed to those jobs, and that says so. A drill-down that silently
// shows everything is worse than no drill-down.
test('a hold reason drills into the jobs behind it', async ({ page }) => {
  await page.goto('/');
  await page.getByRole('link', { name: 'Failed to transfer output' }).click();

  await expect(page).toHaveURL(/\/jobs\?constraint=/);
  await expect(page.getByText(/Showing jobs held: Failed to transfer output/)).toBeVisible();
  // And a way back out: a narrowed list with no exit reads as a broken
  // jobs page.
  await expect(page.getByRole('link', { name: 'show all jobs' })).toBeVisible();
});
