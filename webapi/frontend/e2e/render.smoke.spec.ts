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
