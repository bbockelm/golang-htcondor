import { expect, test } from '@playwright/test';
import path from 'node:path';

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

for (const path of ['/', '/jobs', '/issues', '/submit']) {
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

// The issues page's whole job is to rank problems, so binding one row is
// what proves it works: a page that fetched, parsed and rendered nothing
// would still pass the render check above.
test('issues page ranks the problems it was given', async ({ page }) => {
  await page.goto('/issues');
  // The representative message, not the masked template: a row that led
  // with "<slot>" where the hostname belongs would be useless.
  await expect(page.getByText(/smoke-host\.example\.edu/)).toBeVisible();
  // The users count beside the problem is the number the page exists to
  // put there.
  // Exact, because the section header also says "2 users": the badge on
  // the row is the one being asserted.
  await expect(page.getByText('2 users', { exact: true })).toBeVisible();
  // Where it happened, which is the other half of the ranking: a
  // problem at one resource is that resource's problem.
  await expect(page.getByText('SMOKE-CE1')).toBeVisible();
  // Both sections bind, not just the first.
  await expect(page.getByText(/could not keep running/i)).toBeVisible();
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

// Every figure on the dashboard should answer "which ones". These check
// the two destinations exist and arrive narrowed -- a drill-down that
// silently shows everything is worse than none.
test('a status tile drills into the jobs in that state', async ({ page }) => {
  await page.goto('/');
  await page.getByRole('link', { name: /Held/ }).first().click();

  await expect(page).toHaveURL(/\/jobs\?constraint=/);
  await expect(page.getByText(/Showing held jobs/)).toBeVisible();
});

test('a goodput failure drills into the archive, not the queue', async ({ page }) => {
  await page.goto('/');
  await page.getByRole('link', { name: 'exit 127' }).click();

  // The archive: these jobs ran to completion and the queue destroyed
  // them seconds later.
  await expect(page).toHaveURL(/\/archive\?constraint=/);
  await expect(page.getByText(/Showing jobs that exited 127/)).toBeVisible();
  await expect(page.getByRole('link', { name: 'show all history' })).toBeVisible();
});

// --- Job detail: the panels that depend on the job's universe -------
//
// The static export has one page per route, so /jobs/12.0 is not a file
// on disk -- the placeholder /jobs/_ is, and in production the Go SPA
// handler answers every /jobs/<id> with it (webui/handler.go,
// resolveDynamicRoute). `serve out` does not, so these tests do the
// same substitution at the network layer. The page reads the real id
// off the URL (useResolvedParams), which is exactly what is being
// relied on here.
async function openJobPage(
  page: import('@playwright/test').Page,
  id: string,
  ad: Record<string, unknown>,
) {
  const placeholder = path.join(__dirname, '..', 'out', 'jobs', '_.html');
  await page.route(`**/jobs/${id}`, async (route) => {
    if (route.request().resourceType() !== 'document') {
      await route.fallback();
      return;
    }
    await route.fulfill({ path: placeholder, contentType: 'text/html; charset=utf-8' });
  });
  await page.route(`**/api/v1/jobs/${id}`, (route) => route.fulfill({ json: ad }));
  await page.goto(`/jobs/${id}`);
}

const startedRecently = Math.floor(Date.now() / 1000) - 300;

// A running DAGMan manager: scheduler universe, so the schedd refuses
// GET_JOB_CONNECT_INFO for it (schedd.cpp:18673) and neither tail nor
// ssh can ever work. Its output is not lost -- it is written in place
// in the spool as it runs, which is what makes the download meaningful
// while the job is still going.
const dagmanManagerAd = {
  ClusterId: 77,
  ProcId: 0,
  JobStatus: 2,
  JobUniverse: 7,
  Owner: 'e2e',
  Cmd: '/usr/bin/condor_dagman',
  Arguments: '-p 0 -f -l . -Lockfile diamond.dag.lock -Dag diamond.dag',
  Environment: '_CONDOR_DAGMAN_LOG=diamond.dagman.out _CONDOR_MAX_DAGMAN_LOG=0',
  // Spooled: the schedd rewrote Iwd to the spool and kept the
  // submit-time one in SUBMIT_Iwd. That is what puts the workflow's
  // files somewhere this server can read them.
  Iwd: '/var/lib/condor/spool/77/0/cluster77.proc0.subproc0',
  SUBMIT_Iwd: '/home/e2e/dags',
  QDate: startedRecently - 60,
  JobStartDate: startedRecently,
};

test('a scheduler-universe job page offers no tail or terminal', async ({ page }) => {
  await openJobPage(page, '77.0', dagmanManagerAd);

  // The job is running, so both panels used to render: Live Tail with
  // its button, Terminal with "Available while the job is running".
  // Both are permanently impossible here.
  await expect(page.getByRole('heading', { name: 'Output Files' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Live Tail' })).toHaveCount(0);
  await expect(page.getByRole('heading', { name: 'Terminal', exact: true })).toHaveCount(0);

  // And the download that replaces them is offered -- as a link, not
  // the disabled button -- and says what it is.
  await expect(page.getByRole('link', { name: 'Download as tar' })).toBeVisible();
  await expect(page.getByText(/live snapshot/i)).toBeVisible();
});

test('a vanilla-universe job keeps the tail and waits for its output', async ({ page }) => {
  await openJobPage(page, '78.0', {
    ...dagmanManagerAd,
    ClusterId: 78,
    JobUniverse: 5,
    Cmd: '/bin/sleep',
    Arguments: '600',
    Environment: '',
  });

  // First run, still going: nothing has transferred back, so the
  // download is the disabled button rather than a link.
  await expect(page.getByRole('link', { name: 'Download as tar' })).toHaveCount(0);
  await expect(page.getByText(/output files appear once it completes/i)).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Live Tail' })).toBeVisible();
});

test('a running DAGMan manager surfaces its workflow log', async ({ page }) => {
  await page.route('**/api/v1/jobs/*/files/diamond.dagman.out', (route) =>
    route.fulfill({
      contentType: 'text/plain',
      body: '09/23/26 12:00:00 Submitting HTCondor Node A job(s)...\n',
    }),
  );
  await openJobPage(page, '77.0', dagmanManagerAd);

  // The name comes from _CONDOR_DAGMAN_LOG in the environment, not
  // from the -Dag argument: the two producers disagree about it, and
  // deriving diamond.dag.dagman.out here would fetch a file that this
  // submitter never wrote.
  await expect(page.getByRole('heading', { name: 'Workflow log' })).toBeVisible();
  const summary = page.getByText('diamond.dagman.out', { exact: false }).first();
  await expect(summary).toBeVisible();

  // Explicit load: nothing is fetched until the user opens it, because
  // every fetch re-transfers the workflow's whole spool.
  await summary.click();
  await expect(page.getByText(/Submitting HTCondor Node A/)).toBeVisible();
  await expect(page.getByText(/re-fetches the workflow's spool/)).toBeVisible();
});

// The same manager submitted the ordinary way: `condor_submit_dag` from
// a shell on the access point, no spooling. Iwd is the user's own
// directory, the schedd's spool for the job is empty, and every fetch
// through this server 404s -- so the panel has to say where the log is
// instead of offering to load it.
test('a shell-submitted workflow says where its log is', async ({ page }) => {
  const { SUBMIT_Iwd: _spooled, ...notSpooled } = dagmanManagerAd;
  await openJobPage(page, '79.0', {
    ...notSpooled,
    ClusterId: 79,
    Iwd: '/home/e2e/dags',
  });

  await expect(page.getByRole('heading', { name: 'Workflow log' })).toBeVisible();
  // Scoped to the explanation itself: the Iwd also shows up in the
  // execution table and the raw ClassAd, so a page-wide text match
  // would pass with the sentence missing entirely.
  const explanation = page.getByText(/submitted from a shell on the access point/);
  await expect(explanation).toBeVisible();
  await expect(explanation).toContainText('diamond.dagman.out');
  await expect(explanation).toContainText('/home/e2e/dags');
  await expect(explanation).toContainText('condor_q -better-analyze');
  // No viewer, so no way to ask for a fetch that cannot work.
  await expect(page.getByRole('button', { name: 'Refresh' })).toHaveCount(0);
  await expect(page.getByText(/re-fetches the workflow's spool/)).toHaveCount(0);

  // And the download the scheduler-universe branch offers is gone too:
  // there is nothing in the spool to download.
  await expect(page.getByRole('link', { name: 'Download as tar' })).toHaveCount(0);
});
