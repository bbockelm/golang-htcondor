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
  const explanation = page.getByText(/This workflow was submitted from a shell/);
  await expect(explanation).toBeVisible();
  await expect(explanation).toContainText('diamond.dagman.out');
  await expect(explanation).toContainText('/home/e2e/dags');
  // Where the log is, and nothing else: the sentence used to end with
  // advice to run condor_q, which answers a different question and was
  // aimed at somebody who has just been handed the path to the file.
  await expect(explanation).not.toContainText('condor_q');
  // No viewer, so no way to ask for a fetch that cannot work.
  await expect(page.getByRole('button', { name: 'Refresh' })).toHaveCount(0);
  await expect(page.getByText(/re-fetches the workflow's spool/)).toHaveCount(0);

  // And the download the scheduler-universe branch offers is gone too:
  // there is nothing in the spool to download.
  await expect(page.getByRole('link', { name: 'Download as tar' })).toHaveCount(0);
});

// --- Workflow graph -------------------------------------------------
//
// A fan-out / gather workflow, which is the shape the collapse exists
// for: ten independent work nodes become one box, and the two lines
// around it are the some-to-some link the panel has to warn about.
const fanoutManagerAd = {
  ClusterId: 90,
  ProcId: 0,
  JobStatus: 2,
  JobUniverse: 7,
  Owner: 'e2e',
  Cmd: '/usr/bin/condor_dagman',
  Arguments: '-p 0 -f -l . -Lockfile fanout.dag.lock -Dag fanout.dag',
  Environment: '_CONDOR_DAGMAN_LOG=fanout.dagman.out _CONDOR_MAX_DAGMAN_LOG=0',
  Iwd: '/var/lib/condor/spool/90/0/cluster90.proc0.subproc0',
  SUBMIT_Iwd: '/home/e2e/dags',
  QDate: startedRecently - 60,
  JobStartDate: startedRecently,
};

// Ten work nodes: eight done, one running, one failed. The failed one
// is the reason anyone opens this panel, so it carries the exit code,
// the job id and DAGMan's own note.
const workNodes = [
  ...Array.from({ length: 8 }, (_, i) => ({
    name: `work_${i}`,
    group_id: 'work',
    state: 'done',
    source: 'status-file',
  })),
  {
    name: 'work_8',
    group_id: 'work',
    state: 'running',
    job_id: '91.8',
    source: 'queue',
  },
  {
    name: 'work_9',
    group_id: 'work',
    state: 'failed',
    job_id: '91.9',
    exit_code: 1,
    detail: 'Job exited with status 1',
    source: 'archive',
  },
];

const fanoutDagGraph = {
  cluster: 90,
  dag_file: 'fanout.dag',
  dot_file: 'fanout.dag.dot',
  status_file: 'fanout.dag.status',
  node_count: 12,
  edge_count: 20,
  group_count: 3,
  groups: [
    {
      id: 'setup',
      label: 'setup',
      description: '/bin/prepare',
      count: 1,
      parent_ids: [],
      status: { done: 1 },
    },
    {
      id: 'work',
      label: 'work',
      description: '/bin/crunch',
      count: 10,
      parent_ids: ['setup'],
      status: { done: 8, running: 1, failed: 1 },
    },
    {
      id: 'gather',
      label: 'gather',
      description: '/bin/collect',
      count: 1,
      parent_ids: ['work'],
      status: { unready: 1 },
    },
  ],
  nodes: [
    { name: 'setup', group_id: 'setup', state: 'done', source: 'status-file' },
    ...workNodes,
    { name: 'gather', group_id: 'gather', state: 'unready', source: 'status-file' },
  ],
  state_sources: ['status-file', 'queue'],
  status_file_time: Math.floor(Date.now() / 1000) - 120,
  fetched_at: new Date(Date.now() - 120_000).toISOString(),
  took_ms: 1240,
};

// Route the dag endpoint with a RegExp rather than a glob: the refresh
// button appends ?refresh=1, and the query string has to match too.
async function routeDagGraph(
  page: import('@playwright/test').Page,
  body: unknown,
  status = 200,
) {
  await page.route(/\/api\/v1\/jobs\/[^/]+\/dag(\?.*)?$/, (route) =>
    route.fulfill({ status, json: body as object }),
  );
}

test('a DAGMan manager draws its collapsed workflow on request', async ({ page }) => {
  await routeDagGraph(page, fanoutDagGraph);
  await openJobPage(page, '90.0', fanoutManagerAd);

  await expect(page.getByRole('heading', { name: 'Workflow graph' })).toBeVisible();

  // Explicit load: nothing is drawn until the user asks.
  const svg = page.locator('svg[role="img"]');
  await expect(svg).toHaveCount(0);
  await page.getByRole('button', { name: 'Load graph' }).click();

  await expect(svg).toBeVisible();
  // The three groups, with the collapse made visible: ten work nodes
  // are one box that says so.
  await expect(svg).toContainText('setup');
  await expect(svg).toContainText('work');
  await expect(svg).toContainText('gather');
  await expect(svg).toContainText('×10');
  // Coloured by the most urgent state present, not the most numerous:
  // one failed among ten is what the box has to carry.
  await expect(svg.locator('[data-group-id="work"] rect').first()).toHaveClass(
    /fill-red/,
  );

  // The one caveat that earns its place has to be on the page, not in a
  // comment: a reader who takes the single line for "every work node
  // feeds gather" has misread a fan-in as a barrier. One sentence.
  await expect(
    page.getByText(/some.*node in the first is a parent of.*some.*node in the second/i),
  ).toBeVisible();

  // How old the state is and how long the load took -- the whole of what
  // the panel now says about itself.
  await expect(page.getByText(/State as of .*ago.*loaded in 1\.2s/)).toBeVisible();
});

// The project owner's rule: the panel says what is true of the WORKFLOW,
// never how this server produced it. These four sentences were the worst
// offenders and are gone; the rest of the rule is enforced by the
// assertions above being short.
test('the graph panel does not explain the server', async ({ page }) => {
  await routeDagGraph(page, {
    ...fanoutDagGraph,
    truncated: true,
    incomplete: true,
    dangling_edges: 3,
    approximate_layering: true,
    approximate_reason: 'refinement-bound',
    warnings: ['The job queue could not be consulted, so some nodes may read as unready.'],
  });
  await openJobPage(page, '90.0', fanoutManagerAd);
  await page.getByRole('button', { name: 'Load graph' }).click();
  await expect(page.locator('svg[role="img"]')).toBeVisible();
  await page.locator('[data-group-id="work"]').click();

  // By test id, not by "the div holding the heading": EVERY ancestor div
  // holds the heading, so .first() is the whole page (which legitimately
  // says "spool" in the workflow log panel and the raw ClassAd) and
  // .last() is the button row (which says nothing at all). Both pass
  // whatever the panel's prose says, which is the one thing this test
  // must not do.
  const panel = page.getByTestId('workflow-graph-panel');
  await expect(panel).toBeVisible();
  for (const implementation of [
    /server-side cache/i,
    /re-fetches the workflow/i,
    /Nothing here polls/i,
    /however live the queue half/i,
    /\.dot\b/,
    /node status file/i,
    /spool/i,
    /status file did not contribute/i,
    /Node state came from/i,
    /Structure read from/i,
    /structure file/i,
    /SPLICE or INCLUDE/i,
    /perfect matching/i,
  ]) {
    await expect(panel.getByText(implementation)).toHaveCount(0);
  }
});

test('clicking a group opens the members the collapse hid', async ({ page }) => {
  await routeDagGraph(page, fanoutDagGraph);
  await openJobPage(page, '90.0', fanoutManagerAd);
  await page.getByRole('button', { name: 'Load graph' }).click();

  // Nothing per-node until asked: the box says "1 failed", and "which
  // one" is a click away.
  await expect(page.getByText('work_9')).toHaveCount(0);
  await page.locator('[data-group-id="work"]').click();

  await expect(page.getByText('work_9')).toBeVisible();
  await expect(page.getByText('work_0')).toBeVisible();
  // The three facts behind a failed node.
  await expect(page.getByText('Job exited with status 1')).toBeVisible();
  await expect(page.getByText('exit 1', { exact: true })).toBeVisible();
  await expect(page.getByRole('link', { name: 'job 91.9' })).toHaveAttribute(
    'href',
    '/jobs/91.9',
  );

  // And the constraint that finds these in the jobs list -- not
  // guessable, and nothing else on the page spells DAGManJobId out.
  await expect(page.getByText('DAGManJobId == 90')).toBeVisible();
});

test('the graph says how the picture may be wrong', async ({ page }) => {
  await routeDagGraph(page, {
    ...fanoutDagGraph,
    approximate_layering: true,
    dangling_edges: 3,
  });
  await openJobPage(page, '90.0', fanoutManagerAd);
  await page.getByRole('button', { name: 'Load graph' }).click();

  await expect(
    page.getByText(/grouping is coarser than the workflow's real structure/),
  ).toBeVisible();
  await expect(
    page.getByText(/3\s+dependencies are missing from this drawing/),
  ).toBeVisible();
});

// Fields the HTTP layer does not copy out of dagman.Grouping yet are
// absent from a live response, and absent means "this server does not
// say" -- not "no". A reassuring banner either way would be a claim the
// response never made.
test('the graph claims nothing the response did not say', async ({ page }) => {
  await routeDagGraph(page, fanoutDagGraph);
  await openJobPage(page, '90.0', fanoutManagerAd);
  await page.getByRole('button', { name: 'Load graph' }).click();

  await expect(page.locator('svg[role="img"]')).toBeVisible();
  await expect(page.getByText(/may be missing dependencies/)).toHaveCount(0);
  await expect(page.getByText(/Part of this workflow is missing/)).toHaveCount(0);
  await expect(page.getByText(/dependencies are missing from this drawing/)).toHaveCount(0);
  await expect(page.getByText(/grouping is coarser/)).toHaveCount(0);
});

// 409 is the server saying "this workflow has no structure to show",
// with a sentence that already explains which of the three reasons
// applies. Rendering it as an error would contradict it.
test('a workflow with no structure is explained, not error-boxed', async ({ page }) => {
  await routeDagGraph(
    page,
    {
      error: 'Conflict',
      code: 409,
      message:
        'This workflow does not publish its structure: its DAG declares no DOT command, so ' +
        'DAGMan wrote no fanout.dag.dot into the spool and there is nothing to read the graph from.',
    },
    409,
  );
  await openJobPage(page, '90.0', fanoutManagerAd);
  await page.getByRole('button', { name: 'Load graph' }).click();

  await expect(
    page.getByText(/does not publish its structure: its DAG declares no DOT command/),
  ).toBeVisible();
  await expect(page.getByText(/Could not load the workflow graph/)).toHaveCount(0);
  // The red error box this page uses everywhere else.
  await expect(page.locator('.border-red-200.bg-red-50')).toHaveCount(0);
});

// Same gate as the workflow log, same reason: the .dot and node-status
// files are read out of the spool, and a shell-submitted manager's
// spool is empty.
//
// No panel at all, where there used to be one carrying a sentence. The
// Workflow log panel is on this same page for this same job and already
// says the workflow was submitted from a shell and where its files are;
// an empty box underneath repeating that is one point made twice.
test('a shell-submitted workflow has no workflow graph box', async ({ page }) => {
  const { SUBMIT_Iwd: _spooled, ...notSpooled } = fanoutManagerAd;
  await openJobPage(page, '92.0', {
    ...notSpooled,
    ClusterId: 92,
    Iwd: '/home/e2e/dags',
  });

  // The page rendered -- so the absence below is the panel being gone,
  // not the page failing to load.
  await expect(page.getByRole('heading', { name: 'Workflow log' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Workflow graph' })).toHaveCount(0);
  await expect(page.getByText(/This workflow has no graph here/)).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Load graph' })).toHaveCount(0);
});

// A job that is not a DAGMan manager gets no panel at all.
test('a vanilla job has no workflow graph panel', async ({ page }) => {
  await openJobPage(page, '93.0', {
    ...fanoutManagerAd,
    ClusterId: 93,
    JobUniverse: 5,
    Cmd: '/bin/sleep',
    Arguments: '600',
    Environment: '',
  });

  await expect(page.getByRole('heading', { name: 'Output Files' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Workflow graph' })).toHaveCount(0);
});

// A job that finished between a page being drawn and one of its links
// being clicked is gone from the queue -- the schedd destroys a
// completed job within seconds -- and sitting in the archive under the
// same id. Following a link from /issues or a stale tab should land on
// the record, not on an error.
test('a job that has left the queue opens its archived record', async ({ page }) => {
  const placeholder = path.join(__dirname, '..', 'out', 'jobs', '_.html');
  const archivePlaceholder = path.join(__dirname, '..', 'out', 'archive', '_.html');
  await page.route('**/jobs/8801.0', async (route) => {
    if (route.request().resourceType() !== 'document') {
      await route.fallback();
      return;
    }
    await route.fulfill({ path: placeholder, contentType: 'text/html; charset=utf-8' });
  });
  await page.route('**/archive/8801.0', async (route) => {
    if (route.request().resourceType() !== 'document') {
      await route.fallback();
      return;
    }
    await route.fulfill({ path: archivePlaceholder, contentType: 'text/html; charset=utf-8' });
  });
  await page.route('**/api/v1/jobs/8801.0', (route) =>
    route.fulfill({ status: 404, json: { error: 'Not Found', message: 'Job not found' } }),
  );
  await page.route('**/api/v1/jobs/archive**', (route) =>
    route.fulfill({
      json: {
        ads: [
          {
            ClusterId: 8801,
            ProcId: 0,
            Owner: 'e2e',
            JobStatus: 4,
            ExitCode: 0,
            CompletionDate: Math.floor(Date.now() / 1000) - 120,
            Cmd: '/bin/smoke-finished',
          },
        ],
      },
    }),
  );

  await page.goto('/jobs/8801.0');

  // The URL is the assertion: the reader asked for a queue page and
  // ends up on the archived record rather than at an error.
  await expect(page).toHaveURL(/\/archive\/8801\.0$/);
  await expect(page.getByText('archived')).toBeVisible();
});
