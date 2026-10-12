import { expect, test, type Page, type TestInfo } from '@playwright/test';

import { adminPassword, loginAsAdmin } from './fixtures/login';
import { serverLog } from './fixtures/serverlog';

// /batches/<id> against a real access point: a three-job cluster and a
// two-node DAG, each submitted through the REST API, then read on their
// batch pages while they run and after they finish.

const log = serverLog();
const password = adminPassword(log);

const RUN_TIMEOUT_MS = 150_000;

// Where the access point's condor_dagman is. The CI image is a package
// install; a local release build passes its own.
const DAGMAN = process.env.E2E_DAGMAN ?? '/usr/bin/condor_dagman';
// And its configuration: a scheduler-universe job has only the
// environment its ad carries, and the demo pool's configuration is in
// the directory the server logs, not in the default place.
const CONDOR_CONFIG =
  process.env.E2E_CONDOR_CONFIG ?? log.match(/(\/\S*\/htcondor-demo-\d+)/)?.[1]?.concat('/condor_config');

async function submit(page: Page, lines: string[]): Promise<number> {
  const res = await page.request.post('/api/v1/jobs', { data: { submit_file: lines.join('\n') } });
  expect(res.status(), `submit failed: ${await res.text()}`).toBeLessThan(400);
  const created = await res.json();
  const cluster = Number(created.cluster_id ?? created.ClusterId ?? created.cluster);
  expect(cluster).toBeGreaterThan(0);
  return cluster;
}

// attachDagmanDiagnostics puts what DAGMan said into the report of a
// failed DAG test: the manager job's ad (from the queue, else the
// archive) and its log and stderr from the spool. Best effort -- a
// diagnostic that fails must not hide the failure it is explaining.
async function attachDagmanDiagnostics(page: Page, testInfo: TestInfo, root: number, base: string) {
  const id = `${root}.0`;
  const fetchText = async (url: string): Promise<string> => {
    try {
      const res = await page.request.get(url, { timeout: 20_000 });
      return `HTTP ${res.status()}\n${await res.text()}`;
    } catch (e) {
      return `request failed: ${String(e)}`;
    }
  };
  const parts: [string, string][] = [
    ['dagman-job-ad.txt', await fetchText(`/api/v1/jobs/${id}`)],
    [
      'dagman-job-archive.txt',
      await fetchText(`/api/v1/jobs/archive?owned_by_me=false&constraint=${encodeURIComponent(`ClusterId == ${root}`)}`),
    ],
    [`${base}.dagman.out`, await fetchText(`/api/v1/jobs/${id}/files/${base}.dagman.out`)],
    [`${base}.lib.err`, await fetchText(`/api/v1/jobs/${id}/files/${base}.lib.err`)],
    [
      'batch-jobs.json',
      await fetchText(`/api/v1/jobs?owned_by_me=false&limit=*&constraint=${encodeURIComponent(`JobBatchName == "${base}.dag+${root}"`)}`),
    ],
  ];
  for (const [name, body] of parts) {
    await testInfo.attach(name, { body, contentType: 'text/plain' });
  }
}

// archived counts a batch's finished jobs in the archive, by JobStatus.
async function archived(page: Page, constraint: string): Promise<Record<string, unknown>[]> {
  const res = await page.request.get(
    `/api/v1/jobs/archive?owned_by_me=false&constraint=${encodeURIComponent(constraint)}`,
  );
  if (res.status() !== 200) return [];
  return (await res.json()).ads ?? [];
}

test('a multi-job cluster: its page shows progress and every job, live and finished', async ({ page }) => {
  test.setTimeout(RUN_TIMEOUT_MS + 60_000);
  await loginAsAdmin(page, password);

  const name = `batchpage-e2e-${Date.now().toString(36)}`;
  const cluster = await submit(page, [
    'executable = /bin/sleep',
    'arguments = 5',
    'transfer_executable = false',
    `batch_name = ${name}`,
    'leave_in_queue = false',
    'request_memory = 64 MB',
    'queue 3',
  ]);

  // While it is in the queue.
  await page.goto(`/batches/${cluster}`);
  await expect(page.getByRole('heading', { level: 1, name })).toBeVisible();
  await expect(page.getByTestId('batch-progress')).toContainText(/of 3 jobs done/);
  const jobs = page.getByTestId('batch-jobs');
  await expect(jobs.getByTestId('batch-job-row')).toHaveCount(3);
  for (let p = 0; p < 3; p++) {
    await expect(jobs.getByRole('link', { name: `${cluster}.${p}`, exact: true })).toHaveAttribute(
      'href',
      `/jobs/${cluster}.${p}`,
    );
  }

  // Finished: all three in the archive, then on the page.
  const deadline = Date.now() + RUN_TIMEOUT_MS;
  let done = 0;
  while (Date.now() < deadline && done < 3) {
    done = (await archived(page, `ClusterId == ${cluster}`)).filter((a) => Number(a.JobStatus) === 4).length;
    if (done < 3) await page.waitForTimeout(3000);
  }
  expect(done, 'the three jobs did not all finish').toBe(3);

  await expect(async () => {
    await page.reload();
    await expect(page.getByTestId('batch-progress')).toContainText('3 of 3 jobs done', { timeout: 5000 });
    await expect(page.getByTestId('batch-outcomes')).toContainText('3 succeeded', { timeout: 5000 });
  }).toPass({ timeout: 60_000 });
  await expect(page.getByTestId('batch-actions')).toHaveCount(0);
  await jobs.getByRole('button', { name: /^Finished/ }).click();
  await expect(jobs.getByTestId('batch-job-row')).toHaveCount(3);
  await expect(jobs.getByTestId('batch-job-row').first()).toContainText('Completed');
  await expect(jobs.getByTestId('batch-job-row').first()).toContainText('exit 0');
  // Every job here was held while its input spooled; that is not a hold
  // worth listing.
  await expect(page.getByTestId('batch-holds')).toHaveCount(0);
});

test('a DAG: its page shows node progress, its jobs and its graph', async ({ page }, testInfo) => {
  test.setTimeout(420_000);
  await loginAsAdmin(page, password);

  const tag = Date.now().toString(36);
  const dagName = `bp${tag}.dag`;
  const node = ['executable = /bin/sleep', 'arguments = 90', 'transfer_executable = false', 'request_memory = 64 MB', 'queue'].join('\n');
  // DOT and NODE_STATUS_FILE are what the graph is drawn from; the
  // server adds them to DAGs it submits itself, and this one is
  // submitted by hand.
  const dag = [
    'JOB A node.sub',
    'JOB B node.sub',
    'PARENT A CHILD B',
    `DOT bp${tag}.dot`,
    `NODE_STATUS_FILE bp${tag}.status 5`,
  ].join('\n');
  const base = dagName.replace(/\.dag$/, '');

  // The manager job condor_submit_dag would write, spooled.
  const root = await submit(page, [
    'universe = scheduler',
    `executable = ${DAGMAN}`,
    'transfer_executable = false',
    `output = ${base}.lib.out`,
    `error = ${base}.lib.err`,
    `log = ${base}.dagman.log`,
    'remove_kill_sig = SIGUSR1',
    'My.OtherJobRemoveRequirements = "DAGManJobId =?= $(Cluster)"',
    `My.JobBatchName = "${dagName}+$(Cluster)"`,
    'on_exit_remove = (ExitSignal =?= 11 || (ExitCode =!= UNDEFINED && ExitCode >= 0 && ExitCode <= 2))',
    `arguments = "-p 0 -f -l . -Lockfile ${base}.dag.lock -Dag ${dagName}"`,
    // DAGMAN_AVOID_SLASH_TMP=False: the demo pool's spool is under the
    // system temp directory -- /tmp on Linux -- and DAGMan otherwise
    // refuses to keep its node log there and exits before reading the
    // DAG. A real access point's spool is not under /tmp.
    `environment = "_CONDOR_DAGMAN_LOG=${base}.dagman.out _CONDOR_MAX_DAGMAN_LOG=0 _CONDOR_DAGMAN_AVOID_SLASH_TMP=False PATH=${DAGMAN.replace(/\/[^/]+$/, '')}:/usr/bin:/bin${
      CONDOR_CONFIG ? ` CONDOR_CONFIG=${CONDOR_CONFIG}` : ''
    }"`,
    'should_transfer_files = YES',
    'when_to_transfer_output = ON_EXIT',
    `transfer_input_files = ${dagName},node.sub`,
    'queue',
  ]);
  const upload = await page.request.post(`/api/v1/jobs/${root}.0/input/multipart`, {
    multipart: {
      dag: { name: dagName, mimeType: 'text/plain', buffer: Buffer.from(dag + '\n') },
      sub: { name: 'node.sub', mimeType: 'text/plain', buffer: Buffer.from(node + '\n') },
    },
  });
  expect(upload.status(), `upload failed: ${await upload.text()}`).toBeLessThan(400);

  try {

    // Once DAGMan has submitted node A, the page has a workflow to show.
    await page.goto(`/batches/${root}`);
    await expect(page.getByRole('heading', { level: 1, name: dagName })).toBeVisible();
    await expect(page.getByText('DAG', { exact: true })).toBeVisible();

    // Its jobs: the DAGMan job first.
    const jobs = page.getByTestId('batch-jobs');
    const nodeRow = (n: string) =>
      jobs.getByTestId('batch-job-row').filter({ has: page.getByRole('cell', { name: n, exact: true }) });
    await expect(async () => {
      await page.reload();
      await expect(nodeRow('DAGMan')).toHaveCount(1, { timeout: 5000 });
    }).toPass({ timeout: 30_000 });
    await expect(jobs.getByRole('link', { name: `${root}.0`, exact: true })).toHaveAttribute('href', `/jobs/${root}.0`);

    // Node A, once DAGMan has submitted it -- on the DAG's page whichever
    // user it runs as (a schedd that is not root, like the demo's, runs
    // DAGMan's nodes as its own user).
    await expect(async () => {
      await page.reload();
      await expect(nodeRow('A')).toHaveCount(1, { timeout: 5000 });
    }).toPass({ timeout: 60_000 });
    const nodeCluster = Number((await nodeRow('A').getByRole('link').first().textContent())?.split('.')[0]);
    expect(nodeCluster).toBeGreaterThan(root);

    // And a node's cluster leads to the DAG's page.
    await page.goto(`/batches/${nodeCluster}`);
    await expect(page).toHaveURL(new RegExp(`/batches/${root}$`));
    await expect(page.getByRole('heading', { level: 1, name: dagName })).toBeVisible();

    // The graph: both nodes, once DAGMan has written its files.
    const panel = page.getByTestId('workflow-graph-panel');
    await expect(async () => {
      await panel.getByRole('button', { name: /Load graph|Refresh/ }).click();
      // A and B, one above the other.
      await expect(panel.getByRole('img', { name: 'Workflow graph: 2 groups in 2 layers' })).toBeVisible({
        timeout: 10_000,
      });
    }).toPass({ timeout: 90_000 });

    // Node progress, once DAGMan has first reported it (it does so every
    // two minutes).
    await expect(async () => {
      await page.reload();
      await expect(page.getByTestId('batch-progress')).toContainText(/of 2 nodes done/, { timeout: 5000 });
    }).toPass({ timeout: 180_000 });
    await expect(page.getByTestId('dag-nodes')).toBeVisible();

    // Clean up: removing the batch removes DAGMan and its nodes.
    await page.getByRole('button', { name: 'Remove batch' }).click();
    await page.getByRole('button', { name: /^Remove \d+ jobs?$/ }).click();
    await expect(page.getByTestId('batch-actions')).toHaveCount(0, { timeout: 60_000 });
  } catch (e) {
    await attachDagmanDiagnostics(page, testInfo, root, base);
    throw e;
  }
});
