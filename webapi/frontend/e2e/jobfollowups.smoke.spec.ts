import { expect, test, type Page } from '@playwright/test';
import path from 'node:path';

import { installApiFixtures, installJobsProgressFixtures } from './fixtures/api';
import { SMOKE_NOW } from './fixtures/clock';

// The batch actions menu, running and waiting times, the owner link on
// the job page, and the job page's Requirements breakdown, against
// mocked responses. The smoke session is an administrator, so every
// owner is linkable.

const now = SMOKE_NOW;
const twoHours14 = 2 * 3600 + 14 * 60;

// The /jobs/<id> page: /jobs/_ answers every id in production, so do the
// same here (see openJobPage in render.smoke.spec.ts).
async function openJobPage(page: Page, id: string, ad: Record<string, unknown>) {
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

test.beforeEach(async ({ page }) => {
  await installApiFixtures(page);
});

test('a batch opens its resource utilization from its actions menu', async ({ page }) => {
  await installJobsProgressFixtures(page);
  await page.goto('/jobs');
  const menu = page.getByRole('button', { name: 'More actions for batch smoke-sweep' });
  // From the keyboard, the way the menu is meant to work.
  await menu.focus();
  await page.keyboard.press('ArrowDown');
  // The batch's own page leads the menu.
  const open = page.getByRole('menuitem', { name: 'Open batch page' });
  await expect(open).toBeFocused();
  await expect(open).toHaveAttribute('href', /^\/batches\/\d+$/);
  await page.keyboard.press('ArrowDown');
  const item = page.getByRole('menuitem', { name: 'Resource utilization' });
  await expect(item).toBeFocused();
  const href = new URL((await item.getAttribute('href'))!, 'http://x');
  expect(href.pathname).toBe('/utilization');
  expect(href.searchParams.get('days')).toBe('30');
  expect(href.searchParams.get('constraint')).toBe('JobBatchName == "smoke-sweep" && Owner == "e2e"');
  // Remove is still on the row.
  await page.keyboard.press('Escape');
  await expect(page.getByTitle(/Remove batch smoke-sweep/)).toBeVisible();
  // And the page as a whole has a way in.
  await expect(page.getByRole('link', { name: 'Resource utilization' })).toHaveAttribute(
    'href',
    '/utilization?days=30',
  );
});

test('the jobs table says how long jobs have been running and waiting', async ({ page }) => {
  await page.route('**/api/v1/jobs?**', (route) =>
    route.fulfill({
      json: {
        jobs: [
          { ClusterId: 70, ProcId: 0, JobStatus: 2, Owner: 'e2e', JobBatchName: 'smoke-timed', QDate: now - 90000, JobCurrentStartExecutingDate: now - twoHours14 },
          { ClusterId: 70, ProcId: 1, JobStatus: 1, Owner: 'e2e', JobBatchName: 'smoke-timed', QDate: now - 90000, EnteredCurrentStatus: now - (86400 + 3 * 3600) },
        ],
        has_more: false,
      },
    }),
  );
  await page.goto('/jobs');
  const row = page.getByRole('row').filter({ hasText: 'smoke-timed' }).first();
  await expect(row).toContainText('longest running 2h14m');
  await row.click();
  await expect(page.getByTitle('Running for 2h14m', { exact: true })).toBeVisible();
  await expect(page.getByTitle('Waiting for 1d3h', { exact: true })).toBeVisible();
});

test('the jobs table says how long a batch has left', async ({ page }) => {
  await page.route('**/api/v1/jobs?**', (route) =>
    route.fulfill({
      json: {
        jobs: [
          { ClusterId: 72, ProcId: 0, JobStatus: 2, Owner: 'e2e', JobBatchName: 'smoke-left', QDate: now - 9000, JobCurrentStartExecutingDate: now - 600 },
          { ClusterId: 72, ProcId: 1, JobStatus: 1, Owner: 'e2e', JobBatchName: 'smoke-left', QDate: now - 9000, EnteredCurrentStatus: now - 9000 },
        ],
        has_more: false,
      },
    }),
  );
  const asked: string[][] = [];
  await page.route('**/api/v1/jobs/runtime-estimates', (route) => {
    asked.push((route.request().postDataJSON() as { jobs: string[] }).jobs);
    return route.fulfill({
      json: {
        available: true,
        estimates: {
          '72.0': { available: true, estimate_seconds: 2400, p10_seconds: 1800, p90_seconds: 4800, rough: false, exceeded_history: false, elapsed_seconds: 600, remaining_seconds: 1800 },
          '72.1': { available: true, estimate_seconds: 3600, p10_seconds: 2400, p90_seconds: 9000, rough: false, exceeded_history: false },
        },
        model: { jobs_ingested: 100 },
      },
    });
  });
  await page.goto('/jobs');
  await expect(page.getByRole('columnheader', { name: 'Time left' })).toBeVisible();
  const row = page.getByRole('row').filter({ hasText: 'smoke-left' }).first();
  await expect(row).toContainText('1 waiting · each about 1h once started');
  // Started 10m before noon with 30m to go (SMOKE_NOW is 12:00 PM).
  await expect(row).toContainText(/running ones done by ~12:30\sPM/);
  expect(asked[0]).toEqual(['72.0', '72.1']);
});

// Verbatim from a CHTC job page, as the API sends it.
const chtcRequirements =
  '/Expr(((((((((((PoolName == "CHTC") || (substr(Machine, 0, 3) == "gzk")) && ((Machine != "txie-dsigpu4000.chtc.wisc.edu") && (Machine != "gpu4002.chtc.wisc.edu"))) && (Arch == "X86_64")) && HasContainer) && HasDockerURL) && (Memory >= RequestMemory)) && (Cpus >= RequestCpus)) && (countMatches(MY.RequireGPUs, AvailableGPUs) >= RequestGPUs)) && ((FileSystemDomain == MY.FileSystemDomain) || (HasFileTransfer && stringListIMember("osdf", HasFileTransferPluginMethods)))))/';

// A running job's card states clock times, and which day they fall on
// depends on the time zone and on the time of day the test runs. So these
// tests pin both: the browser runs in UTC, en-US, with its clock fixed,
// and each case states exactly what the card says. One case is all on one
// day; the others start before midnight and end after it, from either
// side, which is when a time needs its day said.
const runtimeEstimate = {
  job_id: '71.0',
  available: true,
  estimate_seconds: 3 * 3600,
  p10_seconds: 2.5 * 3600,
  p90_seconds: 5 * 3600,
  basis: { level: 'template', sample_count: 12 },
  elapsed_seconds: twoHours14 + 60,
  remaining_seconds: 3 * 3600 - twoHours14 - 60,
  exceeded_history: false,
  model: { trained_through: '2026-10-10T12:00:00Z', jobs_ingested: 5000 },
};

// openRunningJobAt opens job 71.0 -- running for 2h15m, about 3h in all
// -- with the browser's clock fixed at `at`.
async function openRunningJobAt(page: Page, at: string) {
  const pinned = new Date(at);
  await page.clock.setFixedTime(pinned);
  const t = Math.floor(pinned.getTime() / 1000);
  await page.route('**/api/v1/jobs/71.0/runtime-estimate', (route) => route.fulfill({ json: runtimeEstimate }));
  await openJobPage(page, '71.0', {
    ClusterId: 71,
    ProcId: 0,
    JobStatus: 2,
    JobUniverse: 5,
    Owner: 'alice',
    Cmd: '/home/alice/run.sh',
    QDate: t - 90000,
    JobCurrentStartDate: t - twoHours14 - 60,
    JobCurrentStartExecutingDate: t - twoHours14,
    Requirements: chtcRequirements,
  });
  return page.getByTestId('runtime-estimate');
}

// expectClockTimes checks the card's clock times. A time's space before
// AM/PM is a non-breaking one, which \s matches.
async function expectClockTimes(
  runtime: import('@playwright/test').Locator,
  want: { done: string; started: string; usually: string; end: string },
) {
  const re = (s: string) => new RegExp(`^${s.replace(/ (AM|PM)/g, '\\s$1')}$`);
  await expect(runtime.getByRole('heading', { name: 'Expected run time' })).toBeVisible();
  await expect(runtime.getByText(re(`About 45m left · likely done around ${want.done}`))).toBeVisible();
  await expect(runtime.getByText(re(`started ${want.started}`))).toBeVisible();
  await expect(runtime.getByText(re(`usually done ${want.usually}`))).toBeVisible();
  await expect(runtime.getByText(re(want.end))).toBeVisible();
}

test.describe('the run time card, with the clock pinned', () => {
  test.use({ timezoneId: 'UTC', locale: 'en-US' });

  test('the job page links the owner, times the run, and breaks down its requirements', async ({ page }) => {
    // Monday 3:00 PM: started 12:45 PM, all on one day.
    const runtime = await openRunningJobAt(page, '2026-10-12T15:00:00Z');

    await expect(page.getByRole('link', { name: 'alice' })).toHaveAttribute('href', '/users/alice');
    await expect(page.getByText('running for 2h14m')).toBeVisible();
    await expectClockTimes(runtime, {
      done: '3:45 PM',
      started: '12:45 PM',
      usually: '3:15 to 5:45 PM',
      end: '6:45 PM',
    });
    await expect(
      runtime.getByText(
        'Running 2h15m of about 3h. From 12 of your earlier jobs with the same command and argument pattern.',
      ),
    ).toBeVisible();
    // A job within its usual time has nothing to look into.
    await expect(runtime.getByText('Longer than usual')).toHaveCount(0);

    const reqs = page.locator('div').filter({ has: page.getByRole('heading', { name: 'Requirements' }) }).last();
    for (const clause of [
      '(PoolName == "CHTC") || (substr(Machine, 0, 3) == "gzk")',
      'Machine != "txie-dsigpu4000.chtc.wisc.edu"',
      'Machine != "gpu4002.chtc.wisc.edu"',
      'Arch == "X86_64"',
      'HasContainer',
      'HasDockerURL',
      '(FileSystemDomain == MY.FileSystemDomain) || (HasFileTransfer && stringListIMember("osdf", HasFileTransferPluginMethods))',
    ]) {
      await expect(reqs.locator('li code').filter({ hasText: clause }).first()).toBeVisible();
    }
    await expect(reqs.getByText('Standard resource requirements (CPUs, memory, GPUs)')).toBeVisible();
    // Not one opaque clause holding the whole wrapped expression.
    await expect(reqs.locator('li code').filter({ hasText: '/Expr(' })).toHaveCount(0);
  });

  test('a run that started before midnight says which day it started', async ({ page }) => {
    // Monday 12:35 AM: started Sunday 10:20 PM, done in the small hours.
    const runtime = await openRunningJobAt(page, '2026-10-12T00:35:00Z');
    await expect(page.getByText('running for 2h14m')).toBeVisible();
    await expectClockTimes(runtime, {
      done: '1:20 AM',
      started: 'Sun 10:20 PM',
      usually: '12:50 to 3:20 AM',
      end: '4:20 AM',
    });
  });

  test('a run that ends after midnight says which day it ends', async ({ page }) => {
    // Sunday 11:30 PM: started 9:15 PM, likely done Monday 12:15 AM.
    const runtime = await openRunningJobAt(page, '2026-10-11T23:30:00Z');
    await expectClockTimes(runtime, {
      done: 'Mon 12:15 AM',
      started: '9:15 PM',
      usually: '11:45 PM to Mon 2:15 AM',
      end: 'Mon 3:15 AM',
    });
  });
});

test('a job running longer than usual says so and opens its live output and shell', async ({ page }) => {
  await page.route('**/api/v1/jobs/73.0/runtime-estimate', (route) =>
    route.fulfill({
      json: {
        job_id: '73.0',
        available: true,
        estimate_seconds: 3600,
        p10_seconds: 1200,
        p90_seconds: 9000,
        basis: { level: 'cluster', sample_count: 64 },
        elapsed_seconds: 3 * 3600 + 12 * 60,
        exceeded_history: true,
        model: { trained_through: '2026-10-10T12:00:00Z', jobs_ingested: 5000 },
      },
    }),
  );
  await page.route('**/api/v1/jobs/73.0/peek**', (route) =>
    route.fulfill({ json: { stdout: { text: 'smoke-peek-line\n', offset: 16 } } }),
  );
  await openJobPage(page, '73.0', {
    ClusterId: 73,
    ProcId: 0,
    JobStatus: 2,
    JobUniverse: 5,
    Owner: 'e2e',
    Cmd: '/home/e2e/run.sh',
    QDate: now - 90000,
    JobCurrentStartDate: now - 3 * 3600 - 12 * 60,
  });

  const runtime = page.getByTestId('runtime-estimate');
  await expect(runtime.getByText('Longer than usual')).toBeVisible();
  await expect(runtime.getByText('Similar jobs took about 1h, nearly all under 2h30m')).toBeVisible();
  await expect(runtime.getByText('now: 3h12m')).toBeVisible();
  await expect(runtime.getByText('It may be stuck, or this input may need more work than usual.')).toBeVisible();

  await runtime.getByRole('button', { name: 'View live output' }).click();
  await expect(page.getByText('smoke-peek-line')).toBeVisible();

  await expect(page.getByRole('button', { name: 'Open shell' })).toBeVisible();
  await runtime.getByRole('button', { name: 'Open a shell in the job' }).click();
  await expect(page.getByRole('button', { name: 'Open shell' })).toHaveCount(0);
});

// The batch name goes to the batch's page; the rest of the row still
// opens it in place. /users/<owner> is the same table.
async function openUserPage(page: Page, owner: string) {
  const placeholder = path.join(__dirname, '..', 'out', 'users', '_.html');
  await page.route(`**/users/${owner}`, async (route) => {
    if (route.request().resourceType() !== 'document') {
      await route.fallback();
      return;
    }
    await route.fulfill({ path: placeholder, contentType: 'text/html; charset=utf-8' });
  });
  await page.goto(`/users/${owner}`);
}

for (const where of ['/jobs', '/users/e2e']) {
  test(`${where}: a batch's name opens its page, the rest of its row its jobs`, async ({ page }) => {
    await installJobsProgressFixtures(page);
    if (where === '/jobs') await page.goto('/jobs');
    else await openUserPage(page, 'e2e');
    const row = page.getByRole('row').filter({ hasText: 'smoke-sweep' });
    const name = row.getByRole('link', { name: 'smoke-sweep' });
    await expect(name).toHaveAttribute('href', '/batches/500');
    await row.getByText('/home/e2e/bin/train').first().click();
    await expect(page.getByRole('link', { name: '500.0' })).toBeVisible();
    await expect(row).toHaveAttribute('aria-expanded', 'true');
    await name.click();
    await page.waitForURL('**/batches/500');
  });
}
