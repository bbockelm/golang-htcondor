import { expect, test, type Page } from '@playwright/test';
import path from 'node:path';

import { installApiFixtures, installJobsProgressFixtures } from './fixtures/api';

// The batch actions menu, running and waiting times, the owner link on
// the job page, and the job page's Requirements breakdown, against
// mocked responses. The smoke session is an administrator, so every
// owner is linkable.

const now = Math.floor(Date.now() / 1000);
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
  await expect(row).toContainText(/running ones done by ~/);
  expect(asked[0]).toEqual(['72.0', '72.1']);
});

// Verbatim from a CHTC job page, as the API sends it.
const chtcRequirements =
  '/Expr(((((((((((PoolName == "CHTC") || (substr(Machine, 0, 3) == "gzk")) && ((Machine != "txie-dsigpu4000.chtc.wisc.edu") && (Machine != "gpu4002.chtc.wisc.edu"))) && (Arch == "X86_64")) && HasContainer) && HasDockerURL) && (Memory >= RequestMemory)) && (Cpus >= RequestCpus)) && (countMatches(MY.RequireGPUs, AvailableGPUs) >= RequestGPUs)) && ((FileSystemDomain == MY.FileSystemDomain) || (HasFileTransfer && stringListIMember("osdf", HasFileTransferPluginMethods)))))/';

test('the job page links the owner, times the run, and breaks down its requirements', async ({ page }) => {
  await page.route('**/api/v1/jobs/71.0/runtime-estimate', (route) =>
    route.fulfill({
      json: {
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
      },
    }),
  );
  await openJobPage(page, '71.0', {
    ClusterId: 71,
    ProcId: 0,
    JobStatus: 2,
    JobUniverse: 5,
    Owner: 'alice',
    Cmd: '/home/alice/run.sh',
    QDate: now - 90000,
    JobCurrentStartDate: now - twoHours14 - 60,
    JobCurrentStartExecutingDate: now - twoHours14,
    Requirements: chtcRequirements,
  });

  await expect(page.getByRole('link', { name: 'alice' })).toHaveAttribute('href', '/users/alice');
  await expect(page.getByText('running for 2h14m')).toBeVisible();
  await expect(page.getByText('About 45m left · running 2h15m of about 3h (usually 2h30m to 5h)')).toBeVisible();
  await expect(
    page.getByText('from 12 of your earlier jobs with the same command and argument pattern'),
  ).toBeVisible();

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
