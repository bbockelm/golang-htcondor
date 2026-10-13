import { expect, test, type Page } from '@playwright/test';
import path from 'node:path';

import { installApiFixtures } from './fixtures/api';
import { SMOKE_NOW } from './fixtures/clock';

// A job's "All attributes" list on a phone: each attribute is a card,
// long values are clamped behind Show more, and nothing on the job and
// archive pages makes the page scroll sideways.

// A finished job carrying the values that are long in practice: an
// environment, a Requirements expression, arguments, a transfer list,
// and strings with no whitespace to break at.
const longPath = '/home/e2e/projects/simulation-campaign-2026/inputs/very/deeply/nested/directory/structure';
const environment = [
  'OMP_NUM_THREADS=4',
  "GREETING='hello world'",
  "QUOTE='it''s here'",
  ...Array.from({ length: 20 }, (_, i) => `SMOKE_VAR_${i}=${'x'.repeat(30)}${i}`),
].join(' ');

const longValuesAd: Record<string, unknown> = {
  ClusterId: 9100,
  ProcId: 0,
  Owner: 'e2e',
  JobStatus: 4,
  ExitCode: 0,
  ExitBySignal: false,
  JobUniverse: 5,
  QDate: SMOKE_NOW - 7200,
  JobStartDate: SMOKE_NOW - 3600,
  CompletionDate: SMOKE_NOW - 600,
  RemoteWallClockTime: 3000,
  Cmd: `${longPath}/bin/run_simulation_with_a_rather_long_executable_name.sh`,
  Args: Array.from({ length: 12 }, (_, i) => `--parameter-${i}=${longPath}/p${i}`).join(' '),
  Iwd: longPath,
  JobBatchName: 'smoke-long-values',
  Environment: environment,
  Requirements:
    '/Expr((TARGET.Arch == "X86_64") && (TARGET.OpSys == "LINUX") && (TARGET.Disk >= RequestDisk) && (TARGET.Memory >= RequestMemory) && (TARGET.Cpus >= RequestCpus) && (TARGET.HasFileTransfer))/',
  TransferInput: Array.from({ length: 15 }, (_, i) => `${longPath}/input_${i}.dat`).join(','),
  GlobalJobId: 'smoke-ap.example.edu#9100.0#1791900000',
  LastRemoteHost: 'slot1_1@glidein_12345_67890@execute-node-with-a-long-name.smoke.example.edu',
  SmokeEncodedBlob: 'QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo'.repeat(12),
  RequestCpus: 1,
  RequestMemory: 2048,
  RequestDisk: 1048576,
  MemoryUsage: 900,
  // The server's evaluated requests, beside the ad rather than in it.
  evaluated: { RequestMemory: 2048, RequestCpus: 1, RequestDisk: 1048576 },
};

// /archive/<id> is one exported page answering every id in production;
// do the same here (see openJobPage in render.smoke.spec.ts).
async function openArchivePage(page: Page, id: string, ad: Record<string, unknown>) {
  const placeholder = path.join(__dirname, '..', 'out', 'archive', '_.html');
  await page.route(`**/archive/${id}`, async (route) => {
    if (route.request().resourceType() !== 'document') {
      await route.fallback();
      return;
    }
    await route.fulfill({ path: placeholder, contentType: 'text/html; charset=utf-8' });
  });
  await page.route('**/api/v1/jobs/archive**', (route) => route.fulfill({ json: { ads: [ad] } }));
  await page.goto(`/archive/${id}`);
}

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

async function noSidewaysScroll(page: Page) {
  const [scroll, inner] = await page.evaluate(() => [
    document.documentElement.scrollWidth,
    window.innerWidth,
  ]);
  expect(scroll, `the page is ${scroll}px wide in a ${inner}px viewport`).toBeLessThanOrEqual(inner);
}

function card(page: Page, name: string) {
  return page
    .getByTestId('attribute-card')
    .filter({ has: page.getByText(name, { exact: true }) });
}

test.beforeEach(async ({ page }) => {
  await installApiFixtures(page);
});

test.describe('390x844', () => {
  test.use({ viewport: { width: 390, height: 844 } });

  test('the archive page lists attributes as cards and clamps long values', async ({ page }) => {
    await openArchivePage(page, '9100.0', longValuesAd);
    await expect(page.getByRole('heading', { name: 'All Attributes' })).toBeVisible();
    await expect(page.getByRole('columnheader', { name: 'Attribute' })).toHaveCount(0);

    // Name above value.
    const id = card(page, 'GlobalJobId');
    await id.scrollIntoViewIfNeeded();
    await expect(id).toContainText('smoke-ap.example.edu#9100.0#1791900000');
    await noSidewaysScroll(page);

    // The server's evaluated requests are not one of the ad's attributes.
    await expect(card(page, 'evaluated')).toHaveCount(0);

    // A short value has no toggle.
    await expect(card(page, 'Owner').getByRole('button', { name: /Show/ })).toHaveCount(0);

    // The environment is clamped to three lines, with a toggle.
    const env = card(page, 'Environment');
    await env.scrollIntoViewIfNeeded();
    const more = env.getByRole('button', { name: 'Show more' });
    await expect(more).toHaveAttribute('aria-expanded', 'false');
    await expect(env).toContainText('23 variables');
    const clamped = env.locator('[id]').first();
    const [scrollH, clientH] = await clamped.evaluate((el) => [el.scrollHeight, el.clientHeight]);
    expect(scrollH, 'the environment is not clamped').toBeGreaterThan(clientH);

    // Opened, it is one variable per line with the quoting resolved.
    await more.click();
    const less = env.getByRole('button', { name: 'Show less' });
    await expect(less).toHaveAttribute('aria-expanded', 'true');
    const list = env.getByTestId('environment-list');
    await expect(list.getByRole('listitem')).toHaveCount(23);
    await expect(list.getByRole('listitem').nth(1)).toHaveText('GREETING=hello world');
    await expect(list.getByRole('listitem').nth(2)).toHaveText("QUOTE=it's here");
    await noSidewaysScroll(page);

    // A string with no whitespace wraps inside its card.
    const blob = card(page, 'SmokeEncodedBlob');
    await blob.scrollIntoViewIfNeeded();
    await blob.getByRole('button', { name: 'Show more' }).click();
    await expect(blob.getByRole('button', { name: 'Show less' })).toBeVisible();
    await noSidewaysScroll(page);

    // The filter still narrows the list.
    await page.getByRole('textbox', { name: 'Filter ClassAd attributes' }).fill('globaljob');
    await expect(page.getByTestId('attribute-card')).toHaveCount(1);
    await noSidewaysScroll(page);
  });

  test('the job page does not scroll sideways', async ({ page }) => {
    await openJobPage(page, '9100.0', longValuesAd);
    await expect(page.getByRole('heading', { name: 'All Attributes' })).toBeVisible();
    await expect(card(page, 'Environment')).toBeVisible();
    await noSidewaysScroll(page);
  });
});

test.describe('1280x900', () => {
  test.use({ viewport: { width: 1280, height: 900 } });

  test('the archive page keeps its attributes table on a wide screen', async ({ page }) => {
    await openArchivePage(page, '9100.0', longValuesAd);
    await expect(page.getByRole('columnheader', { name: 'Attribute' })).toBeVisible();
    await expect(page.getByTestId('attribute-card')).toHaveCount(0);
    const env = page.getByRole('row').filter({ has: page.getByText('Environment', { exact: true }) });
    await expect(env.getByRole('button', { name: 'Show more' })).toBeVisible();
    // A short value has no toggle.
    const owner = page.getByRole('row').filter({ has: page.getByText('Owner', { exact: true }) });
    await expect(owner.getByRole('button', { name: /Show/ })).toHaveCount(0);
    await noSidewaysScroll(page);
  });
});
