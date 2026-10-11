import { expect, test, type Page, type Request } from '@playwright/test';

import { installApiFixtures } from './fixtures/api';
import { ownersOf, utilizationFixture } from '../src/lib/utilization.fixture';

// The Utilization page's filters and controls against a fixture that
// answers the way the server does: it narrows by `owners`, narrows by a
// batch-name `constraint`, rejects an expression it cannot parse with a
// 400, and reports a cut-short answer until asked for more.
//
// Every test also records the requests the page made, because "the chip
// appeared" is only half of the filter: the other half is that the query
// carries it.

async function installUtilization(page: Page): Promise<Request[]> {
  const seen: Request[] = [];
  await page.route((u) => u.pathname === '/api/v1/utilization', async (route) => {
    const req = route.request();
    seen.push(req);
    const q = new URL(req.url()).searchParams;
    const constraint = q.get('constraint') ?? '';
    if (constraint.includes('===')) {
      await route.fulfill({
        status: 400,
        json: { error: 'Bad Request', message: `Invalid constraint: unable to parse "${constraint}"` },
      });
      return;
    }
    const owners = (q.get('owners') ?? '').split(',').filter(Boolean);
    const limit = Number(q.get('limit') ?? 50_000);
    let workflows = utilizationFixture.workflows;
    const m = constraint.match(/JobBatchName == "([^"]+)"/);
    if (m) workflows = workflows.filter((w) => w.name === m[1]);
    if (owners.length) workflows = workflows.filter((w) => owners.includes(w.owner ?? ''));
    await route.fulfill({
      json: {
        ...utilizationFixture,
        days: Number(q.get('days') ?? 7),
        workflows,
        owners: ownersOf(workflows),
        limit,
        max_limit: 1_000_000,
        // The month is cut short until the page asks for everything.
        truncated: q.get('days') === '30' && limit < 1_000_000,
      },
    });
  });
  return seen;
}

// Pool-wide: the owner filter only exists for a session that can see
// other users' jobs, and only in the Everyone scope.
async function everyone(page: Page) {
  await page.addInitScript(() => {
    try {
      localStorage.setItem('htcondor.listingScope', 'all');
    } catch {
      /* the page falls back to Mine */
    }
  });
}

const lastQuery = (seen: Request[]) => new URL(seen[seen.length - 1].url()).searchParams;

test.beforeEach(async ({ page }) => {
  await installApiFixtures(page);
});

test('the text filter narrows the workflows and lives in the URL', async ({ page }) => {
  await installUtilization(page);
  await page.goto('/utilization');
  await page.getByPlaceholder(/Filter workflows/).fill('blast');
  await expect(page.getByRole('row', { name: /^blast-search/ })).toBeVisible();
  await expect(page.getByRole('row', { name: /^train-resnet/ })).toHaveCount(0);
  await expect(page).toHaveURL(/[?&]q=blast/);
});

test('a ClassAd filter goes to the server, and a bad one is reported by the input', async ({ page }) => {
  const seen = await installUtilization(page);
  await page.goto('/utilization');
  await page.getByRole('button', { name: 'ClassAd expression' }).click();
  const input = page.getByPlaceholder(/ClassAd, e\.g\./);
  await input.fill('JobBatchName == "summarize"');
  await page.getByRole('button', { name: 'Apply' }).click();
  await expect(page.getByRole('row', { name: /^summarize/ })).toBeVisible();
  await expect(page.getByRole('row', { name: /^blast-search/ })).toHaveCount(0);
  expect(lastQuery(seen).get('constraint')).toBe('JobBatchName == "summarize"');
  await expect(page).toHaveURL(/constraint=/);

  await input.fill('RequestGpus === 1');
  await page.getByRole('button', { name: 'Apply' }).click();
  // By the input, not in place of the page: Next's route announcer is
  // also an alert, so pick ours by its text.
  await expect(page.getByRole('alert').filter({ hasText: 'Invalid constraint' })).toContainText(
    'unable to parse "RequestGpus === 1"',
  );
});

test('clicking an owner adds them to the filter, and the query carries it', async ({ page }) => {
  await everyone(page);
  const seen = await installUtilization(page);
  await page.goto('/utilization');
  await page.getByTestId('owner-pill').filter({ hasText: 'bob' }).first().click();
  await expect(page.getByTestId('owner-chip')).toHaveText(['bob×']);
  await expect.poll(() => lastQuery(seen).get('owners')).toBe('bob');
  await expect(page.getByRole('row', { name: /^genome-assembly/ })).toBeVisible();
  await expect(page.getByRole('row', { name: /^blast-search/ })).toHaveCount(0);
  await expect(page).toHaveURL(/owners=bob/);
});

test('the user list picks several users and keeps offering the rest', async ({ page }) => {
  await everyone(page);
  const seen = await installUtilization(page);
  await page.goto('/utilization');
  await page.getByRole('button', { name: /^Users/ }).click();
  // click, not check: the box follows the URL, which updates a moment
  // after the click rather than within it.
  await page.getByRole('checkbox', { name: /alice/ }).click();
  await expect(page.getByRole('checkbox', { name: /alice/ })).toBeChecked();
  await expect.poll(() => lastQuery(seen).get('owners')).toBe('alice');
  // The list still has bob: it comes from the answer without the filter.
  await page.getByRole('checkbox', { name: /bob/ }).click();
  await expect(page.getByRole('checkbox', { name: /bob/ })).toBeChecked();
  await expect.poll(() => lastQuery(seen).get('owners')).toBe('alice,bob');
  await expect(page.getByTestId('owner-chip')).toHaveText(['alice×', 'bob×']);
  await page.getByRole('button', { name: 'Remove alice' }).click();
  await expect(page.getByTestId('owner-chip')).toHaveText(['bob×']);
});

test('a cut-short answer offers to analyze more, with a way back', async ({ page }) => {
  const seen = await installUtilization(page);
  await page.goto('/utilization?days=30');
  const notice = page.getByTestId('truncated');
  await expect(notice).toContainText('not all of them');
  await notice.getByRole('button', { name: 'Analyze up to 250,000 jobs' }).click();
  await expect(page).toHaveURL(/limit=250000/);
  await expect.poll(() => lastQuery(seen).get('limit')).toBe('250000');
  await page.getByRole('button', { name: /all, up to 1,000,000/ }).click();
  await expect(page.getByText(/covers all/)).toBeVisible();
  await page.getByRole('button', { name: 'Back to the usual number' }).click();
  await expect(page).not.toHaveURL(/limit=/);
});

test('single-job workflows fold into one row that opens', async ({ page }) => {
  await installUtilization(page);
  await page.goto('/utilization');
  const group = page.getByTestId('singles-group');
  await expect(group).toContainText('3 single-job workflows');
  await expect(page.getByRole('row', { name: /^debug-run/ })).toHaveCount(0);
  await group.getByRole('button').click();
  await expect(page.getByRole('row', { name: /^debug-run: 1 job/ })).toBeVisible();
});

test('the headline leads with GPUs when jobs reserved them', async ({ page }) => {
  await installUtilization(page);
  await page.goto('/utilization');
  const first = page.locator('[data-testid^="resource-"]').first();
  await expect(first).toHaveAttribute('data-testid', 'resource-gpu');
  await expect(first).toContainText('GPU-hours');
});
