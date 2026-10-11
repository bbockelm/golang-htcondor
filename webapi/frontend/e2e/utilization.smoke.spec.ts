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

// The /jobs page links a batch here as ?days=30&constraint=<the batch's
// constraint>. Landing on it must apply the constraint and show it in
// the box it applies through, so the user can see and edit what narrowed
// the page.
test('a link carrying a constraint lands filtered, with the expression in the box', async ({ page }) => {
  const seen = await installUtilization(page);
  await page.goto(`/utilization?days=30&constraint=${encodeURIComponent('JobBatchName == "summarize"')}`);
  await expect(page.getByRole('button', { name: 'ClassAd expression' })).toHaveAttribute('aria-pressed', 'true');
  await expect(page.getByPlaceholder(/ClassAd, e\.g\./)).toHaveValue('JobBatchName == "summarize"');
  await expect(page.getByRole('row', { name: /^summarize/ })).toBeVisible();
  await expect(page.getByRole('row', { name: /^blast-search/ })).toHaveCount(0);
  expect(lastQuery(seen).get('constraint')).toBe('JobBatchName == "summarize"');
  expect(lastQuery(seen).get('days')).toBe('30');
});

test("a workflow's page lists its jobs, sorted by the server and loaded as it scrolls", async ({ page }) => {
  await installUtilization(page);
  await page.goto('/utilization?w=wf-assemble');
  const list = page.getByTestId('workflow-jobs');
  await expect(list).toContainText('100 of 310 shown');
  await expect(list.getByRole('link').first()).toHaveAttribute('href', /^\/archive\/\d+\.\d+$/);

  const sorted = page.waitForRequest((r) => r.url().includes('/api/v1/utilization/jobs') && r.url().includes('sort=wall'));
  await list.getByRole('button', { name: /Run time/ }).click();
  await sorted;

  await expect(list).toContainText('100 of 310 shown');
  // The next page arrives as the end of the list scrolls into view, with
  // nothing clicked.
  await list.getByRole('button', { name: 'Load more' }).scrollIntoViewIfNeeded();
  await expect(list).toContainText('200 of 310 shown');
});

test('picking a bar of the memory histogram marks those jobs in the list', async ({ page }) => {
  await installUtilization(page);
  await page.goto('/utilization?w=wf-assemble');
  const fig = page.locator('figure', { hasText: 'Peak memory per job' });
  // The tallest values: the jobs that went over their request.
  await fig.locator('rect.cursor-pointer').last().click();
  const focus = page.getByTestId('job-focus');
  await expect(focus).toContainText('Marking jobs with peak memory');
  await expect(page.locator('[data-testid="workflow-jobs"] tr[data-marked="true"]').first()).toBeVisible();
  await focus.getByRole('button', { name: 'clear' }).click();
  await expect(focus).toHaveCount(0);
});

test('clicking a job on the run-time scatter finds it in the job list', async ({ page }) => {
  await installUtilization(page);
  await page.goto('/utilization?w=wf-assemble');
  const fig = page.locator('figure', { hasText: 'Run time and peak memory' });
  // A "went over memory" mark: few of them, so the click lands on one.
  await fig.scrollIntoViewIfNeeded();
  const mark = fig.locator('svg[role="img"] path').first();
  const box = (await mark.boundingBox())!;
  await page.mouse.click(box.x + box.width / 2, box.y + box.height / 2);
  const focus = page.getByTestId('job-focus');
  await expect(focus).toContainText(/Job \d+\.\d+, marked below\./);
  const id = (await focus.innerText()).match(/Job (\d+\.\d+)/)![1];
  const row = page.locator('[data-testid="workflow-jobs"] tr[data-marked="true"]');
  await expect(row).toHaveCount(1);
  await expect(row.getByRole('link')).toHaveText(id);
  await expect(row).toBeInViewport();
  await expect(fig.getByTestId('scatter-picked')).toHaveCount(1);
});

// On a phone: nothing scrolls sideways, chart text stays readable, and
// the workflows are cards.
test.describe('on a phone', () => {
  test.use({ viewport: { width: 390, height: 844 } });

  // The page scrolls inside the app shell, so both the document and the
  // shell's scroll container are checked.
  const sideways = (page: Page) =>
    page.evaluate(() =>
      [document.documentElement, ...document.querySelectorAll<HTMLElement>('.overflow-auto')]
        .filter((e) => !e.closest('table') && !e.closest('[data-testid="workflow-jobs"]'))
        .some((e) => e.scrollWidth > e.clientWidth + 1),
    );

  // The smallest chart text as drawn: its size in viewBox units times the
  // SVG's scale.
  const smallestChartText = (page: Page) =>
    page.evaluate(() => {
      let min = Infinity;
      for (const svg of document.querySelectorAll<SVGSVGElement>('figure svg[role="img"]')) {
        const vb = svg.viewBox.baseVal;
        if (!vb?.width) continue;
        const scale = svg.getBoundingClientRect().width / vb.width;
        for (const t of svg.querySelectorAll('text')) {
          const fs = parseFloat(getComputedStyle(t).fontSize);
          if (fs) min = Math.min(min, fs * scale);
        }
      }
      return min;
    });

  test('the overview fits the screen and lists workflows as cards', async ({ page }) => {
    await installUtilization(page);
    await page.goto('/utilization');
    await expect(page.getByTestId('workflow-card').first()).toBeVisible();
    await expect(page.locator('table')).toHaveCount(0);
    expect(await sideways(page)).toBe(false);
  });

  test("a workflow's charts keep their text readable", async ({ page }) => {
    await installUtilization(page);
    await page.goto('/utilization?w=wf-assemble');
    await expect(page.locator('figure', { hasText: 'Peak memory per job' }).first()).toBeVisible();
    expect(await sideways(page)).toBe(false);
    expect(await smallestChartText(page)).toBeGreaterThanOrEqual(10);
  });
});

test('suggestions apply to waiting jobs after a review that lists every change', async ({ page }) => {
  await installUtilization(page);
  let body: unknown;
  await page.route(
    (u) => u.pathname === '/api/v1/utilization/apply',
    async (route) => {
      body = route.request().postDataJSON();
      await route.fulfill({
        json: {
          edited: 118,
          set: { RequestMemory: 1792, RequestDisk: 3 * 1024 * 1024 },
          declined: [],
          skipped: [{ job: '81291.4', reason: 'its memory request is a formula' }],
          failed: [],
        },
      });
    },
  );
  await page.goto('/utilization?w=wf-blast');
  const panel = page.getByTestId('apply-panel');
  await expect(panel).toContainText('120 jobs of this workflow are still waiting');
  await panel.getByRole('button', { name: 'Review the changes' }).click();
  const changes = panel.getByTestId('apply-changes');
  await expect(changes).toContainText('request_memory');
  await expect(changes).toContainText('1.8 GB');
  await expect(changes).toContainText('request_disk');
  await panel.getByRole('button', { name: 'Apply to 120 waiting jobs' }).click();
  const result = page.getByTestId('apply-result');
  await expect(result).toContainText('Changed 118 waiting jobs: now requesting memory 1.8 GB, disk 3 GB.');
  await expect(result).toContainText('1 job — its memory request is a formula');
  // Ids, not values: the server writes what its own advice says.
  expect(body).toMatchObject({ w: 'wf-blast', advice: ['memory-retry', 'disk-lower'], days: 7 });
  expect(JSON.stringify(body)).not.toContain('1792');
});
