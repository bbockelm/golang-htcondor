import { expect, test } from '@playwright/test';

import { installApiFixtures } from './fixtures/api';
import { routeJobGroup } from './fixtures/estimates';
import type { JobGroup } from '../src/lib/similar.fixture';
import { ARCHIVE_RUNS, openArchivedRestartedJob, openRunningNoGpuJob } from './fixtures/jobpages';
import { CONTAINER_GPU_NOTABLE } from '../src/lib/requirements.fixture';

test.beforeEach(async ({ page }) => {
  await installApiFixtures(page);
});

test('an archived job shows a request written as an expression as one number, in the table and the graph', async ({ page }) => {
  await openArchivedRestartedJob(page);

  const resources = page.locator('table').filter({ has: page.getByRole('columnheader', { name: 'Requested' }) });
  const memory = resources.getByRole('row').filter({ has: page.getByRole('cell', { name: 'Memory', exact: true }) });
  await expect(memory.getByText('10.7 GB')).toBeVisible();
  await expect(memory.getByText('from expression')).toBeVisible();
  await expect(memory.locator('[title^="ifthenelse(MemoryUsage"]')).toHaveCount(1);

  const graph = page.locator('figure').filter({ has: page.getByText('Memory', { exact: true }) });
  await expect(graph.getByText('Requested 10.7 GB · from expression')).toBeVisible();
  // The axis in one unit, in round steps of it.
  await expect(graph.locator('svg > g:has(> line.stroke-gray-100) > text')).toHaveText(['0', '5 GB', '10 GB', '15 GB']);
});

test('an archived job breaks down its Requirements', async ({ page }) => {
  await openArchivedRestartedJob(page);

  const reqs = page.locator('div').filter({ has: page.getByRole('heading', { name: 'Requirements' }) }).last();
  await expect(reqs.locator('li code')).toHaveText(CONTAINER_GPU_NOTABLE);
  await expect(reqs.getByText('Standard resource requirements (CPUs, memory, GPUs)')).toBeVisible();
});

test('a job restarted 68 times draws each run in a different color from its neighbours', async ({ page }) => {
  await openArchivedRestartedJob(page);

  const graph = page.locator('figure').filter({ has: page.getByText('Memory', { exact: true }) });
  const lines = graph.locator('polyline');
  await expect(lines).toHaveCount(ARCHIVE_RUNS);
  const strokes = await lines.evaluateAll((els) => els.map((e) => e.getAttribute('stroke')));
  for (let i = 1; i < strokes.length; i++) expect(strokes[i]).not.toBe(strokes[i - 1]);
  await expect(
    graph.getByText(`${ARCHIVE_RUNS} runs (Run 1 to Run ${ARCHIVE_RUNS}). Colors repeat every 6 runs; hover a point for its run.`),
  ).toBeVisible();
});

test('a job that requested no GPUs has no GPU row', async ({ page }) => {
  await openRunningNoGpuJob(page);

  const resources = page.locator('table').filter({ has: page.getByRole('columnheader', { name: 'Requested' }) });
  await expect(resources.getByRole('cell', { name: 'CPUs', exact: true })).toBeVisible();
  await expect(resources.getByRole('cell', { name: 'GPUs', exact: true })).toHaveCount(0);
});

// Job 9301.0 ran 68 times for about 57h in all and peaked at 7.2 GB.
// Against a group of runs like it, that is ordinary.
const ordinary9301: JobGroup = {
  runtimes: { count: 40, p10: 150_000, p25: 180_000, p50: 200_000, p75: 220_000, p90: 240_000 },
  memory: { count: 35, p10: 5200, p25: 5600, p50: 6000, p75: 6600, p90: 7100 },
};

test('an archived job compares its peak memory with similar jobs', async ({ page }) => {
  await routeJobGroup(page, '9301.0', { peak_mib: 7325, requested_mib: 10987 }, ordinary9301);
  await openArchivedRestartedJob(page);
  const memory = page.getByTestId('memory-estimate');
  await expect(memory.getByText('Peaked at 7.2 GB')).toBeVisible();
  await expect(memory.getByText('Similar jobs peaked at about 5.9 GB; 9 in 10 stayed under 6.9 GB.')).toBeVisible();
  // A finished job is not compared with its request in words; its request
  // is drawn, as on the similar-jobs plot.
  await expect(memory.getByText(/requested/)).toHaveCount(0);
  await expect(memory.getByText('More memory than usual')).toHaveCount(0);
  const bar = memory.getByTestId('memory-range-bar');
  await expect(bar.locator('[data-part="job-end"]')).toHaveClass(/bg-green-700/);
  await expect(bar.locator('[data-part="ref"]')).toBeVisible();
  await memory.getByRole('button', { name: 'How to read' }).click();
  await expect(memory.getByTestId('range-legend').getByRole('listitem')).toHaveText([
    'Most similar jobs', 'Half of similar jobs', 'Typical', 'This job', 'This job, unusually high', 'Requested',
  ]);

  // The similar jobs' memory -- the same group -- drawn the same way.
  await page.getByTestId('job-related').getByRole('button', { name: 'Similar jobs' }).click();
  const plot = page.getByTestId('memory-spread-plot');
  await expect(page.getByTestId('memory-spread')).toContainText('typically 5.9 GB');
  for (const name of ['band', 'box', 'tick', 'job', 'ref']) {
    await expect(plot.locator(`[data-part="${name}"]`)).toHaveClass(
      (await bar.locator(`[data-part="${name}"]`).getAttribute('class'))!,
    );
  }
  await expect(page.getByTestId('similar-jobs').getByText('Longer than usual')).toHaveCount(0);
});

// Against the fixtures' usual group -- typically 45m and 1.2 GB -- the
// same job ran far longer and used far more: both its plots turn amber.
test('an archived job that ran longer and used more than usual says so', async ({ page }) => {
  await routeJobGroup(page, '9301.0', { peak_mib: 7325, requested_mib: 10987, exceeded_history: true, above_usual: true });
  await openArchivedRestartedJob(page);
  const memory = page.getByTestId('memory-estimate');
  await expect(memory.getByText('More memory than usual')).toBeVisible();
  await expect(memory.getByText('Similar jobs peaked at about 1.2 GB; 9 in 10 stayed under 1.5 GB.')).toBeVisible();
  await expect(memory.getByTestId('memory-range-bar').locator('[data-part="job-end"]')).toHaveClass(/bg-amber-600/);
  await memory.getByRole('button', { name: 'How to read' }).click();
  await expect(memory.getByTestId('range-legend')).toContainText('This job, unusually high');

  await page.getByTestId('job-related').getByRole('button', { name: 'Similar jobs' }).click();
  const similar = page.getByTestId('similar-jobs');
  await expect(similar.getByText('Longer than usual')).toBeVisible();
  await expect(similar.getByText('More memory than usual')).toBeVisible();
  for (const id of ['runtime-spread-plot', 'memory-spread-plot']) {
    await expect(similar.getByTestId(id).locator('[data-part="job-end"]')).toHaveClass(/bg-amber-600/);
  }
  await similar.getByTestId('runtime-spread').getByRole('button', { name: 'How to read' }).click();
  await expect(similar.getByTestId('runtime-spread').getByTestId('range-legend')).toContainText('This job, unusually high');
});
