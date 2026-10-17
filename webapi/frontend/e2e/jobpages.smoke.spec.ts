import { expect, test } from '@playwright/test';

import { installApiFixtures } from './fixtures/api';
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

test('an archived job compares its peak memory with similar jobs', async ({ page }) => {
  await page.route('**/api/v1/jobs/9301.0/runtime-estimate', (route) =>
    route.fulfill({
      json: {
        job_id: '9301.0',
        available: true,
        estimate_seconds: 3000,
        p10_seconds: 2400,
        p90_seconds: 3600,
        basis: { level: 'exact', sample_count: 40 },
        exceeded_history: false,
        memory: { sample_count: 40, p10_mib: 5200, p25_mib: 5600, p50_mib: 6000, p75_mib: 6600, p90_mib: 7100, peak_mib: 7325, requested_mib: 10987, above_requested: 0, rough: false, above_usual: false },
        model: { jobs_ingested: 5000 },
      },
    }),
  );
  await openArchivedRestartedJob(page);
  const memory = page.getByTestId('memory-estimate');
  await expect(memory.getByText('Peaked at 7.2 GB')).toBeVisible();
  await expect(memory.getByText('Similar jobs peaked at about 5.9 GB; 9 in 10 stayed under 6.9 GB.')).toBeVisible();
  // A finished job is not compared with its request, nor called above usual.
  await expect(memory.getByText(/requested/)).toHaveCount(0);
  await expect(memory.getByText('More memory than usual')).toHaveCount(0);
});
