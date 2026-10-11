import { expect, test } from '@playwright/test';

import type { CollectorAdsResponse } from '../src/lib/api';
import type { DrainEstimates } from '../src/lib/drain';
import { emptyDrainFixture, installApiFixtures } from './fixtures/api';

// The Pool page's "Empty if drained now" column binds the drain
// estimates to the nodes the collector query lists: one node with a mix
// of estimated jobs and jobs from elsewhere, one draining, one idle.

const partitionable = (machine: string, free: number, running: number) => ({
  Name: `slot1@${machine}`,
  Machine: machine,
  SlotType: 'Partitionable',
  PartitionableSlot: true,
  Cpus: free,
  Memory: 1024,
  TotalCpus: 48,
  TotalMemory: 196608,
  NumDynamicSlots: running,
  State: 'Unclaimed',
  Activity: 'Idle',
});

const slotsFixture: CollectorAdsResponse = {
  ads: [
    partitionable('e2231.smoke.example', 8, 6),
    partitionable('e4019.smoke.example', 36, 3),
    partitionable('e0907.smoke.example', 48, 0),
  ],
};

const node = {
  jobs_from_this_ap: 0,
  jobs_unknown_end: 0,
  jobs_unknown_from_other_aps: 0,
  evicted_on_drain: 0,
  exceeded: 0,
};

const drainFixture: DrainEstimates = {
  ...emptyDrainFixture,
  summary: {
    machines: 2,
    jobs_running: 9,
    jobs_estimated: 5,
    jobs_from_this_ap: 5,
    cores_freeing_next_hour: 12,
    draining_nodes: 1,
    draining_likely_empty_within_2h: 1,
  },
  machines: [
    {
      ...node,
      machine: 'e2231.smoke.example',
      draining: false,
      jobs_total: 6,
      jobs_estimated: 2,
      jobs_from_this_ap: 2,
      jobs_unknown_end: 4,
      jobs_unknown_from_other_aps: 4,
      likely_empty_seconds: 5400,
      at_least_seconds: 5400,
      unknown_up_to_seconds: 259200,
      at_most_seconds: 259200,
      expected_ends: [
        { seconds: 2700, usually_by_seconds: 5400, cpus: 4 },
        { seconds: 5400, usually_by_seconds: 8100, cpus: 4 },
      ],
    },
    {
      ...node,
      machine: 'e4019.smoke.example',
      draining: true,
      jobs_total: 3,
      jobs_estimated: 3,
      jobs_from_this_ap: 3,
      likely_empty_seconds: 2400,
      likely_empty_at: new Date(Date.now() + 2400_000).toISOString(),
      expected_ends: [{ seconds: 2400, usually_by_seconds: 3600, cpus: 4 }],
    },
  ],
};

test('pool page says when each node would be empty if drained now', async ({ page }) => {
  await installApiFixtures(page);
  await page.route('**/api/v1/collector/ads/**', (route) => route.fulfill({ json: slotsFixture }));
  await page.route('**/api/v1/pool/drain-estimates', (route) => route.fulfill({ json: drainFixture }));
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(String(e)));
  page.on('console', (m) => {
    if (m.type() === 'error') errors.push(m.text());
  });

  await page.goto('/pool');
  await expect(page.getByRole('columnheader', { name: 'Empty if drained now' })).toBeVisible();
  await expect(page.getByText('At least 1h30m')).toBeVisible();
  await expect(
    page.getByText('2 of 6 jobs estimated · 4 from other access points could run up to 3 days'),
  ).toBeVisible();
  await expect(page.getByText('Draining · about 40m')).toBeVisible();
  await expect(page.getByText('Empty now')).toBeVisible();
  await expect(page.getByText('Running jobs with an estimate')).toBeVisible();
  expect(errors).toEqual([]);
});
