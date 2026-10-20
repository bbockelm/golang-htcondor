import type { Page } from '@playwright/test';

import type { RuntimeEstimateLevel } from '../../src/lib/api';
import { estimateFixture, similarFixture, type EstimateFor, type JobGroup } from '../../src/lib/similar.fixture';

// routeJobGroup answers one job's runtime estimate and its similar jobs
// from one group, so its cards and its similar-jobs plots agree. Without
// a group, the fixtures' default one.
export async function routeJobGroup(page: Page, jobID: string, job: EstimateFor = {}, group?: JobGroup) {
  await page.route(`**/api/v1/jobs/${jobID}/runtime-estimate`, (route) =>
    route.fulfill({ json: estimateFixture(jobID, job, group) }),
  );
  const id = jobID.replace(/\./g, '\\.');
  await page.route(new RegExp(`/api/v1/jobs/${id}/similar(\\?|$)`), (route) => {
    const q = new URL(route.request().url()).searchParams;
    return route.fulfill({
      json: similarFixture(
        jobID,
        {
          level: (q.get('level') ?? undefined) as RuntimeEstimateLevel | undefined,
          offset: Number(q.get('offset') ?? 0),
          page_size: Number(q.get('page_size') ?? 50),
        },
        group,
      ),
    });
  });
}
