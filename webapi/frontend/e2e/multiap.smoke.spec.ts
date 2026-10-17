import path from 'node:path';

import { expect, test } from '@playwright/test';

import { installApiFixtures } from './fixtures/api';
import { restartedJobMetrics } from './fixtures/jobpages';
import { SMOKE_NOW } from './fixtures/clock';

// Multi-AP mode against mocked responses: the pages render, name the
// access point of every job, say which access point is behind, and
// submit to the caller's home access point or an alternate.

test.beforeEach(async ({ page }) => {
  await installApiFixtures(page, { multiAP: true });
});

function watchForErrors(page: import('@playwright/test').Page) {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(String(e)));
  page.on('console', (m) => {
    if (m.type() === 'error') errors.push(m.text());
  });
  return errors;
}

for (const path of ['/', '/jobs', '/archive', '/utilization', '/aps', '/submit', '/interactive']) {
  test(`multi-AP: renders ${path} without page errors`, async ({ page }) => {
    const errors = watchForErrors(page);
    const res = await page.goto(path);
    expect(res?.status(), `${path} should not 4xx/5xx`).toBeLessThan(400);
    await expect(page.locator('body')).toBeVisible();
    expect(errors, `${path} raised page errors`).toEqual([]);
  });
}

test('multi-AP: the jobs page shows both access points and the one behind', async ({ page }) => {
  await page.goto('/jobs');
  await expect(page.getByText('smoke-ap1-batch')).toBeVisible();
  await expect(page.getByText('smoke-ap2-batch')).toBeVisible();
  await expect(page.getByRole('cell', { name: 'ap2.smoke.example' })).toBeVisible();
  await expect(page.getByRole('status')).toContainText('ap2.smoke.example (stale, 412 s behind)');
  await expect(page.getByText('+ Submit a batch')).toHaveCount(0);
  await expect(page.getByTitle(/Remove batch/)).toHaveCount(0);
});

test('multi-AP: the sidebar offers the pages multi-AP mode serves', async ({ page }) => {
  await page.goto('/jobs');
  await expect(page.getByRole('link', { name: 'Access Points' })).toBeVisible();
  await expect(page.getByRole('link', { name: 'Submit', exact: true })).toBeVisible();
  await expect(page.getByRole('link', { name: 'Interactive', exact: true })).toBeVisible();
});

test('multi-AP: a terminal launches on the chosen access point', async ({ page }) => {
  const posted: string[] = [];
  await page.route('**/api/v1/interactive/terminal?schedd=*', async (route) => {
    if (route.request().method() !== 'POST') return route.fallback();
    posted.push(route.request().url());
    await route.fulfill({
      status: 201,
      contentType: 'application/json',
      body: JSON.stringify({
        instance_id: 'abc',
        cluster_id: 8,
        proc_id: 0,
        job_id: '8.0@ap2.smoke.example',
        batch_name: 'htcondor-api-interactive-terminal-abc',
        schedd: 'ap2.smoke.example',
      }),
    });
  });
  await page.goto('/interactive');
  // One launcher per kind of interactive work, each naming where it goes.
  await expect(page.getByText('Will submit to')).toHaveCount(3);
  const select = page.getByRole('combobox', { name: 'Access point for the terminal' });
  await expect(select).toHaveValue('ap1.smoke.example');
  await select.selectOption('ap2.smoke.example');
  await page.getByRole('button', { name: 'Launch terminal' }).click();
  await expect.poll(() => posted.length).toBe(1);
  expect(new URL(posted[0]).searchParams.get('schedd')).toBe('ap2.smoke.example');
  await expect(page).toHaveURL(/\/interactive\/terminal\/8\.0(%40|@)ap2\.smoke\.example/);
});

test('multi-AP: the submit page names the access point and offers the alternates', async ({ page }) => {
  await page.goto('/submit');
  await expect(page.getByText('Will submit to')).toBeVisible();
  const select = page.getByRole('combobox', { name: 'Access point' });
  await expect(select).toHaveValue('ap1.smoke.example');
  await expect(select.locator('option')).toHaveText(['ap1.smoke.example (home)', 'ap2.smoke.example']);
  await select.selectOption('ap2.smoke.example');
  await expect(select).toHaveValue('ap2.smoke.example');
});

test('multi-AP: submitting sends the chosen access point and the job ids that come back', async ({ page }) => {
  const posted: string[] = [];
  await page.route('**/api/v1/jobs?schedd=*', async (route) => {
    if (route.request().method() !== 'POST') return route.fallback();
    posted.push(route.request().url());
    await route.fulfill({
      status: 201,
      contentType: 'application/json',
      body: JSON.stringify({
        cluster_id: 7,
        job_ids: ['7.0@ap2.smoke.example'],
        schedd: 'ap2.smoke.example',
      }),
    });
  });
  await page.route('**/api/v1/templates', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        templates: [
          {
            id: 'smoke-true',
            name: 'Smoke true',
            columns: [],
            contents: 'executable = /bin/true\ntransfer_executable = false\n',
            source: 'builtin',
          },
        ],
      }),
    }),
  );
  await page.goto('/submit');
  await page.getByRole('combobox', { name: 'Access point' }).selectOption('ap2.smoke.example');
  // A template with no columns is submitted as copies: its one table
  // row is empty, which the manual table refuses.
  await page.getByRole('button', { name: 'Run N copies' }).click();
  const button = page.getByRole('button', { name: /^Submit batch/ });
  await expect(button).toBeEnabled();
  await button.click();
  await expect.poll(() => posted.length).toBe(1);
  expect(new URL(posted[0]).searchParams.get('schedd')).toBe('ap2.smoke.example');
  await expect(page).toHaveURL(/\/jobs\/7\.0(%40|@)ap2\.smoke\.example/);
});

test('multi-AP: the access points page marks where the caller may submit', async ({ page }) => {
  await page.goto('/aps');
  await expect(page.getByText('your home')).toBeVisible();
  await expect(page.getByText('you may submit')).toBeVisible();
});

test('multi-AP: the archive names the access point and links the complete id', async ({ page }) => {
  await page.goto('/archive');
  const link = page.getByRole('link', { name: '39.0@ap1.smoke.example' });
  await expect(link).toBeVisible();
  await expect(link).toHaveAttribute('href', '/archive/39.0%40ap1.smoke.example');
});

test('multi-AP: the job page plots resource usage for the job on its access point', async ({ page }) => {
  const errors = watchForErrors(page);
  const id = '9301.0@ap2.smoke.example';
  // The job page's document: the export's placeholder, as the Go server
  // answers it.
  const placeholder = path.join(__dirname, '..', 'out', 'jobs', '_.html');
  await page.route(
    (url) => decodeURIComponent(url.pathname) === `/jobs/${id}`,
    async (r) => {
      if (r.request().resourceType() !== 'document') return r.fallback();
      await r.fulfill({ path: placeholder, contentType: 'text/html; charset=utf-8' });
    },
  );
  await page.route(
    (url) => decodeURIComponent(url.pathname) === `/api/v1/jobs/${id}`,
    (r) =>
      r.fulfill({
        json: {
          schedd: 'ap2.smoke.example',
          cluster: 9301,
          proc: 0,
          job_id: id,
          archived: false,
          source: 'hub',
          ClusterId: 9301,
          ProcId: 0,
          Owner: 'e2e',
          JobStatus: 2,
          QDate: SMOKE_NOW - 7200,
          RequestMemory: 10987,
          RequestCpus: 4,
          Cmd: '/bin/smoke',
        },
      }),
  );
  const asked: URLSearchParams[] = [];
  await page.route('**/api/v1/metrics/job_metrics?**', (r) => {
    asked.push(new URL(r.request().url()).searchParams);
    return r.fulfill({
      json: {
        ...restartedJobMetrics(),
        job: { schedd: 'ap2.smoke.example', cluster: 9301, proc: 0, job_id: id },
        sources: { aps: 2, fresh: 2, degraded: [] },
      },
    });
  });
  await page.goto(`/jobs/${id}`);
  await expect(page.getByRole('heading', { name: 'Resource usage' })).toBeVisible();
  await expect(page.getByRole('img', { name: /^Memory over time/ })).toBeVisible();
  // The samples are asked for by the complete id, with no cluster.proc
  // clause that would match another access point's 9301.0.
  expect(asked.length).toBeGreaterThan(0);
  for (const q of asked) {
    expect(q.get('job_id')).toBe(id);
    expect(q.get('constraint') ?? '').not.toMatch(/ClusterId|ProcId/);
  }
  expect(errors).toEqual([]);
});
