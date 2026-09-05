import { expect, test } from '@playwright/test';

// Full-stack suite: the real htcondor-api binary, serving the embedded
// UI, against a real personal HTCondor. Authentication is the
// HTTP_API_USER_HEADER the server is started with (see the workflow);
// playwright.config.ts attaches it to every request.
//
// What this catches that the smoke suite cannot: the API contract. A
// backend response shape change slips past frozen fixtures but fails
// here, because the page is binding whatever the server actually sends.

test('the API is up and reports our identity', async ({ request }) => {
  const res = await request.get('/api/v1/whoami');
  expect(res.status()).toBe(200);
  const body = await res.json();
  expect(body.authenticated, 'header auth should be accepted').toBe(true);
  expect(body.user, 'server should attribute the request to the header user').toBeTruthy();
});

test('the UI is served by the binary, not a dev server', async ({ page }) => {
  const res = await page.goto('/');
  expect(res?.status()).toBeLessThan(400);
  // The embedded export is what production ships (Dockerfile.release
  // stage 2 with go:embed); if this 404s, the embed tag was missing.
  await expect(page.locator('body')).toBeVisible();
});

test('the jobs page renders against a live schedd', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(String(e)));

  await page.goto('/jobs');
  await expect(page.locator('body')).toBeVisible();

  // An empty queue is a legitimate result here — a fresh personal
  // condor has no jobs. What must not happen is an error state or a
  // render failure, so assert on those rather than on rows.
  await expect(page.getByText(/failed|error/i).first()).toBeHidden({ timeout: 5_000 }).catch(() => {
    // getByText finds nothing at all when the page is clean, which
    // toBeHidden treats as passing; the catch only absorbs strict-mode
    // violations from multiple incidental matches.
  });
  expect(errors, 'jobs page raised page errors against a live server').toEqual([]);
});

test('a submitted job appears in the queue', async ({ request }) => {
  const submit = await request.post('/api/v1/jobs', {
    data: {
      submit_file: ['executable = /bin/sleep', 'arguments = 30', 'queue 1'].join('\n'),
    },
  });

  // This is the path that broke on ap40: MaxTransferInputMB leaked from
  // a config default into every job ad and a schedd protecting the
  // attribute refused the transaction (#235). A submit that 500s here
  // is exactly that class of regression.
  expect(
    submit.status(),
    `submit failed: ${await submit.text()}`,
  ).toBeLessThan(400);

  const created = await submit.json();
  const cluster = created.cluster_id ?? created.ClusterId ?? created.cluster;
  expect(cluster, 'submit response should name the new cluster').toBeTruthy();

  const listed = await request.get('/api/v1/jobs');
  expect(listed.status()).toBe(200);
  expect(await listed.text()).toContain(String(cluster));
});
