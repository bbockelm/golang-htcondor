import { readFileSync } from 'node:fs';

import { expect, test } from '@playwright/test';

import { adminPassword, loginAsAdmin } from './fixtures/login';

// Full-stack suite: the real htcondor-api binary, serving the embedded
// UI, against a real personal HTCondor started by `-demo`.
//
// Everything here runs behind a real login. The suite previously
// authenticated with a trusted user header, which demo mode does not
// accept and which could not drive the UI in any case -- see
// fixtures/login.ts. So the API tests below use `page.request`, which
// shares the logged-in browser context's cookies, rather than the
// standalone `request` fixture, which has none.
//
// What this catches that the smoke suite cannot: the API contract. A
// backend response shape change slips past frozen fixtures but fails
// here, because the page is binding whatever the server actually sends.

// Demo mode generates the admin password per run and prints it; the
// workflow captures the server output to this path.
const password = adminPassword(
  readFileSync(process.env.E2E_SERVER_LOG ?? '/tmp/e2e-server.log', 'utf8'),
);

test.beforeEach(async ({ page }) => {
  await loginAsAdmin(page, password);
});

test('the API is up and reports our identity', async ({ page }) => {
  const res = await page.request.get('/api/v1/whoami');
  expect(res.status()).toBe(200);
  const body = await res.json();
  // whoami answers 200 with authenticated:false when auth fails, so the
  // status alone proves nothing -- the flag is the assertion.
  expect(body.authenticated, 'the session cookie should be accepted').toBe(true);
  expect(body.user, 'server should attribute the request to the logged-in user').toBeTruthy();
});

test('the UI is served from the embedded export', async ({ page }) => {
  // Fetched rather than rendered on purpose: this asserts the binary
  // serves the export at all -- if -tags embed_frontend were missing
  // this 404s. That the export actually renders is what the
  // browser tests below cover.
  const res = await page.request.get('/');
  expect(res.status()).toBe(200);
  const body = await res.text();
  expect(body, 'expected the prerendered HTML shell').toContain('<html');
  expect(body).toContain('__next');
});

test('a submitted job appears in the queue', async ({ page }) => {
  const submit = await page.request.post('/api/v1/jobs', {
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

  // owned_by_me=false deliberately. The default listing is scoped to the
  // caller, but the server reaches the schedd as its own process user, so
  // the schedd records Owner as the daemon user rather than the logged-in
  // identity -- the same "the schedd picks the identity, not the caller"
  // behavior behind #177. Scoping by owner here would assert that identity
  // plumbing rather than that the submit worked, and would fail for a
  // reason unrelated to what this test is for.
  const listed = await page.request.get('/api/v1/jobs?owned_by_me=false');
  expect(listed.status()).toBe(200);
  expect(
    await listed.text(),
    `cluster ${cluster} was accepted but is not in the queue`,
  ).toContain(String(cluster));
});

// Browser tests against the real server.
//
// These log in through the OAuth flow the deployed UI uses, so they
// exercise authenticated pages -- which nothing did before. Under the
// user-header auth this suite previously configured, the SPA saw itself
// as logged out and every page assertion landed on a 401 JSON document
// that "the body is visible" happily accepted.
test.describe('authenticated UI', () => {
  test('the jobs page renders against a live schedd', async ({ page }) => {
    const errors: string[] = [];
    page.on('pageerror', (e) => errors.push(String(e)));

    await page.goto('/jobs');

    // A logged-in SPA renders its chrome. Asserting on a nav item
    // proves we are looking at the application and not at the login
    // redirect or an error document -- the thing this suite could not
    // previously distinguish.
    await expect(page.getByRole('link', { name: /jobs/i }).first()).toBeVisible();
    expect(errors, 'jobs page raised page errors').toEqual([]);
  });

  // JupyterDetailClient, the component #240 refactored that nothing
  // reached. It only works behind a server that maps
  // /interactive/jupyter/<id> onto the page the export prerenders under
  // `_` -- webui/handler.go does exactly that -- and it skips fetching
  // for the literal placeholder (`enabled: !!id && id !== '_'`), so only
  // a concrete id against the real server drives it.
  test('the jupyter detail page derives a status for an unknown instance', async ({ page }) => {
    const errors: string[] = [];
    page.on('pageerror', (e) => errors.push(String(e)));

    await page.goto('/interactive/jupyter/no-such-instance');

    // No such instance exists, so the fetch 404s and deriveStatus must
    // resolve to 'gone'. Asserted on the exact copy that branch renders,
    // not a loose alternation: an earlier version of this test matched
    // /not found/i, which the server's non-embedded fallback page also
    // contains -- so it passed against a build that was not serving the
    // SPA at all. The 'error' branch renders "Could not load this
    // session", so this cannot pass by landing there either.
    await expect(page.getByText(/No such session/i)).toBeVisible();
    await expect(page.getByRole('link', { name: /back to sessions/i })).toBeVisible();
    expect(errors, 'jupyter detail raised page errors').toEqual([]);
  });
});
