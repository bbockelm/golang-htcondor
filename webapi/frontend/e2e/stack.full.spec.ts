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

test('the UI is served from the embedded export', async ({ request }) => {
  // Checked with request, not page: the SPA immediately redirects to
  // /login (see the note at the bottom of this file), so a browser lands
  // on an error document and page-level assertions here would pass on
  // that instead of on the UI. What this can honestly verify is that the
  // binary serves the export at all -- if -tags embed_frontend were
  // missing this 404s.
  const res = await request.get('/');
  expect(res.status()).toBe(200);
  const body = await res.text();
  expect(body, 'expected the prerendered HTML shell').toContain('<html');
  expect(body).toContain('__next');
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

  // owned_by_me=false deliberately. The default listing is scoped to the
  // caller, and under header auth the server reaches the schedd as its own
  // process user, so the schedd records Owner as the daemon user rather than
  // the header identity -- the same "the schedd picks the identity, not the
  // caller" behavior behind #177. Scoping by owner here would assert that
  // identity plumbing rather than that the submit worked, and would fail for
  // a reason unrelated to what this test is for.
  const listed = await request.get('/api/v1/jobs?owned_by_me=false');
  expect(listed.status()).toBe(200);
  expect(
    await listed.text(),
    `cluster ${cluster} was accepted but is not in the queue`,
  ).toContain(String(cluster));
});

// Why there are no page-rendering assertions in this file.
//
// The SPA resolves its session through GET /api/v1/auth/me, which is
// cookie-only by deliberate design -- it does not consult the user
// header or a bearer token. Under the header auth this harness uses it
// therefore answers authenticated=false, the app redirects to
// /login?return_to=..., and the e2e server (which has no OAuth2
// provider) returns
//
//   {"error":"Unauthorized","message":"Authentication required but no
//    OAuth2 provider configured","code":401}
//
// A browser test here lands on that document. Assertions as loose as
// "the body is visible" or "no page errors" pass against it, and so does
// any text match that happens to appear in it -- an earlier version of
// this file matched /error/ and reported the Jupyter detail page as
// covered while looking at that JSON.
//
// So: UI rendering is the smoke suite's job, where fixtures make it
// deterministic. This suite asserts the API contract and the paths that
// only a real schedd can exercise. Driving the real SPA here needs a
// browser session cookie, which means standing up the built-in IDP in
// the harness -- worth doing, not done.
