import { expect, test } from '@playwright/test';

import { adminPassword, loginAsAdmin } from './fixtures/login';
import { serverLog } from './fixtures/serverlog';

// Share URLs must be built from how the caller reached us, never from
// the server's own hostname.
//
// This shipped broken: inside a container FULL_HOSTNAME is the pod name,
// and a share link came out as
//
//   http://htcondor-api-6f9c86677f-sg8cj:8080/api/v1/share/output?t=...
//
// which nobody outside the cluster can open. #269 stopped the guessing;
// nothing guarded it. The bug class -- a server inventing its own public
// identity -- is invisible in dev, where the hostname and the public URL
// happen to be the same string.
//
// Demo mode leaves HTTP_API_BASE_URL unset, so these exercise the
// request-derived branch, which is the one that broke.

const password = adminPassword(
  serverLog(),
);

test.beforeEach(async ({ page }) => {
  await loginAsAdmin(page, password);
});

async function submitJob(page: import('@playwright/test').Page): Promise<string> {
  const res = await page.request.post('/api/v1/jobs', {
    data: {
      submit_file: ['executable = /bin/sleep', 'arguments = 60', 'queue 1'].join('\n'),
    },
  });
  expect(res.status(), `submit failed: ${await res.text()}`).toBeLessThan(400);
  const body = await res.json();
  const cluster = body.cluster_id ?? body.ClusterId ?? body.cluster;
  expect(cluster, 'submit response should name the new cluster').toBeTruthy();
  return `${cluster}.0`;
}

test('a share URL uses the host the caller reached us at', async ({ page, baseURL }) => {
  const jobID = await submitJob(page);

  const res = await page.request.post(`/api/v1/jobs/${jobID}/output/share`, { data: {} });
  // A 404 here means the ownership check rejected us, not that the URL
  // is wrong -- surface the body so the two are distinguishable.
  expect(res.status(), `share mint failed: ${await res.text()}`).toBe(200);

  const { url } = await res.json();
  const parsed = new URL(url);

  // Compared against the base URL the run actually used, not a literal:
  // the harness picks a free port per run so two of them can share a
  // host, and a hardcoded one turns this into a test of the harness.
  expect(baseURL, 'the suite needs a base URL to compare against').toBeTruthy();
  expect(parsed.host, `share URL should use the request host, got ${url}`).toBe(
    new URL(baseURL!).host,
  );
  expect(parsed.protocol).toBe('https:');
  expect(parsed.pathname).toBe('/api/v1/share/output');
  expect(parsed.searchParams.get('t'), 'share URL should carry a token').toBeTruthy();
});

test('a share URL honours X-Forwarded-Host', async ({ page }) => {
  const jobID = await submitJob(page);

  // Behind a proxy the request Host is the internal name; the public one
  // arrives in the header. Asserting on a host that is neither the
  // container's own name nor the listen address is what makes this test
  // able to fail: if the server went back to using its own identity,
  // this could not accidentally still pass.
  const res = await page.request.post(`/api/v1/jobs/${jobID}/output/share`, {
    data: {},
    headers: { 'X-Forwarded-Host': 'ap40-api.example.test' },
  });
  expect(res.status(), `share mint failed: ${await res.text()}`).toBe(200);

  const { url } = await res.json();
  expect(new URL(url).host).toBe('ap40-api.example.test');
});
