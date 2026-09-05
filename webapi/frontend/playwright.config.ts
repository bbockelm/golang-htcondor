import { defineConfig, devices } from '@playwright/test';

// Two suites, deliberately different in what they trade away.
//
//   smoke  - the built static export with every /api/v1/* call answered
//            from a fixture. No daemon, no HTCondor, seconds to run. It
//            cannot catch API contract drift (the fixtures are frozen),
//            but it fails fast on the thing it does cover: whether the
//            pages render at all.
//
//   full   - the real htcondor-api binary against a real personal
//            HTCondor, driven through the same UI. Catches contract
//            drift and anything that only appears with live data, at
//            the cost of minutes and a heavier setup.
//
// PLAYWRIGHT_BASE_URL selects which the run targets; CI runs smoke
// first and only starts the container if it passes.
const baseURL = process.env.PLAYWRIGHT_BASE_URL ?? 'http://127.0.0.1:3100';
const suite = process.env.PLAYWRIGHT_SUITE ?? 'smoke';

export default defineConfig({
  testDir: './e2e',
  // A UI assertion that needs more than 10s is measuring the backend,
  // not the UI.
  timeout: 30_000,
  expect: { timeout: 10_000 },
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  workers: process.env.CI ? 2 : undefined,
  reporter: process.env.CI ? [['list'], ['html', { open: 'never' }]] : 'list',

  use: {
    baseURL,
    // Demo mode serves HTTPS with a CA it generates at startup, so the
    // browser has no way to trust it. The alternative -- plain HTTP --
    // is worse: the session cookie is set Secure, and dropping it would
    // leave every authenticated test failing for a reason unrelated to
    // what it tests.
    ignoreHTTPSErrors: true,
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    // No auth headers. The full suite logs in through the real OAuth
    // flow (see e2e/fixtures/login.ts); the smoke suite never reaches a
    // server. A header would not help either way: /api/v1/auth/me
    // resolves the browser session cookie only.
  },

  projects: [
    {
      name: suite,
      use: { ...devices['Desktop Chrome'] },
      testMatch: suite === 'full' ? /.*\.full\.spec\.ts/ : /.*\.smoke\.spec\.ts/,
    },
  ],
});
