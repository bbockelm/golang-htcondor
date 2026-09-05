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
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    // The full suite authenticates with the header the server is
    // configured to trust (HTTP_API_USER_HEADER). The smoke suite never
    // reaches a server, so it is harmless there.
    extraHTTPHeaders:
      suite === 'full' ? { 'X-Test-User': process.env.E2E_USER ?? 'e2e@test.htcondor.org' } : {},
  },

  projects: [
    {
      name: suite,
      use: { ...devices['Desktop Chrome'] },
      testMatch: suite === 'full' ? /.*\.full\.spec\.ts/ : /.*\.smoke\.spec\.ts/,
    },
  ],
});
