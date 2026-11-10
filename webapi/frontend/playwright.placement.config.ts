import { defineConfig, devices } from '@playwright/test';

// Placement onboarding end to end: a real HTCondor with a condor_placementd,
// htcondor-api serving the embedded UI, its built-in IdP, and the HTCondor
// CLI using the tokens the browser and a device-flow client are given.
//
// Its own config, so neither of playwright.config.ts's suites picks the spec
// up: it needs a pool scripts/placement-e2e/harness.sh brought up, and its
// steps are one story that runs in order.
const baseURL = process.env.PLACEMENT_E2E_BASE_URL;
if (!baseURL) {
  throw new Error(
    'PLACEMENT_E2E_BASE_URL is not set; source the env file scripts/placement-e2e/harness.sh up writes.',
  );
}

export default defineConfig({
  testDir: './e2e/placement',
  testMatch: /.*\.placement\.spec\.ts/,
  // Two jobs go through the pool inside the one test; the steps that wait
  // on a job carry their own deadlines, well inside this.
  timeout: 360_000,
  expect: { timeout: 15_000 },
  forbidOnly: !!process.env.CI,
  // A retry would rerun onboarding against a pool the first attempt already
  // changed, and fail for that reason instead of the real one.
  retries: 0,
  workers: 1,
  reporter: process.env.CI ? [['list'], ['html', { open: 'never', outputFolder: 'playwright-report-placement' }]] : 'list',
  outputDir: 'test-results-placement',

  use: {
    baseURL,
    // The harness's CA is not one the browser knows.
    ignoreHTTPSErrors: true,
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    acceptDownloads: true,
  },

  projects: [
    {
      name: 'placement',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
});
