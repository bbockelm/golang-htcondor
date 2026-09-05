import type { Page } from '@playwright/test';
import type {
  AdminLogsResponse,
  DashboardStats,
  JobListResponse,
  Session,
} from '../../src/lib/api';

// Frozen sample responses for the smoke suite.
//
// Every fixture is annotated with the interface the app actually
// consumes, so a backend change that alters a response shape breaks
// `npm run typecheck` here instead of silently leaving this suite
// testing a shape nothing sends any more. The first draft of this file
// was hand-invented and immediately failed with
// "Cannot read properties of undefined (reading 'idle')" -- which is
// the failure mode the type annotations exist to prevent.
//
// This suite proves the pages render and bind data. Anything that
// depends on the live contract belongs in the full suite.

export const dashboardFixture: DashboardStats = {
  username: 'e2e',
  jobs_by_status: { '1': 1, '2': 1 },
  jobs_total: 2,
};

export const jobsFixture: JobListResponse = {
  jobs: [
    {
      ClusterId: 12,
      ProcId: 0,
      JobStatus: 2,
      Owner: 'e2e',
      Cmd: '/bin/sleep',
      JobBatchName: 'smoke-batch',
      QDate: 1757000000,
      RequestCpus: 1,
      RequestMemory: 1024,
    },
    {
      ClusterId: 12,
      ProcId: 1,
      JobStatus: 1,
      Owner: 'e2e',
      Cmd: '/bin/sleep',
      JobBatchName: 'smoke-batch',
      QDate: 1757000001,
      RequestCpus: 1,
      RequestMemory: 1024,
    },
  ],
  total_returned: 2,
  has_more: false,
};

export const sessionFixture: Session = {
  authenticated: true,
  username: 'e2e',
  groups: ['OSG-Staff'],
  is_admin: true,
};

// One long line carrying a full user_agent: this is the exact shape
// that collapsed the message column to one letter per line (#224), so
// the smoke suite should always carry one. LogEntry.fields is
// Record<string, string> -- values are pre-rendered by the server.
export const adminLogsFixture: AdminLogsResponse = {
  enabled: true,
  entries: [
    {
      time: '2026-09-05T12:31:16.748Z',
      level: 'INFO',
      destination: 'http',
      message: 'HTTP request',
      fields: {
        bytes: '6461',
        client_ip: '75.100.12.31',
        method: 'GET',
        path: '/',
        status: '200',
        duration_ms: '0',
        user_agent:
          'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36',
      },
    },
  ],
};

// The Jupyter detail page derives its whole view state from this one
// response plus a readiness probe. connected=true with a proxy_path is
// the "helper is up" branch -- the interesting one, because that is
// where JupyterDetailClient decides between launching and ready.
// installApiFixtures answers /api/v1/* from the table below and fails
// loudly on anything unmapped rather than returning an empty 200 -- a
// silent {} is how a fixture suite quietly stops testing the page it
// was written for.
export async function installApiFixtures(page: Page) {
  const table: Record<string, unknown> = {
    '/api/v1/whoami': { authenticated: true, user: 'e2e@test.htcondor.org' },
    '/api/v1/auth/me': sessionFixture,
    '/api/v1/jobs': jobsFixture,
    '/api/v1/dashboard': dashboardFixture,
    '/api/v1/admin/logs': adminLogsFixture,
    '/api/v1/version': {
      version: 'e2e',
      commit: 'e2e',
      start_time: '2026-01-02T15:04:05Z',
      uptime_seconds: 3661,
    },
    // enabled so the chat surface actually mounts: the jobs page hides
    // ChatPanel entirely on enabled=false, which would leave it untested.
    '/api/v1/chat/info': { enabled: true },
    '/api/v1/templates': { templates: [] },
  };

  await page.route('**/api/v1/**', async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path in table) {
      await route.fulfill({ json: table[path] as object });
      return;
    }
    await route.fulfill({
      status: 501,
      json: { error: `smoke suite has no fixture for ${path}` },
    });
  });
}
