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

// Activity timestamps are relative to load time rather than frozen:
// the panels render "3m ago", and a fixed 2024 epoch would render
// "2y ago" on every row -- still a pass, but it stops looking like the
// thing being tested. Nothing asserts the formatted age, only that the
// rows bind.
const minutesAgo = (m: number) => Math.floor(Date.now() / 1000) - m * 60;

export const dashboardFixture: DashboardStats = {
  username: 'e2e',
  // Named keys, not JobStatus numbers: the handler buckets by name
  // ("idle"/"running"/"held"...) and the tiles read those names. The
  // original fixture used '1'/'2' here, which types as Record<string,
  // number> just as happily and rendered every tile as 0.
  jobs_by_status: { idle: 1, running: 1, held: 3, completed: 1 },
  jobs_total: 6,
  activity: {
    hold_reasons: [
      { code: 13, label: 'Failed to transfer output', count: 2, example: 'smoke-transfer-error' },
      { code: 3, label: 'Policy expression (periodic_hold)', count: 1 },
    ],
    recently_submitted: [{ cluster_id: 42, proc_id: 0, at: minutesAgo(2), detail: 'smoke-submitted' }],
    recently_started: [{ cluster_id: 41, proc_id: 3, at: minutesAgo(5), detail: 'smoke-exec-host' }],
    recently_held: [{ cluster_id: 40, proc_id: 1, at: minutesAgo(9), detail: 'smoke-transfer-error' }],
    recently_completed: [{ cluster_id: 39, proc_id: 0, at: minutesAgo(20), detail: 'smoke-completed' }],
    completed_available: true,
    completed_partial: false,
    source: 'smoke fixture',
    computed_at: minutesAgo(1),
  },
  goodput: {
    window_hours: 24,
    succeeded: 120,
    failed: 8,
    unfinished: 1,
    good_seconds: 90000,
    bad_seconds: 30000,
    top_failures: [
      { code: 127, signal: false, count: 6, seconds: 25000 },
      { code: 0, signal: true, count: 2, seconds: 5000 },
    ],
  },
};

// Two frames, in the wire format writeActivityEvent produces. Hand-built
// rather than typed like the JSON fixtures: the point here is the
// framing, which a typed object could not express.
function activityStreamFixture(): string {
  const at = Math.floor(Date.now() / 1000);
  const frame = (ev: Record<string, unknown>) => `event: activity\ndata: ${JSON.stringify(ev)}\n\n`;
  return (
    frame({ kind: 'started', cluster_id: 77, proc_id: 0, owner: 'e2e', at, detail: 'smoke-live-host' }) +
    frame({ kind: 'held', cluster_id: 76, proc_id: 1, owner: 'e2e', at: at - 5, detail: 'smoke-live-hold' })
  );
}

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
    // The dashboard's live ticker is an EventSource, so it needs a real
    // SSE response rather than JSON. Falling through to the 501 below
    // would be a truthful "this deployment has no mirror" -- but it also
    // logs a failed-resource console error, and the smoke suite fails on
    // those. Serving a short stream covers the wiring instead.
    if (path === '/api/v1/dashboard/activity/stream') {
      await route.fulfill({
        status: 200,
        headers: { 'content-type': 'text/event-stream', 'cache-control': 'no-cache' },
        body: activityStreamFixture(),
      });
      return;
    }
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
