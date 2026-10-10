import type { Page } from '@playwright/test';
import type {
  AccessPointsResponse,
  AdminLogsResponse,
  DashboardActivityResponse,
  DashboardStats,
  IssuesResponse,
  JobListResponse,
  Session,
  ClassAd,
} from '../../src/lib/api';
import { utilizationFixture } from '../../src/lib/utilization.fixture';
import type { MetricsResponse } from '../../src/lib/metrics';

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

export const dashboardActivityFixture: DashboardActivityResponse = {
  activity: {
    hold_reasons: [
      { code: 13, label: 'Failed to transfer output', count: 2, example: 'smoke-transfer-error' },
      { code: 3, label: 'Policy expression (periodic_hold)', count: 1 },
    ],
    hold_window_seconds: 3600,
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
    since: Math.floor(Date.now() / 1000) - 24 * 3600,
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

export const dashboardFixture: DashboardStats = {
  username: 'e2e',
  // Named keys, not JobStatus numbers: the handler buckets by name
  // ("idle"/"running"/"held"...) and the tiles read those names. The
  // original fixture used '1'/'2' here, which types as Record<string,
  // number> just as happily and rendered every tile as 0.
  jobs_by_status: { idle: 1, running: 1, held: 3, completed: 1 },
  jobs_total: 6,
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

// The issues page's answer. Two sections with one cluster each, which is
// enough to prove the page binds: a fixture with no clusters renders the
// "nothing wrong" state, which would pass a render check while testing
// none of the row rendering.
export const issuesFixture: IssuesResponse = {
  window_seconds: 86400,
  computed_at: Math.floor(Date.now() / 1000),
  granularity: 0.5,
  include_ended: true,
  bucket_seconds: 3600,
  source: 'smoke fixture',
  sections: [
    {
      kind: 'hold',
      title: 'Holds',
      total: 12,
      users: 2,
      clusters: [
        {
          kind: 'hold',
          template: 'Error from <slot> memory usage exceeded request_memory',
          count: 12,
          users: 2,
          top_users: [{ owner: 'e2e', count: 10 }],
          facets: [
            { name: 'resource', distinct: 1, top: [{ value: 'SMOKE-CE1', count: 12 }] },
            { name: 'site', distinct: 2, top: [{ value: 'Smoke-Site', count: 8 }] },
          ],
          codes: [{ code: 21, subcode: 102, label: 'memory usage exceeded the request', count: 12 }],
          last_seen: Math.floor(Date.now() / 1000) - 300,
          timeline: [0, 0, 1, 3, 2, 0, 0, 0, 1, 4, 6, 2, 0, 0, 0, 0, 1, 1, 0, 0, 2, 3, 5, 1],
          examples: [
            {
              cluster_id: 12,
              proc_id: 0,
              owner: 'e2e',
              at: Math.floor(Date.now() / 1000) - 300,
              message: 'Error from slot1_4@smoke-host.example.edu: memory usage exceeded request_memory',
            },
            {
              cluster_id: 12,
              proc_id: 1,
              owner: 'e2e',
              at: Math.floor(Date.now() / 1000) - 600,
              message: 'Error from slot1_9@smoke-other.example.edu: memory usage exceeded request_memory',
            },
          ],
        },
      ],
    },
    {
      kind: 'run_failure',
      title: 'Jobs that could not keep running',
      total: 3,
      users: 1,
      clusters: [
        {
          kind: 'run_failure',
          template: 'Job disconnected too long JobLeaseDuration <num> seconds expired',
          count: 3,
          users: 1,
          examples: [
            {
              cluster_id: 13,
              proc_id: 0,
              owner: 'e2e',
              message: 'Job disconnected too long: JobLeaseDuration (2400 seconds) expired',
            },
          ],
        },
      ],
    },
  ],
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
// Multi-AP mode: one server in front of two access points, one of which
// is behind. The same cluster.proc exists on both, as it does in
// practice: cluster ids are per access point.
export const multiAPSources = {
  aps: 2,
  fresh: 1,
  degraded: [{ schedd: 'ap2.smoke.example', state: 'stale', staleness_seconds: 412 }],
};

export const multiAPJobsFixture: JobListResponse = {
  jobs: [
    {
      schedd: 'ap1.smoke.example',
      cluster: 12,
      proc: 0,
      job_id: '12.0@ap1.smoke.example',
      ClusterId: 12,
      ProcId: 0,
      JobStatus: 2,
      Owner: 'e2e',
      Cmd: '/bin/sleep',
      JobBatchName: 'smoke-ap1-batch',
      QDate: 1757000000,
    },
    {
      schedd: 'ap2.smoke.example',
      cluster: 12,
      proc: 0,
      job_id: '12.0@ap2.smoke.example',
      ClusterId: 12,
      ProcId: 0,
      JobStatus: 5,
      Owner: 'e2e',
      Cmd: '/bin/false',
      JobBatchName: 'smoke-ap2-batch',
      QDate: 1757000100,
    },
  ],
  total_returned: 2,
  has_more: false,
  sources: multiAPSources,
};

export const multiAPAccessPointsFixture: AccessPointsResponse = {
  constraint: 'regexp("smoke", Name)',
  aps: [
    { schedd: 'ap1.smoke.example', in_collector: true, hub: { state: 'fresh', staleness_seconds: 3 } },
    { schedd: 'ap2.smoke.example', in_collector: true, hub: { state: 'stale', staleness_seconds: 412 } },
  ],
  sources: multiAPSources,
  hub: { reachable: true },
};

export async function installApiFixtures(page: Page, opts: { multiAP?: boolean } = {}) {
  const table: Record<string, unknown> = {
    '/api/v1/whoami': { authenticated: true, user: 'e2e@test.htcondor.org' },
    '/api/v1/auth/me': sessionFixture,
    '/api/v1/jobs': jobsFixture,
    '/api/v1/issues': issuesFixture,
    '/api/v1/dashboard': dashboardFixture,
    '/api/v1/dashboard/activity': dashboardActivityFixture,
    // The archive is where every drill-down into finished work lands.
    '/api/v1/jobs/archive': {
      ads: [
        {
          ClusterId: 39,
          ProcId: 0,
          Owner: 'e2e',
          JobStatus: 4,
          ExitCode: 127,
          CompletionDate: Math.floor(Date.now() / 1000) - 600,
          JobBatchName: 'smoke-archived-batch',
        },
      ],
    },
    '/api/v1/admin/logs': adminLogsFixture,
    // Generated from simulated jobs, so its figures agree with each other
    // (see the fixture's header).
    '/api/v1/utilization': utilizationFixture,
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
    // The /interactive page's three lists. Empty is the interesting
    // default: it renders the launch forms, which is most of the page.
    '/api/v1/jupyter/instances': { instances: [] },
    '/api/v1/interactive/terminal': { terminals: [] },
    '/api/v1/apps': { apps: [] },
  };
  if (opts.multiAP) {
    table['/api/v1/auth/me'] = { ...sessionFixture, is_admin: false, multi_ap: true };
    table['/api/v1/jobs'] = multiAPJobsFixture;
    table['/api/v1/aps'] = multiAPAccessPointsFixture;
    table['/api/v1/jobs/archive'] = {
      ads: [
        {
          schedd: 'ap1.smoke.example',
          cluster: 39,
          proc: 0,
          job_id: '39.0@ap1.smoke.example',
          archived: true,
          ClusterId: 39,
          ProcId: 0,
          Owner: 'e2e',
          JobStatus: 4,
          ExitCode: 0,
          CompletionDate: Math.floor(Date.now() / 1000) - 600,
          JobBatchName: 'smoke-ap1-archived',
        },
      ],
      has_more: false,
      sources: multiAPSources,
    };
    table['/api/v1/chat/info'] = { enabled: false };
    // Everything else is what a multi-AP server answers for routes it
    // does not serve.
    delete table['/api/v1/dashboard'];
    delete table['/api/v1/dashboard/activity'];
  }

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

// --- The /jobs Progress, Held and Running views ---
//
// One queue with each case the views distinguish: a plain batch of which
// most jobs have finished and left the queue, a max_materialize factory
// with most of its jobs not yet queued, and a DAG whose count lives in its
// root DAGMan job. Hold reasons are real-shaped: the "Error from <slot>:"
// prefix is what the Held view strips.
const qdate = 1757000000;

function progressQueue(): ClassAd[] {
  const jobs: ClassAd[] = [];
  // sweep: 100 submitted, 12 still queued -- 88 done.
  [2, 2, 2, 2, 2, 1, 1, 1, 1, 5, 5, 5].forEach((status, i) =>
    jobs.push({
      ClusterId: 500, ProcId: i, JobStatus: status, Owner: 'e2e', QDate: qdate,
      Cmd: '/home/e2e/bin/train', JobBatchName: 'smoke-sweep', TotalSubmitProcs: 100,
      RequestMemory: 2048, RequestCpus: 1,
      ...(status === 5
        ? {
            HoldReasonCode: 34,
            HoldReason:
              i === 11
                ? 'Transfer input files failure at access point smoke-ap: reading from file /home/e2e/in.dat: (errno 2) No such file or directory'
                : `Error from slot1_${i}@glidein_${i}@node${i}.smoke.example.edu: memory usage exceeded request_memory`,
          }
        : {}),
    }),
  );
  // factory: 1000 total, procs 0..39 queued so far, 30..39 still here.
  for (let i = 30; i < 40; i++) {
    jobs.push({
      ClusterId: 510, ProcId: i, JobStatus: i < 36 ? 2 : 1, Owner: 'e2e', QDate: qdate + 10,
      Cmd: '/bin/sim', JobBatchName: 'smoke-factory', TotalSubmitProcs: 1000,
      JobMaterializeNextProcId: 40, RequestMemory: 4096, RequestCpus: 4,
    });
  }
  // A DAG: the root DAGMan job and two node jobs.
  jobs.push({
    ClusterId: 600, ProcId: 0, JobStatus: 2, Owner: 'e2e', QDate: qdate + 20,
    Cmd: '/usr/bin/condor_dagman', JobBatchName: 'smoke-pipeline.dag+600',
    DAG_NodesTotal: 40, DAG_NodesDone: 17, DAG_NodesFailed: 3, DAG_NodesQueued: 2,
    TotalSubmitProcs: 1,
  });
  for (let i = 0; i < 2; i++) {
    jobs.push({
      ClusterId: 601 + i, ProcId: 0, JobStatus: 2, Owner: 'e2e', QDate: qdate + 30,
      Cmd: '/bin/step', JobBatchName: 'smoke-pipeline.dag+600', DAGManJobId: 600,
      DAGNodeName: `step${i}`, TotalSubmitProcs: 1, RequestMemory: 1024, RequestCpus: 1,
    });
  }
  return jobs;
}

// What the running view's narrow query answers: memory and CPU per
// running job. 500.4 has not reported anything yet.
function usageOf(j: ClassAd): ClassAd {
  const u: ClassAd = {
    ClusterId: j.ClusterId, ProcId: j.ProcId, JobStatus: 2,
    RequestMemory: j.RequestMemory, RequestCpus: j.RequestCpus,
  };
  if (j.ClusterId === 500 && j.ProcId === 4) return u;
  const frac = j.ClusterId === 500 && j.ProcId === 2 ? 1.15 : 0.5;
  u.MemoryUsage = Math.round(Number(j.RequestMemory) * frac);
  u.CpusUsage = Number(j.RequestCpus) * 0.9;
  return u;
}

const recentCpuFixture: MetricsResponse = {
  enabled: true,
  table: 'job_metrics',
  columns: [
    { name: 'ClusterId', kind: 'group' },
    { name: 'ProcId', kind: 'group' },
    { name: 'avg_CpuUtil', kind: 'metric', func: 'avg', attr: 'CpuUtil' },
  ],
  rows: [['500', '0', '0.2']],
};

// installJobsProgressFixtures answers /api/v1/jobs the way the three
// queries the page makes need: the listing, the running view's usage
// query (asked for CpusUsage), and the exact count for a partial listing
// (a member(ClusterId, ...) constraint). Installed after
// installApiFixtures, whose routes it overrides.
//
// `partial` makes the listing a first page that leaves out two of the
// sweep's queued jobs, the case where counting what was listed would
// call them finished. `exactQueries` collects the constraints of the
// exact-count queries so a test can see they were made.
export async function installJobsProgressFixtures(
  page: Page,
  opts: { partial?: boolean; exactQueries?: string[] } = {},
) {
  const queue = progressQueue();
  await page.route('**/api/v1/jobs?**', async (route) => {
    const url = new URL(route.request().url());
    const projection = url.searchParams.get('projection') ?? '';
    const constraint = url.searchParams.get('constraint') ?? '';
    let body: JobListResponse;
    if (projection.includes('CpusUsage')) {
      body = { jobs: queue.filter((j) => j.JobStatus === 2).map(usageOf), has_more: false };
    } else if (constraint.startsWith('member(ClusterId')) {
      opts.exactQueries?.push(constraint);
      const ids = new Set((constraint.match(/\{([^}]*)\}/)?.[1] ?? '').split(',').map((x) => Number(x.trim())));
      body = { jobs: queue.filter((j) => ids.has(Number(j.ClusterId))), has_more: false };
    } else if (opts.partial) {
      const listed = queue.filter((j) => !(j.ClusterId === 500 && (j.ProcId === 7 || j.ProcId === 8)));
      body = {
        jobs: listed,
        total_returned: listed.length,
        has_more: true,
        pagination_unavailable: 'smoke: no cursor',
      };
    } else {
      body = { jobs: queue, total_returned: queue.length, has_more: false };
    }
    await route.fulfill({ json: body });
  });
  await page.route('**/api/v1/metrics/job_metrics?**', (route) =>
    route.fulfill({ json: recentCpuFixture }),
  );
}
