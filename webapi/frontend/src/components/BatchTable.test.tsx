import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { JobRuntimeEstimate, RuntimeEstimates } from '@/lib/api';

// Every table asks for its jobs' runtime estimates; by default the server
// has none to give, which leaves the Time left column out.
const runtimeEstimates = vi.fn();
vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api');
  return {
    ...actual,
    api: {
      ...actual.api,
      jobs: { ...actual.api.jobs, runtimeEstimates: (...a: unknown[]) => runtimeEstimates(...a) },
    },
  };
});
beforeEach(() => {
  runtimeEstimates.mockReset();
  runtimeEstimates.mockResolvedValue({ available: false, reason: 'disabled' } satisfies RuntimeEstimates);
});

import { BatchTable } from './BatchTable';
import { groupIntoBatches } from '@/lib/batches';
import { batchView } from '@/lib/batchView';
import { PROGRESS_WHY } from '@/lib/batchProgress';
import type { JobUsage } from '@/lib/runningUsage';
import type { ClassAd, DisplayStatus } from '@/lib/api';

vi.mock('next/navigation', () => ({
  useRouter: () => ({ push: vi.fn() }),
}));

const ads: ClassAd[] = [
  {
    ClusterId: 10, ProcId: 0, JobStatus: 2, Owner: 'alice',
    Cmd: '/bin/train', QDate: 1000, JobBatchName: 'training',
  },
  {
    ClusterId: 11, ProcId: 0, JobStatus: 1, Owner: 'bob',
    Cmd: '/bin/sim', QDate: 3000, JobBatchName: 'sim',
  },
  {
    ClusterId: 11, ProcId: 1, JobStatus: 1, Owner: 'bob',
    Cmd: '/bin/sim', QDate: 3000, JobBatchName: 'sim',
  },
];

function table(props: Partial<Parameters<typeof BatchTable>[0]> = {}) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <BatchTable
        batches={groupIntoBatches(ads)}
        expanded={new Set()}
        setExpanded={vi.fn()}
        highlighted={null}
        onChange={vi.fn()}
        {...props}
      />
    </QueryClientProvider>,
  );
}

// The rendered batch rows, in the order the table put them.
function batchNames(): string[] {
  return screen
    .getAllByRole('row')
    // Skip the header and the "showing N of M" footer, neither of which
    // has a batch name.
    .filter((r) => r.getAttribute('aria-expanded') !== null)
    .map((r) => within(r).getAllByRole('cell')[1].textContent ?? '');
}

describe('BatchTable', () => {
  it('leaves the user column out when every row is the same user', () => {
    table();
    expect(screen.queryByRole('button', { name: /User/ })).toBeNull();
    expect(screen.queryByRole('link', { name: 'alice' })).toBeNull();
  });

  it('links each user to their own page when showing several', () => {
    table({ showOwner: true });
    expect(screen.getByRole('link', { name: 'alice' })).toHaveAttribute(
      'href',
      '/users/alice',
    );
  });

  it('opens the user page instead of expanding the row', () => {
    const setExpanded = vi.fn();
    table({ showOwner: true, setExpanded });
    // The pill sits inside a row whose click handler expands the batch;
    // both firing would expand a batch on the way to another page.
    fireEvent.click(screen.getByRole('link', { name: 'alice' }));
    expect(setExpanded).not.toHaveBeenCalled();
  });

  it('starts newest-first and re-sorts when a column is clicked', () => {
    table();
    // QDate 3000 beats 1000.
    expect(batchNames()[0]).toContain('sim');

    fireEvent.click(screen.getByRole('button', { name: /Jobs/ }));
    // Ascending job count: the one-job batch leads.
    expect(batchNames()[0]).toContain('training');

    fireEvent.click(screen.getByRole('button', { name: /Jobs/ }));
    // Clicking the same column again reverses it.
    expect(batchNames()[0]).toContain('sim');
  });
});

describe('BatchTable in multi-AP mode', () => {
  const multi: ClassAd[] = [
    { ClusterId: 1, ProcId: 0, JobStatus: 5, Owner: 'alice', schedd: 'ap1.example.org', job_id: '1.0@ap1.example.org' },
    { ClusterId: 1, ProcId: 0, JobStatus: 5, Owner: 'alice', schedd: 'ap2.example.org', job_id: '1.0@ap2.example.org' },
  ];

  it('shows the access point and offers nothing that acts on a job', () => {
    table({ batches: groupIntoBatches(multi), multiAP: true });
    expect(screen.getByRole('button', { name: /Access point/ })).toBeTruthy();
    expect(screen.getByText('ap1.example.org')).toBeTruthy();
    expect(screen.getByText('ap2.example.org')).toBeTruthy();
    expect(screen.queryByTitle(/Remove batch/)).toBeNull();
    expect(screen.queryByText('Remove')).toBeNull();
  });

  it('opens a batch\'s utilization on its own access point', () => {
    table({ batches: groupIntoBatches(multi), multiAP: true });
    fireEvent.click(screen.getAllByRole('button', { name: /More actions for batch/ })[0]);
    const href = screen.getByRole('menuitem', { name: 'Resource utilization' }).getAttribute('href')!;
    expect(new URL(href, 'http://x').searchParams.get('schedd')).toMatch(/^ap[12]\.example\.org$/);
  });

  it('links each job by its complete id', () => {
    table({
      batches: groupIntoBatches(multi),
      multiAP: true,
      expanded: new Set(groupIntoBatches(multi).map((b) => `${b.schedd}\u0000${b.batchID}`)),
    });
    const link = screen.getByRole('link', { name: '1.0@ap2.example.org' });
    expect(link.getAttribute('href')).toBe('/jobs/1.0%40ap2.example.org');
    // Held jobs: the single-AP table would offer Release.
    expect(screen.queryByText('Release')).toBeNull();
  });
});

describe('BatchTable batch page links', () => {
  const dag: ClassAd[] = [
    { ClusterId: 100, ProcId: 0, JobStatus: 2, Owner: 'carol', Cmd: 'condor_dagman', JobBatchName: 'foo.dag+100' },
    { ClusterId: 104, ProcId: 0, JobStatus: 2, Owner: 'carol', JobBatchName: 'foo.dag+100', DAGManJobId: 100 },
  ];

  it('links the batch name to its page, by the batch id', () => {
    table();
    expect(screen.getByRole('link', { name: 'training' })).toHaveAttribute('href', '/batches/10');
    expect(screen.getByRole('link', { name: 'sim' })).toHaveAttribute('href', '/batches/11');
  });

  it('links a DAG by its root DAGMan cluster', () => {
    table({ batches: groupIntoBatches(dag) });
    expect(screen.getByRole('link', { name: 'foo.dag' })).toHaveAttribute('href', '/batches/100');
  });

  it('follows the name without opening the row; the rest of the row still opens it', () => {
    const setExpanded = vi.fn();
    table({ setExpanded });
    fireEvent.click(screen.getByRole('link', { name: 'sim' }));
    expect(setExpanded).not.toHaveBeenCalled();
    fireEvent.click(screen.getByText('/bin/sim'));
    expect(setExpanded).toHaveBeenCalledTimes(1);
  });

  it('offers the batch page first in the actions menu', () => {
    table();
    fireEvent.click(screen.getByRole('button', { name: 'More actions for batch training' }));
    const items = screen.getAllByRole('menuitem');
    expect(items.map((i) => i.textContent)).toEqual(['Open batch page', 'Resource utilization']);
    expect(items[0]).toHaveAttribute('href', '/batches/10');
  });

  it('has no batch page in multi-AP mode', () => {
    const multi: ClassAd[] = [
      { ClusterId: 1, ProcId: 0, JobStatus: 5, Owner: 'alice', schedd: 'ap1.example.org', job_id: '1.0@ap1.example.org' },
    ];
    table({ batches: groupIntoBatches(multi), multiAP: true });
    expect(screen.queryByRole('link', { name: '1' })).toBeNull();
    expect(document.querySelector('a[href^="/batches/"]')).toBeNull();
    fireEvent.click(screen.getByRole('button', { name: /More actions for batch/ }));
    expect(screen.queryByRole('menuitem', { name: 'Open batch page' })).toBeNull();
    expect(screen.getByRole('menuitem', { name: 'Resource utilization' })).toBeTruthy();
  });
});

describe('BatchTable progress', () => {
  const queue: ClassAd[] = [
    // 10 submitted, 3 finished: 5 running, 2 held left.
    ...[2, 2, 2, 2, 2, 5, 5].map((s, i) => ({
      ClusterId: 20, ProcId: i, JobStatus: s, Owner: 'alice', QDate: 100,
      JobBatchName: 'sweep', TotalSubmitProcs: 10,
    })),
    // 4 submitted, 3 finished.
    { ClusterId: 21, ProcId: 0, JobStatus: 1, Owner: 'alice', QDate: 200, JobBatchName: 'quick', TotalSubmitProcs: 4 },
  ];

  it('shows how many jobs are done, from every job rather than the filtered ones', () => {
    const view = batchView(queue, new Set<DisplayStatus>(['held']), '', true);
    table({ batches: view.batches, progress: view.progress });
    expect(screen.getByRole('button', { name: /Progress/ })).toBeTruthy();
    const cell = screen.getByText('3 / 10');
    expect(cell.closest('[title]')?.getAttribute('title')).toMatch(/^3 of 10 jobs done/);
  });

  it('sorts by the share done', () => {
    const view = batchView(queue, new Set(), '', true);
    table({ batches: view.batches, progress: view.progress });
    fireEvent.click(screen.getByRole('button', { name: /Progress/ }));
    // 3/10 before 3/4 ascending.
    expect(batchNames()[0]).toContain('sweep');
    fireEvent.click(screen.getByRole('button', { name: /Progress/ }));
    expect(batchNames()[0]).toContain('quick');
  });

  it('shows a dash, with the reason, when the count is unknown', () => {
    const view = batchView(queue, new Set(), '', false);
    table({ batches: view.batches, progress: view.progress });
    const dashes = screen.getAllByTitle(PROGRESS_WHY.partial);
    expect(dashes).toHaveLength(2);
  });

  it('leaves the column out when not given progress', () => {
    table();
    expect(screen.queryByRole('button', { name: /Progress/ })).toBeNull();
  });
});

describe('BatchTable held view', () => {
  const held: ClassAd[] = [
    { ClusterId: 30, ProcId: 0, JobStatus: 5, Owner: 'alice', Cmd: '/bin/a', HoldReason: 'Job exceeded 2048 MB on node-1' },
    { ClusterId: 30, ProcId: 1, JobStatus: 5, Owner: 'alice', Cmd: '/bin/a', HoldReason: 'Job exceeded 2048 MB on node-7' },
    { ClusterId: 30, ProcId: 2, JobStatus: 5, Owner: 'alice', Cmd: '/bin/a', HoldReason: 'Transfer of /home/alice/x failed' },
    { ClusterId: 31, ProcId: 0, JobStatus: 5, Owner: 'alice', Cmd: '/bin/b', HoldReason: 'Another reason' },
  ];

  it('shows the hold reason instead of the command', () => {
    table({ batches: groupIntoBatches(held), detail: 'hold' });
    expect(screen.getByRole('button', { name: /Hold reason/ })).toBeTruthy();
    expect(screen.queryByRole('button', { name: /Command/ })).toBeNull();
    expect(screen.queryByText('/bin/a')).toBeNull();
    // The most common kind, as a real message, with its count and the
    // number of other kinds.
    expect(screen.getByText('Job exceeded 2048 MB on node-1')).toBeTruthy();
    expect(screen.getByText('×2')).toBeTruthy();
    expect(screen.getByText('+1 other reason')).toBeTruthy();
  });

  it('shows each job\'s own reason in the expanded jobs', () => {
    const batches = groupIntoBatches(held);
    table({ batches, detail: 'hold', expanded: new Set(batches.map((b) => b.batchID)) });
    // The batch table's header, plus one in each expanded jobs table.
    expect(screen.getAllByRole('columnheader', { name: /Hold reason/ })).toHaveLength(3);
    expect(screen.getByText('Transfer of /home/alice/x failed')).toBeTruthy();
    expect(screen.getAllByText('Job exceeded 2048 MB on node-7')).toHaveLength(1);
  });

  it('shows the problem first and the whole message on hover', () => {
    const fromNode: ClassAd[] = [
      {
        ClusterId: 32, ProcId: 0, JobStatus: 5, Owner: 'alice',
        HoldReason: 'Error from slot1_27@glidein_18169@node9.anvil.rcac.purdue.edu: memory usage exceeded request_memory',
      },
    ];
    const batches = groupIntoBatches(fromNode);
    table({ batches, detail: 'hold', expanded: new Set(batches.map((b) => b.batchID)) });
    const cells = screen.getAllByText('memory usage exceeded request_memory');
    // The batch row and the job row.
    expect(cells).toHaveLength(2);
    for (const c of cells) {
      expect(c.getAttribute('title')).toMatch(/^Error from slot1_27@glidein_18169@node9/);
    }
  });

  it('sorts by the reason shown', () => {
    table({ batches: groupIntoBatches(held), detail: 'hold' });
    fireEvent.click(screen.getByRole('button', { name: /Hold reason/ }));
    // "Another reason" < "Job exceeded…"
    expect(batchNames()[0]).toContain('31');
  });
});

describe('BatchTable running view', () => {
  const running: ClassAd[] = [
    { ClusterId: 40, ProcId: 0, JobStatus: 2, Owner: 'alice', Cmd: '/bin/a' },
    { ClusterId: 40, ProcId: 1, JobStatus: 2, Owner: 'alice', Cmd: '/bin/a' },
  ];
  const byJob = new Map<string, JobUsage>([
    ['40.0', { memUsedMiB: 2400, memReqMiB: 2048, cpuUsed: 0.9, cpuReq: 1, cpuSource: 'recent' }],
  ]);

  it('replaces the command with memory and CPU bars', () => {
    const batches = groupIntoBatches(running);
    table({
      batches,
      detail: 'usage',
      usage: { byJob, loading: false },
      expanded: new Set(batches.map((b) => b.batchID)),
    });
    expect(screen.getByRole('button', { name: /Memory \(peak\)/ })).toBeTruthy();
    expect(screen.getByRole('button', { name: /CPU \(recent\)/ })).toBeTruthy();
    expect(screen.queryByText('/bin/a')).toBeNull();
    // Submitted makes room for the second bar.
    expect(screen.queryByRole('button', { name: /Submitted/ })).toBeNull();
    // The job over its request is flagged, with the percentage in words.
    expect(screen.getByText('2.3 / 2.0 GB · 117%').closest('[data-tone]')?.getAttribute('data-tone')).toBe('critical');
    // The job with nothing measured says so rather than showing zero.
    expect(screen.getAllByText('not reported yet').length).toBeGreaterThanOrEqual(2);
  });
});

describe('BatchTable running and waiting times', () => {
  // The table reads the clock, so it is fixed: only Date, so the
  // rendering's own timers still run.
  const now = 1_791_997_200;
  beforeEach(() => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(now * 1000);
  });
  afterEach(() => vi.useRealTimers());
  const timed: ClassAd[] = [
    { ClusterId: 50, ProcId: 0, JobStatus: 2, Owner: 'alice', JobCurrentStartExecutingDate: now - (2 * 3600 + 14 * 60) },
    { ClusterId: 50, ProcId: 1, JobStatus: 2, Owner: 'alice', JobCurrentStartExecutingDate: now - 5 * 3600 },
    { ClusterId: 50, ProcId: 2, JobStatus: 1, Owner: 'alice', QDate: now - 3 * 86400, EnteredCurrentStatus: now - (3 * 86400 + 2 * 3600) },
  ];

  it('shows how long each job has been running or waiting, and the batch\'s longest run', () => {
    const batches = groupIntoBatches(timed);
    table({ batches, expanded: new Set(batches.map((b) => b.batchID)) });
    expect(screen.getByText('longest running 5h')).toBeTruthy();
    expect(screen.getByTitle('Running for 2h14m')).toBeTruthy();
    expect(screen.getByTitle('Running for 5h')).toBeTruthy();
    expect(screen.getByTitle('Waiting for 3d2h')).toBeTruthy();
  });
});

describe('BatchTable row actions menu', () => {
  const dag: ClassAd[] = [
    { ClusterId: 100, ProcId: 0, JobStatus: 2, Owner: 'carol', Cmd: 'condor_dagman', JobBatchName: 'foo.dag+100' },
    { ClusterId: 101, ProcId: 0, JobStatus: 2, Owner: 'carol', JobBatchName: 'foo.dag+100', DAGManJobId: 100 },
  ];

  function utilizationOf(name: RegExp) {
    fireEvent.click(screen.getByRole('button', { name }));
    const href = screen.getByRole('menuitem', { name: 'Resource utilization' }).getAttribute('href')!;
    const url = new URL(href, 'http://x');
    return { path: url.pathname, days: url.searchParams.get('days'), constraint: url.searchParams.get('constraint') };
  }

  it('opens a named batch\'s utilization narrowed to that batch', () => {
    table();
    expect(utilizationOf(/More actions for batch training/)).toEqual({
      path: '/utilization',
      days: '30',
      constraint: 'JobBatchName == "training" && Owner == "alice"',
    });
    // Remove is still right there.
    expect(screen.getAllByTitle(/Remove batch/)).toHaveLength(2);
  });

  it('narrows a DAG by its batch name alone', () => {
    table({ batches: groupIntoBatches(dag) });
    expect(utilizationOf(/More actions for batch foo\.dag/).constraint).toBe('JobBatchName == "foo.dag+100"');
  });

  it('works from the keyboard', () => {
    table();
    const button = screen.getByRole('button', { name: /More actions for batch sim/ });
    fireEvent.keyDown(button, { key: 'ArrowDown' });
    const item = screen.getByRole('menuitem', { name: 'Open batch page' });
    expect(document.activeElement).toBe(item);
    fireEvent.keyDown(item, { key: 'Escape' });
    expect(screen.queryByRole('menu')).toBeNull();
    expect(document.activeElement).toBe(button);
  });
});

describe('BatchTable time left', () => {
  function estimate(over: Partial<JobRuntimeEstimate> = {}): JobRuntimeEstimate {
    return {
      available: true,
      estimate_seconds: 3600,
      p10_seconds: 2400,
      p90_seconds: 9000,
      basis: { level: 'template', sample_count: 12 },
      rough: false,
      exceeded_history: false,
      ...over,
    };
  }
  const answer = (estimates: Record<string, JobRuntimeEstimate>): RuntimeEstimates => ({
    available: true,
    estimates,
    model: { jobs_ingested: 100 },
  });

  it('asks once for the waiting and running jobs and shows each batch\'s time left', async () => {
    runtimeEstimates.mockResolvedValue(
      answer({
        '10.0': estimate({ elapsed_seconds: 600, remaining_seconds: 1800, estimate_seconds: 2400 }),
        '11.0': estimate(),
        '11.1': estimate(),
      }),
    );
    table();
    await screen.findByText('Time left');
    expect(runtimeEstimates).toHaveBeenCalledTimes(1);
    // Running jobs first: a batch's finish needs every one of them.
    expect(runtimeEstimates).toHaveBeenCalledWith(['10.0', '11.0', '11.1']);
    const cells = screen.getAllByTestId('batch-time-left').map((c) => c.textContent);
    expect(cells).toContain('2 waiting · each about 1h once started');
    expect(cells.some((t) => /^All done by ~/.test(t ?? ''))).toBe(true);
    expect(screen.queryByTestId('longer-than-usual')).toBeNull();
  });

  it('flags a batch whose job is running longer than usual', async () => {
    runtimeEstimates.mockResolvedValue(
      answer({ '10.0': estimate({ elapsed_seconds: 20000, exceeded_history: true }) }),
    );
    table();
    expect(await screen.findByText('Running longer than usual')).toBeInTheDocument();
    expect(screen.getByText('Past its usual 1h')).toBeInTheDocument();
  });

  it('gives each expanded job its own time left', async () => {
    runtimeEstimates.mockResolvedValue(
      answer({
        '10.0': estimate({ elapsed_seconds: 600, remaining_seconds: 1800, estimate_seconds: 2400 }),
        '11.0': estimate({ rough: true, estimate_seconds: 7200, basis: { level: 'owner', sample_count: 9 } }),
      }),
    );
    const batches = groupIntoBatches(ads);
    table({ batches, expanded: new Set(batches.map((b) => b.batchID)) });
    // The batch table's column and each expanded job table's.
    expect(await screen.findAllByText('Time left')).toHaveLength(3);
    const jobs = screen.getAllByTestId('job-time-left').map((c) => c.textContent ?? '');
    expect(jobs.some((t) => /^~30mdone ~/.test(t))).toBe(true); // main, then the finish on its own line
    expect(jobs).toContain('Runs roughly 2h once startedrough guess');
    // 11.1 was asked about and has no figure.
    expect(jobs).toContain('—');
  });

  it('leaves the column out when the server has no estimates', async () => {
    table();
    await waitFor(() => expect(runtimeEstimates).toHaveBeenCalled());
    expect(screen.queryByText('Time left')).toBeNull();
  });

  it('describes a DAG by its nodes, never asks about its DAGMan job, and gives no finish time for it', async () => {
    const dagAds: ClassAd[] = [
      {
        ClusterId: 100, ProcId: 0, JobStatus: 2, Owner: 'carol', Cmd: 'condor_dagman', QDate: 500,
        JobBatchName: 'foo.dag+100', DAG_NodesTotal: 20, DAG_NodesDone: 11, DAG_NodesFailed: 2, DAG_NodesQueued: 3,
      },
      { ClusterId: 201, ProcId: 0, JobStatus: 2, Owner: 'carol', Cmd: '/bin/node', QDate: 600, JobBatchName: 'foo.dag+100', DAGManJobId: 100 },
      { ClusterId: 202, ProcId: 0, JobStatus: 2, Owner: 'carol', Cmd: '/bin/node', QDate: 600, JobBatchName: 'foo.dag+100', DAGManJobId: 100 },
      { ClusterId: 203, ProcId: 0, JobStatus: 1, Owner: 'carol', Cmd: '/bin/node', QDate: 600, JobBatchName: 'foo.dag+100', DAGManJobId: 100 },
    ];
    runtimeEstimates.mockResolvedValue(
      answer({
        '201.0': estimate({ elapsed_seconds: 600, remaining_seconds: 1800, estimate_seconds: 2400 }),
        '202.0': estimate({ elapsed_seconds: 20000, exceeded_history: true }),
        '203.0': estimate(),
      }),
    );
    const batches = groupIntoBatches(dagAds);
    table({ batches, expanded: new Set(batches.map((b) => b.batchID)) });
    await screen.findAllByText('Time left');
    expect(runtimeEstimates).toHaveBeenCalledWith(['201.0', '202.0', '203.0']);
    const cell = screen.getByTestId('batch-time-left');
    expect(cell.textContent).toMatch(/^7 of 20 nodes left1 of 2 running nodes done by ~.+1 waiting · each about 1h once started$/);
    expect(cell.getAttribute('title')).not.toMatch(/All done|most by/);
    expect(screen.getByText('1 running longer than usual')).toBeInTheDocument();
    // The DAGMan job gets no time-left cell of its own; each node job does.
    expect(screen.getAllByTestId('job-time-left')).toHaveLength(3);
  });

  it('does not ask in multi-AP mode or for held jobs', () => {
    table({ multiAP: true });
    table({ detail: 'hold' });
    expect(runtimeEstimates).not.toHaveBeenCalled();
  });
});

// Below 1024px the table is cards. jsdom has no matchMedia: give it one
// that says the screen is narrow.
describe('BatchTable as cards', () => {
  beforeEach(() => {
    vi.stubGlobal('matchMedia', (q: string) => ({
      matches: q.includes('max-width'),
      media: q,
      addEventListener: () => {},
      removeEventListener: () => {},
    }));
  });
  afterEach(() => vi.unstubAllGlobals());

  const held: ClassAd[] = [
    {
      ClusterId: 30, ProcId: 0, JobStatus: 5, Owner: 'alice', Cmd: '/bin/a', JobBatchName: 'sweep', TotalSubmitProcs: 10,
      HoldReason: 'Error from slot1_3@node3.example.edu: memory usage exceeded request_memory',
    },
    {
      ClusterId: 30, ProcId: 1, JobStatus: 5, Owner: 'alice', Cmd: '/bin/a', JobBatchName: 'sweep', TotalSubmitProcs: 10,
      HoldReason: 'Error from slot1_9@node9.example.edu: memory usage exceeded request_memory',
    },
  ];

  it('lists batches as cards with a sort picker, not a table', () => {
    const view = batchView(ads, new Set(), '', true);
    table({ batches: view.batches, progress: view.progress, showOwner: true });
    expect(screen.queryByRole('table')).toBeNull();
    const cards = screen.getAllByTestId('batch-card');
    expect(cards).toHaveLength(2);
    // Newest first, as the table starts.
    expect(cards[0]).toHaveTextContent('sim');
    expect(within(cards[0]).getByRole('link', { name: 'bob' })).toHaveAttribute('href', '/users/bob');
    expect(cards[0]).toHaveTextContent('/bin/sim');
    // The picker re-sorts: by name, descending.
    fireEvent.change(screen.getByRole('combobox', { name: /Sort by/ }), { target: { value: 'batch' } });
    expect(screen.getAllByTestId('batch-card')[0]).toHaveTextContent('training');
    fireEvent.click(screen.getByRole('button', { name: /switch to ascending/ }));
    expect(screen.getAllByTestId('batch-card')[0]).toHaveTextContent('sim');
  });

  it('keeps Remove and the actions menu on every card', () => {
    table();
    const card = screen.getAllByTestId('batch-card').find((c) => c.textContent?.includes('training'))!;
    expect(within(card).getByTitle(/Remove batch training/)).toBeTruthy();
    fireEvent.click(within(card).getByRole('button', { name: 'More actions for batch training' }));
    expect(within(card).getByRole('menuitem', { name: 'Resource utilization' }).getAttribute('href')).toMatch(
      /^\/utilization\?days=30&constraint=/,
    );
  });

  it('opens when tapped anywhere but a control', () => {
    const setExpanded = vi.fn();
    table({ setExpanded });
    const card = screen.getAllByTestId('batch-card')[0];
    fireEvent.click(within(card).getByText('/bin/sim'));
    expect(setExpanded).toHaveBeenCalledTimes(1);
    // A control does its own job and does not also open the card.
    fireEvent.click(within(card).getByTitle(/Remove batch/));
    fireEvent.click(within(card).getByRole('button', { name: /More actions for batch/ }));
    expect(setExpanded).toHaveBeenCalledTimes(1);
  });

  it('links the name to the batch page, and the caret still opens the card', () => {
    const setExpanded = vi.fn();
    table({ setExpanded });
    const card = screen.getAllByTestId('batch-card').find((c) => c.textContent?.includes('training'))!;
    const link = within(card).getByRole('link', { name: 'training' });
    expect(link).toHaveAttribute('href', '/batches/10');
    fireEvent.click(link);
    expect(setExpanded).not.toHaveBeenCalled();
    fireEvent.click(within(card).getByRole('button', { name: 'Jobs in batch training' }));
    expect(setExpanded).toHaveBeenCalledTimes(1);
    fireEvent.click(within(card).getByRole('button', { name: 'More actions for batch training' }));
    expect(within(card).getByRole('menuitem', { name: 'Open batch page' })).toHaveAttribute('href', '/batches/10');
  });

  it('shows the hold reason in the held view, and its jobs with Release when open', () => {
    const batches = groupIntoBatches(held);
    table({ batches, detail: 'hold', expanded: new Set(batches.map((b) => b.batchID)) });
    const card = screen.getByTestId('batch-card');
    expect(within(card).getAllByText('memory usage exceeded request_memory')[0]).toBeTruthy();
    expect(card).toHaveTextContent('×2');
    const jobs = within(card).getAllByTestId('job-card');
    expect(jobs).toHaveLength(2);
    expect(within(jobs[0]).getByRole('button', { name: 'Release' })).toBeTruthy();
    expect(within(jobs[0]).getByTitle('Remove job 30.0')).toBeTruthy();
  });

  it('shows memory and CPU bars in the running view', () => {
    const running: ClassAd[] = [{ ClusterId: 40, ProcId: 0, JobStatus: 2, Owner: 'alice', Cmd: '/bin/a' }];
    const batches = groupIntoBatches(running);
    const byJob = new Map<string, JobUsage>([
      ['40.0', { memUsedMiB: 2400, memReqMiB: 2048, cpuUsed: 0.9, cpuReq: 1, cpuSource: 'recent' }],
    ]);
    table({ batches, detail: 'usage', usage: { byJob, loading: false }, expanded: new Set([40]) });
    const card = screen.getByTestId('batch-card');
    expect(within(card).getAllByText('Memory (peak)').length).toBeGreaterThan(0);
    expect(within(card).getAllByText('CPU (recent)').length).toBeGreaterThan(0);
    // The job's own bars, inside the open card.
    expect(within(within(card).getByTestId('job-card')).getByText('2.3 / 2.0 GB · 117%')).toBeTruthy();
  });

  it('offers nothing that acts on a job in multi-AP mode, but keeps the menu', () => {
    const multi: ClassAd[] = [
      { ClusterId: 1, ProcId: 0, JobStatus: 5, Owner: 'alice', schedd: 'ap1.example.org', job_id: '1.0@ap1.example.org' },
    ];
    const batches = groupIntoBatches(multi);
    table({ batches, multiAP: true, expanded: new Set(batches.map((b) => `${b.schedd}\u0000${b.batchID}`)) });
    expect(screen.queryByTitle(/Remove/)).toBeNull();
    expect(screen.queryByText('Release')).toBeNull();
    expect(screen.getByRole('button', { name: /More actions for batch/ })).toBeTruthy();
    expect(document.querySelector('a[href^="/batches/"]')).toBeNull();
  });
});
