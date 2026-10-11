import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { beforeEach, describe, expect, it, vi } from 'vitest';
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
  const now = Math.floor(Date.now() / 1000);
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
    const item = screen.getByRole('menuitem', { name: 'Resource utilization' });
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

  it('does not ask in multi-AP mode or for held jobs', () => {
    table({ multiAP: true });
    table({ detail: 'hold' });
    expect(runtimeEstimates).not.toHaveBeenCalled();
  });
});
