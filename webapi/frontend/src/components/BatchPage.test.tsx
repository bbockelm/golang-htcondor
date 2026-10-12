import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { api } from '@/lib/api';
import {
  batchJobsFixture,
  dagBatchFixture,
  finishedBatchFixture,
  liveBatchFixture,
  newBatchFixture,
} from '@/lib/batchPage.fixture';
import type { BatchResponse } from '@/lib/batchPage';
import type { TimedJob } from '@/lib/timeLeft';
import type { RuntimeEstimatesState } from '@/lib/useRuntimeEstimates';
import {
  BatchHeader,
  DagSection,
  HoldsSection,
  JobsSection,
  OutcomesSection,
  ProgressSection,
  ResourcesSection,
} from './BatchPage';

// /batches/<id>, one section at a time, over the four fixture batches:
// one part-way through, one finished, a DAG, and one just submitted.

const NOW = 1_760_000_000;

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

function wrap(ui: React.ReactNode) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={client}>{ui}</QueryClientProvider>);
}

// jsdom has no matchMedia; a phone matches every max-width query.
function asPhone() {
  vi.stubGlobal('matchMedia', (q: string) => ({
    matches: q.includes('max-width'),
    media: q,
    addEventListener: () => {},
    removeEventListener: () => {},
  }));
}

describe('BatchHeader', () => {
  it('names the batch and offers release, hold and remove for a batch with jobs in the queue', () => {
    wrap(<BatchHeader batch={liveBatchFixture(NOW)} now={NOW} />);
    expect(screen.getByRole('heading', { level: 1 })).toHaveTextContent('blast-run');
    expect(screen.getByText(/Batch 300 · 2 clusters/)).toBeInTheDocument();
    const actions = screen.getByTestId('batch-actions');
    expect(within(actions).getByRole('button', { name: 'Release 3 held' })).toBeInTheDocument();
    expect(within(actions).getByRole('button', { name: 'Hold batch' })).toBeInTheDocument();
    expect(within(actions).getByRole('button', { name: 'Remove batch' })).toBeInTheDocument();
  });

  it("removes by the batch's remove constraint after a confirm", async () => {
    const spy = vi.spyOn(api.jobs, 'removeByConstraint').mockResolvedValue({});
    const b = dagBatchFixture(NOW);
    wrap(<BatchHeader batch={b} now={NOW} />);
    fireEvent.click(screen.getByRole('button', { name: 'Remove batch' }));
    expect(spy).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole('button', { name: 'Remove 4 jobs' }));
    await waitFor(() => expect(spy).toHaveBeenCalledWith(b.remove_constraint));
  });

  it('holds and releases by the same constraint', async () => {
    const hold = vi.spyOn(api.jobs, 'holdByConstraint').mockResolvedValue({});
    const release = vi.spyOn(api.jobs, 'releaseByConstraint').mockResolvedValue({});
    const b = liveBatchFixture(NOW);
    wrap(<BatchHeader batch={b} now={NOW} />);
    fireEvent.click(screen.getByRole('button', { name: 'Hold batch' }));
    fireEvent.click(screen.getByRole('button', { name: 'Hold 42 jobs' }));
    await waitFor(() => expect(hold).toHaveBeenCalledWith(b.remove_constraint));
    fireEvent.click(screen.getByRole('button', { name: 'Release 3 held' }));
    fireEvent.click(screen.getByRole('button', { name: 'Release 3 jobs' }));
    await waitFor(() => expect(release).toHaveBeenCalledWith(b.remove_constraint));
  });

  it('has no actions for a finished batch, nor in multi-AP mode', () => {
    const { unmount } = wrap(<BatchHeader batch={finishedBatchFixture(NOW)} now={NOW} />);
    expect(screen.queryByTestId('batch-actions')).not.toBeInTheDocument();
    expect(screen.getByText(/Last job finished 2d/)).toBeInTheDocument();
    unmount();
    wrap(<BatchHeader batch={liveBatchFixture(NOW)} now={NOW} multiAP />);
    expect(screen.queryByTestId('batch-actions')).not.toBeInTheDocument();
  });

  it('marks a DAG and offers no release when nothing is held', () => {
    wrap(<BatchHeader batch={dagBatchFixture(NOW)} now={NOW} />);
    expect(screen.getByText('DAG', { exact: true })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Release/ })).not.toBeInTheDocument();
  });
});

describe('ProgressSection', () => {
  it('states done of total, what the rest is doing, and the queue by state', () => {
    wrap(<ProgressSection batch={liveBatchFixture(NOW)} timed={undefined} estimates={undefined} now={NOW} />);
    const s = screen.getByTestId('batch-progress');
    expect(s).toHaveTextContent('55 of 100 jobs done');
    expect(s).toHaveTextContent('12 running · 30 waiting · 3 held');
    expect(within(s).getByTestId('live-counts')).toHaveTextContent('12 Running30 Idle3 Held');
    expect(within(s).queryByTestId('batch-time-left-section')).not.toBeInTheDocument();
  });

  it("says why the count is unknown, from the server's reason key", () => {
    wrap(<ProgressSection batch={newBatchFixture(NOW)} timed={undefined} estimates={undefined} now={NOW} />);
    expect(screen.getByTestId('batch-progress')).toHaveTextContent(
      'How many jobs this batch was submitted with is not recorded.',
    );
  });

  it('gives the time left from the estimates of the waiting and running jobs', () => {
    const timed: TimedJob[] = [
      { status: 'running', estimate: { available: true, estimate_seconds: 2700, p10_seconds: 1800, p90_seconds: 4200, exceeded_history: false, elapsed_seconds: 1200, remaining_seconds: 1500 } },
      { status: 'idle', estimate: { available: true, estimate_seconds: 2700, p10_seconds: 1800, p90_seconds: 4200, exceeded_history: false } },
    ];
    const estimates: RuntimeEstimatesState = {
      available: true,
      byId: new Map([['301.0', timed[0].estimate!]]),
      requested: new Set(['301.0', '301.12']),
      fetchedAt: NOW,
    };
    wrap(<ProgressSection batch={liveBatchFixture(NOW)} timed={timed} estimates={estimates} now={NOW} />);
    expect(screen.getByTestId('batch-time-left')).toHaveTextContent('1 waiting · each about 45m once started');
  });

  it('counts a DAG in nodes', () => {
    wrap(<ProgressSection batch={dagBatchFixture(NOW)} timed={undefined} estimates={undefined} now={NOW} />);
    expect(screen.getByTestId('batch-progress')).toHaveTextContent('3 of 8 nodes done');
  });
});

describe('DagSection', () => {
  it("lists the DAG's node counts and offers its graph", () => {
    wrap(<DagSection batch={dagBatchFixture(NOW)} />);
    expect(screen.getByTestId('dag-nodes')).toHaveTextContent('3 done3 in the queue2 waiting on parents');
    // Zero counts are left out.
    expect(screen.getByTestId('dag-nodes')).not.toHaveTextContent('failed');
    expect(screen.getByTestId('workflow-graph-panel')).toBeInTheDocument();
  });

  it('says so when the DAG has not reported its nodes', () => {
    const b: BatchResponse = { ...dagBatchFixture(NOW), dag: undefined };
    wrap(<DagSection batch={b} />);
    expect(screen.getByTestId('batch-dag')).toHaveTextContent('This workflow has not reported its nodes yet.');
  });

  it('is not there for a batch that is not a DAG', () => {
    wrap(<DagSection batch={liveBatchFixture(NOW)} />);
    expect(screen.queryByTestId('batch-dag')).not.toBeInTheDocument();
  });
});

describe('OutcomesSection', () => {
  it('splits finished jobs by how they ended, with run times and lost time', () => {
    wrap(<OutcomesSection batch={liveBatchFixture(NOW)} />);
    const s = screen.getByTestId('batch-outcomes');
    expect(s).toHaveTextContent('50 succeeded');
    expect(s).toHaveTextContent('4 failed');
    expect(s).toHaveTextContent('1 removed');
    expect(within(s).getByTestId('outcomes')).toHaveTextContent(
      '50 · exit code 03 · exit code 11 · killed by signal 91 · removed',
    );
    expect(within(s).getByTestId('runtime-strip')).toBeInTheDocument();
    expect(s).toHaveTextContent('Typically 45m; 9 in 10 within 1h10m; the longest 1h55m.');
    expect(s).toHaveTextContent('52 h of run time, 6 h of it lost to runs that started over · 210 core-hours');
    expect(s).toHaveTextContent('Peak memory typically 1.2 GiB of 4 GiB requested; the largest 3.4 GiB.');
  });

  it('leaves out the breakdown when every job ended the same way, and the lost time when there is none', () => {
    wrap(<OutcomesSection batch={finishedBatchFixture(NOW)} />);
    const s = screen.getByTestId('batch-outcomes');
    expect(s).toHaveTextContent('20 succeeded');
    expect(within(s).queryByTestId('outcomes')).not.toBeInTheDocument();
    expect(s).not.toHaveTextContent('lost');
  });

  it('says when none has finished', () => {
    wrap(<OutcomesSection batch={newBatchFixture(NOW)} />);
    expect(screen.getByTestId('batch-outcomes')).toHaveTextContent("None of this batch's jobs has finished yet.");
  });

  it('says when the figures cover only the newest jobs', () => {
    const b = liveBatchFixture(NOW);
    wrap(<OutcomesSection batch={{ ...b, finished: { ...b.finished, truncated: true, limit: 100_000 } }} />);
    expect(screen.getByTestId('batch-outcomes')).toHaveTextContent('These cover the newest 100,000 finished jobs.');
  });
});

describe('HoldsSection', () => {
  it('groups hold reasons, held now and held before, with the jobs they apply to', () => {
    wrap(<HoldsSection batch={liveBatchFixture(NOW)} />);
    const s = screen.getByTestId('batch-holds');
    const items = within(s).getAllByRole('listitem');
    expect(items[0]).toHaveTextContent('3jobs held nowMemory limit exceeded');
    expect(items[1]).toHaveTextContent('2finished jobs were heldInput transfer failed');
    expect(within(items[0]).getByRole('link', { name: '301.4' })).toHaveAttribute('href', '/jobs/301.4');
  });

  it("quotes one of each group's own messages, never its pattern", () => {
    wrap(<HoldsSection batch={liveBatchFixture(NOW)} />);
    const s = screen.getByTestId('batch-holds');
    const items = within(s).getAllByRole('listitem');
    // Without the "Error from <slot>: " that names the machine.
    expect(items[0]).toHaveTextContent('Job has gone over cgroup memory limit of 4096 megabytes.');
    expect(items[0]).not.toHaveTextContent('Error from');
    expect(items[1]).toHaveTextContent('Transfer input files failure at execution point slot1@e9: reading db.tar');
    expect(s.textContent).not.toContain('*');
  });

  it('shows the count and label alone for a group with no example', () => {
    const b = liveBatchFixture(NOW);
    wrap(<HoldsSection batch={{ ...b, hold_reasons: [{ ...b.hold_reasons[0], examples: [] }] }} />);
    const s = screen.getByTestId('batch-holds');
    expect(s).toHaveTextContent('3jobs held nowMemory limit exceeded');
    expect(s.textContent).not.toContain('*');
  });

  it('leaves out the input-spooling hold every remote submit passes through', () => {
    const b = finishedBatchFixture(NOW);
    wrap(
      <HoldsSection
        batch={{
          ...b,
          hold_reasons: [
            { kind: 'was_held', template: 'Spooling input data files', count: 20, codes: [{ code: 16, subcode: 0, count: 20 }], examples: [] },
          ],
        }}
      />,
    );
    expect(screen.queryByTestId('batch-holds')).not.toBeInTheDocument();
  });

  it('is not there when nothing was held', () => {
    wrap(<HoldsSection batch={finishedBatchFixture(NOW)} />);
    expect(screen.queryByTestId('batch-holds')).not.toBeInTheDocument();
  });
});

describe('ResourcesSection', () => {
  it("links each Utilization workflow of a finished batch and does not read the queue", () => {
    const list = vi.spyOn(api.jobs, 'list');
    wrap(<ResourcesSection batch={finishedBatchFixture(NOW)} />);
    expect(screen.getByRole('link', { name: 'simulate' })).toHaveAttribute('href', '/utilization?w=wf-sim&days=30');
    expect(list).not.toHaveBeenCalled();
  });

  it("shows the live usage of the batch's jobs in the queue", async () => {
    const b = liveBatchFixture(NOW);
    const list = vi.spyOn(api.jobs, 'list').mockResolvedValue({
      jobs: [
        { ClusterId: 301, ProcId: 0, JobStatus: 2, RequestCpus: 4, RequestMemory: 4096, MemoryUsage: 1024 },
        { ClusterId: 301, ProcId: 1, JobStatus: 1, RequestCpus: 4, RequestMemory: 4096 },
      ],
      has_more: false,
    } as never);
    wrap(<ResourcesSection batch={b} />);
    await screen.findByText('1 running, 1 idle');
    expect(list.mock.calls[0][0]).toMatchObject({ constraint: b.remove_constraint, owned_by_me: false });
  });

  it('is not there for a batch with nothing in the queue and no workflow', () => {
    const b: BatchResponse = { ...finishedBatchFixture(NOW), workflows: [] };
    wrap(<ResourcesSection batch={b} />);
    expect(screen.queryByTestId('batch-resources')).not.toBeInTheDocument();
  });
});

describe('JobsSection', () => {
  function serve(b: BatchResponse) {
    return vi.spyOn(api.batches, 'jobs').mockImplementation(async (_id, q) => batchJobsFixture(b, NOW, q ?? {}));
  }

  it('lists live and finished jobs a page at a time, each linking to its page', async () => {
    const b = liveBatchFixture(NOW);
    const spy = serve(b);
    wrap(<JobsSection batch={b} estimates={undefined} now={NOW} />);
    const rows = await screen.findAllByTestId('batch-job-row');
    expect(rows).toHaveLength(50);
    expect(within(rows[0]).getByRole('link', { name: '301.0' })).toHaveAttribute('href', '/jobs/301.0');
    expect(rows[0]).toHaveTextContent('running 20m');
    fireEvent.click(screen.getByRole('button', { name: 'Show more (50 of 100)' }));
    await waitFor(() => expect(screen.getAllByTestId('batch-job-row')).toHaveLength(100));
    expect(spy.mock.calls[1][1]).toMatchObject({ offset: 50, page_size: 50 });
    const last = screen.getAllByTestId('batch-job-row')[99];
    expect(last).toHaveTextContent('Removed');
  });

  it('filters by the chips and sorts by the select', async () => {
    const b = liveBatchFixture(NOW);
    const spy = serve(b);
    wrap(<JobsSection batch={b} estimates={undefined} now={NOW} />);
    await screen.findAllByTestId('batch-job-row');
    const chips = screen.getByRole('group', { name: 'Show' });
    expect(within(chips).getAllByRole('button').map((c) => c.textContent)).toEqual([
      'All',
      'In the queue45',
      'Finished55',
      'Running12',
      'Idle30',
      'Held3',
    ]);
    fireEvent.click(within(chips).getByRole('button', { name: /^Finished/ }));
    await waitFor(() => expect(spy).toHaveBeenLastCalledWith(300, expect.objectContaining({ status: ['finished'] })));
    expect(within(chips).getByRole('button', { name: /^Finished/ })).toHaveAttribute('aria-pressed', 'true');
    fireEvent.change(screen.getByRole('combobox', { name: 'Sort' }), { target: { value: 'runtime' } });
    await waitFor(() =>
      expect(spy).toHaveBeenLastCalledWith(300, expect.objectContaining({ status: ['finished'], sort: 'runtime' })),
    );
    await waitFor(() => expect(screen.getAllByTestId('batch-job-row')[0]).toHaveTextContent('ran 55m'));
  });

  it("shows a DAG's node names and its DAGMan job", async () => {
    const b = dagBatchFixture(NOW);
    serve(b);
    wrap(<JobsSection batch={b} estimates={undefined} now={NOW} />);
    const rows = await screen.findAllByTestId('batch-job-row');
    expect(screen.getByRole('columnheader', { name: 'Node' })).toBeInTheDocument();
    expect(rows[0]).toHaveTextContent('500.0DAGManRunning');
    expect(rows[1]).toHaveTextContent('501.0node_ARunning');
  });

  it('is compact entries on a phone', async () => {
    asPhone();
    const b = finishedBatchFixture(NOW);
    serve(b);
    wrap(<JobsSection batch={b} estimates={undefined} now={NOW} />);
    const cards = await screen.findAllByTestId('batch-job-card');
    expect(cards).toHaveLength(20);
    expect(screen.queryByRole('table')).not.toBeInTheDocument();
    expect(cards[0]).toHaveTextContent('410.1000Completedran 10mexit 0');
  });

  it("shows a finished job's ending, and a hold it had along the way unless it was the input spooling", async () => {
    const b = finishedBatchFixture(NOW);
    vi.spyOn(api.batches, 'jobs').mockImplementation(async (_id, q) => {
      const r = batchJobsFixture(b, NOW, q ?? {});
      r.jobs[0] = { ...r.jobs[0], hold_reason: 'Spooling input data files', hold_code: 16 };
      r.jobs[1] = { ...r.jobs[1], hold_reason: 'Transfer input files failure', hold_code: 13 };
      return r;
    });
    wrap(<JobsSection batch={b} estimates={undefined} now={NOW} />);
    const rows = await screen.findAllByTestId('batch-job-row');
    expect(rows[0]).toHaveTextContent(/exit 0$/);
    expect(rows[1]).toHaveTextContent(/exit 0Was held: Transfer input files failure$/);
  });

  it('offers only the groups the batch has, and says when a filter has no jobs', async () => {
    const b = newBatchFixture(NOW);
    vi.spyOn(api.batches, 'jobs').mockImplementation(async (_id, q) =>
      q?.status ? { ...batchJobsFixture(b, NOW, {}), total: 0, jobs: [] } : batchJobsFixture(b, NOW, {}),
    );
    wrap(<JobsSection batch={b} estimates={undefined} now={NOW} />);
    await screen.findAllByTestId('batch-job-row');
    const chips = screen.getByRole('group', { name: 'Show' });
    expect(within(chips).getAllByRole('button').map((c) => c.textContent)).toEqual(['All', 'In the queue5', 'Idle5']);
    fireEvent.click(within(chips).getByRole('button', { name: /^Idle/ }));
    expect(await screen.findByText('No jobs here.')).toBeInTheDocument();
  });
});
