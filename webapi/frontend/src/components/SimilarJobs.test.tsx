import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { api, ApiError } from '@/lib/api';
import { forJobFixture, similarFixture } from '@/lib/similar.fixture';
import { batchHref, utilizationHrefForJob } from '@/lib/similar';
import { MemorySpread, RuntimeSpread, SimilarJobs } from './SimilarJobs';
import { JobRelated } from './JobRelated';
import { RuntimeEstimateView } from '@/app/jobs/[id]/RuntimeEstimate';

// From one job back to its groups: the run time card's basis opens the
// jobs it names, the group can be widened or narrowed, the pool-wide
// group shows only its spread, and the workflow link appears only where
// there is a workflow to show.

afterEach(() => vi.restoreAllMocks());

function wrap(ui: React.ReactNode) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={client}>{ui}</QueryClientProvider>);
}

describe('the run time card', () => {
  const estimate = {
    job_id: '12.0',
    available: true,
    estimate_seconds: 4200,
    p10_seconds: 2400,
    p90_seconds: 9000,
    basis: { level: 'template' as const, sample_count: 41 },
    exceeded_history: false,
    model: { jobs_ingested: 5000 },
  };

  it('turns its basis into a link to those jobs', () => {
    const onShowSimilar = vi.fn();
    render(<RuntimeEstimateView estimate={estimate} status={1} fetchedAt={1_760_000_000} onShowSimilar={onShowSimilar} />);
    const link = screen.getByTestId('runtime-basis-link');
    expect(link).toHaveTextContent('From 41 of your earlier jobs with the same command and argument pattern.');
    fireEvent.click(link);
    expect(onShowSimilar).toHaveBeenCalled();
  });

  it('leaves the basis as text where there is nothing to open', () => {
    render(<RuntimeEstimateView estimate={estimate} status={1} fetchedAt={1_760_000_000} />);
    expect(screen.queryByTestId('runtime-basis-link')).not.toBeInTheDocument();
  });
});

describe('SimilarJobs', () => {
  it('starts at the group the estimate used, with every level and its count', async () => {
    const spy = vi.spyOn(api.jobs, 'similar').mockImplementation(async (id, p) => similarFixture(id, p));
    wrap(<SimilarJobs jobID="12.0" mark={{ seconds: 3000, label: 'This job so far' }} />);
    await screen.findByTestId('similar-jobs');
    expect(spy.mock.calls[0][1]).toMatchObject({ level: undefined, offset: 0 });
    const levels = screen.getByRole('radiogroup', { name: 'Compare with' });
    const chosen = within(levels).getByRole('radio', { checked: true });
    expect(chosen).toHaveTextContent('same command, numbers ignored · 41 (used for the estimate)');
    // A level that does not apply to this job is not offered.
    expect(within(levels).queryByText(/same cluster/)).not.toBeInTheDocument();
    expect(within(levels).getByRole('radio', { name: /same program, any arguments · 150/ })).toBeInTheDocument();
    // The jobs, newest first, each linking to its record.
    const rows = screen.getAllByRole('row').slice(1);
    expect(rows).toHaveLength(41);
    expect(within(rows[0]).getByRole('link')).toHaveAttribute('href', '/archive/81200.0');
    expect(screen.getByTestId('spread-mark')).toBeInTheDocument();
    expect(screen.getByText(/This job so far: 50m/)).toBeInTheDocument();
  });

  it('asks for a wider group when one is picked, and pages through it', async () => {
    const spy = vi.spyOn(api.jobs, 'similar').mockImplementation(async (id, p) => similarFixture(id, p));
    wrap(<SimilarJobs jobID="12.0" />);
    await screen.findByTestId('similar-jobs');
    fireEvent.click(screen.getByRole('radio', { name: /same program/ }));
    await waitFor(() => expect(spy.mock.calls.at(-1)![1]).toMatchObject({ level: 'cmd', offset: 0 }));
    await screen.findByRole('button', { name: /Show more \(50 of 150\)/ });
    fireEvent.click(screen.getByRole('button', { name: /Show more/ }));
    await waitFor(() => expect(spy.mock.calls.at(-1)![1]).toMatchObject({ level: 'cmd', offset: 50 }));
  });

  it('offers no group wider than the owner\'s own jobs', async () => {
    vi.spyOn(api.jobs, 'similar').mockImplementation(async (id, p) => similarFixture(id, { ...p, level: p?.level ?? 'owner' }));
    wrap(<SimilarJobs jobID="12.0" />);
    const levels = await screen.findByRole('radiogroup', { name: 'Compare with' });
    expect(within(levels).getByRole('radio', { checked: true })).toHaveTextContent('all your jobs of this kind');
    expect(within(levels).queryByText(/access point/)).not.toBeInTheDocument();
    expect(screen.getAllByRole('row').slice(1)).toHaveLength(50);
  });

  it('says so when the server has no similar jobs to offer', async () => {
    vi.spyOn(api.jobs, 'similar').mockRejectedValue(new ApiError(501, 'not available'));
    wrap(<SimilarJobs jobID="12.0" />);
    expect(await screen.findByText('Similar jobs are not available on this server.')).toBeInTheDocument();
  });
});

describe('Related', () => {
  const session = { authenticated: true, username: 'e2e', is_admin: false };

  it('links the batch, the workflow and the similar jobs', async () => {
    vi.spyOn(api.auth, 'me').mockResolvedValue(session);
    vi.spyOn(api.jobs, 'utilizationWorkflow').mockResolvedValue(forJobFixture('12.0'));
    const onSimilar = vi.fn();
    wrap(<JobRelated jobID="12.0" cluster={12} archived={false} onSimilar={onSimilar} />);
    expect(screen.getByRole('link', { name: 'Batch 12' })).toHaveAttribute('href', '/batches/12');
    const util = await screen.findByTestId('related-utilization');
    expect(util).toHaveAttribute('href', '/utilization?days=30&w=wf-blast');
    fireEvent.click(screen.getByRole('button', { name: 'Similar jobs' }));
    expect(onSimilar).toHaveBeenCalled();
  });

  it('hides the workflow link when the workflow has no finished jobs to show', async () => {
    vi.spyOn(api.auth, 'me').mockResolvedValue(session);
    const spy = vi.spyOn(api.jobs, 'utilizationWorkflow').mockResolvedValue(forJobFixture('12.0', { has_history: false }));
    wrap(<JobRelated jobID="12.0" cluster={12} archived={false} onSimilar={() => {}} />);
    await waitFor(() => expect(spy).toHaveBeenCalled());
    await new Promise((r) => setTimeout(r, 0));
    expect(screen.queryByTestId('related-utilization')).not.toBeInTheDocument();
  });

  it('hides the workflow link when the workflow cannot be found', async () => {
    vi.spyOn(api.auth, 'me').mockResolvedValue(session);
    const spy = vi.spyOn(api.jobs, 'utilizationWorkflow').mockRejectedValue(new ApiError(501, 'multi-AP'));
    wrap(<JobRelated jobID="12.0" cluster={12} archived onSimilar={() => {}} />);
    await waitFor(() => expect(spy).toHaveBeenCalled());
    expect(screen.queryByTestId('related-utilization')).not.toBeInTheDocument();
    // The batch page reads the archive too.
    expect(screen.getByRole('link', { name: 'Batch 12' })).toHaveAttribute('href', '/batches/12');
  });

  it("links a DAG node to its DAG's batch, not its own cluster", () => {
    vi.spyOn(api.auth, 'me').mockResolvedValue(session);
    vi.spyOn(api.jobs, 'utilizationWorkflow').mockRejectedValue(new ApiError(404, 'none'));
    wrap(<JobRelated jobID="104.0" cluster={104} batchID={100} archived={false} onSimilar={() => {}} />);
    expect(screen.getByRole('link', { name: 'Batch 100' })).toHaveAttribute('href', '/batches/100');
  });

  it('lists the cluster in multi-AP mode, which has no batch pages', () => {
    vi.spyOn(api.auth, 'me').mockResolvedValue(session);
    vi.spyOn(api.jobs, 'utilizationWorkflow').mockRejectedValue(new ApiError(501, 'multi-AP'));
    wrap(<JobRelated jobID="104.0@ap1.example.org" cluster={104} batchID={100} archived={false} onSimilar={() => {}} />);
    expect(screen.getByRole('link', { name: 'Batch 104' })).toHaveAttribute('href', batchHref(104, false));
  });
});

describe('utilizationHrefForJob', () => {
  it("opens someone else's workflow in the pool-wide scope, narrowed to them", () => {
    expect(utilizationHrefForJob(forJobFixture('1.0', { owner: 'bob' }), 'admin')).toBe(
      '/utilization?days=30&w=wf-blast&owned_by_me=false&owners=bob',
    );
  });

  it('links when it cannot tell cheaply whether there is history', () => {
    expect(utilizationHrefForJob(forJobFixture('1.0', { has_history: null }), 'e2e')).toBe(
      '/utilization?days=30&w=wf-blast',
    );
  });
});

describe('the spreads', () => {
  const q = { count: 9, p10: 900, p25: 1000, p50: 1229, p75: 1500, p90: 2048 };

  it('describes run times and peak memory in the same form', () => {
    render(<RuntimeSpread runtimes={{ count: 9, p10: 600, p25: 1200, p50: 1800, p75: 2400, p90: 3600 }} mark={{ seconds: 3000, label: 'This job so far' }} />);
    expect(screen.getByTestId('runtime-spread')).toHaveTextContent(
      'Half of these 9 jobs took 20m to 40m (typically 30m); 9 in 10 finished within 1h. This job so far: 50m.',
    );
    render(<MemorySpread memory={q} mark={{ mib: 6246, label: 'This job so far' }} requestedMiB={2048} />);
    const memory = screen.getByTestId('memory-spread');
    expect(memory).toHaveTextContent(
      'Half of these 9 jobs peaked at 1,000 MB to 1.5 GB (typically 1.2 GB); 9 in 10 stayed under 2 GB. This job so far: 6.1 GB. Requested: 2 GB.',
    );
    expect(within(memory).getByTestId('memory-spread-mark')).toBeInTheDocument();
    expect(within(memory).getByTestId('memory-spread-ref')).toBeInTheDocument();
    expect(within(memory).getByText('Requested')).toBeInTheDocument();
  });

  it('places the job and its request on the same axis as the group', () => {
    render(<MemorySpread memory={q} mark={{ mib: 6246, label: 'This job' }} requestedMiB={2048} />);
    const memory = screen.getByTestId('memory-spread');
    // The axis reaches past the largest of them: the job's peak.
    const left = (el: HTMLElement) => parseFloat(el.style.left);
    expect(left(within(memory).getByTestId('memory-spread-mark'))).toBeCloseTo(100 / 1.15, 1);
    expect(left(within(memory).getByTestId('memory-spread-ref'))).toBeCloseTo((2048 / (6246 * 1.15)) * 100, 1);
  });

  it('stretches the axis to a request larger than everything else', () => {
    render(<MemorySpread memory={q} mark={{ mib: 3000, label: 'This job' }} requestedMiB={8192} />);
    const memory = screen.getByTestId('memory-spread');
    expect(parseFloat(within(memory).getByTestId('memory-spread-ref').style.left)).toBeCloseTo(100 / 1.15, 1);
  });

  it('draws no mark or request line without them', () => {
    render(<MemorySpread memory={q} />);
    expect(screen.queryByTestId('memory-spread-mark')).not.toBeInTheDocument();
    expect(screen.queryByTestId('memory-spread-ref')).not.toBeInTheDocument();
  });
});

describe('SimilarJobs memory', () => {
  it('shows the group\'s memory under its run times, and each job\'s peak', async () => {
    vi.spyOn(api.jobs, 'similar').mockImplementation(async (id, p) => similarFixture(id, p));
    wrap(<SimilarJobs jobID="12.0" memory={{ mark: { mib: 3000, label: 'This job so far' }, requestedMiB: 2048 }} />);
    await screen.findByTestId('similar-jobs');
    expect(screen.getByTestId('memory-spread')).toHaveTextContent('This job so far: 2.9 GB.');
    expect(screen.getByRole('columnheader', { name: 'Peak memory' })).toBeInTheDocument();
    const rows = screen.getAllByRole('row').slice(1);
    // The fixture leaves every seventh record without a peak.
    expect(within(rows[6]).getAllByRole('cell')[3]).toHaveTextContent('—');
    expect(within(rows[0]).getAllByRole('cell')[3]).toHaveTextContent(/^\d[\d.]* (MB|GB)$/);
  });

  it('shows no memory plot for a group whose records have no peak', async () => {
    vi.spyOn(api.jobs, 'similar').mockImplementation(async (id, p) => similarFixture(id, { ...p, level: 'iwd' }));
    wrap(<SimilarJobs jobID="12.0" />);
    await screen.findByTestId('similar-jobs');
    expect(screen.getByTestId('runtime-spread')).toBeInTheDocument();
    expect(screen.queryByTestId('memory-spread')).not.toBeInTheDocument();
  });
});
