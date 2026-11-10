import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { api, ApiError } from '@/lib/api';
import { utilizationJobsFixture } from '@/lib/utilization.fixture';
import type { JobFocus, UtilJobRow } from '@/lib/utilization';
import { coresReading, memoryReading, WorkflowJobs, type JobsQuery } from './UtilizationJobs';

// The list of a workflow's jobs: what each row says, that sorting is the
// server's (it asks again rather than reordering the page it has), that a
// range picked on a chart marks its jobs, and what an unknown workflow
// looks like.

beforeAll(() => {
  // jsdom has no IntersectionObserver; the list only needs it to load
  // the next page on scroll, and the tests drive "Load more" instead.
  class IO {
    observe() {}
    disconnect() {}
  }
  vi.stubGlobal('IntersectionObserver', IO);
});

afterEach(() => vi.restoreAllMocks());

const query: JobsQuery = { days: 7, owned_by_me: true, constraint: 'RequestGpus > 0' };

function renderList(focus: JobFocus | null = null) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <WorkflowJobs workflowKey="wf-assemble" query={query} hasGpu={false} focus={focus} onClearFocus={() => {}} />
    </QueryClientProvider>,
  );
}

function stubJobs() {
  return vi.spyOn(api, 'utilizationJobs').mockImplementation(async (p) => utilizationJobsFixture(p.w, p)!);
}

describe('job readings', () => {
  const row = utilizationJobsFixture('wf-assemble')!.jobs[0];

  it('reads peak memory against the request, flagged when over', () => {
    const over: UtilJobRow = { ...row, memory_peak_mib: 3072, request: { ...row.request, memory_mib: 2048 } };
    const r = memoryReading(over)!;
    expect(r.tone).toBe('critical');
    expect(r.text).toBe('3 GB of 2 GB · 150%');
  });

  it('has nothing to draw for an unmeasured job', () => {
    expect(memoryReading({ ...row, memory_peak_mib: null })).toBeUndefined();
    expect(coresReading({ ...row, cores_used: null })).toBeUndefined();
  });
});

describe('WorkflowJobs', () => {
  it('lists the jobs, each linked to its record, with the analysis filters on the request', async () => {
    const spy = stubJobs();
    renderList();
    await screen.findByText(/100 of 310 shown/);
    const first = spy.mock.calls[0][0];
    expect(first).toMatchObject({ w: 'wf-assemble', days: 7, constraint: 'RequestGpus > 0', sort: 'completed', order: 'desc', offset: 0 });
    const link = screen.getAllByRole('link')[0];
    expect(link.getAttribute('href')).toMatch(/^\/archive\/\d+\.\d+$/);
  });

  it('sorts on the server and pages from where it left off', async () => {
    const spy = stubJobs();
    renderList();
    await screen.findByText(/100 of 310 shown/);
    fireEvent.click(screen.getByRole('button', { name: /Run time/ }));
    await waitFor(() => expect(spy.mock.calls.at(-1)![0]).toMatchObject({ sort: 'wall', order: 'asc', offset: 0 }));
    fireEvent.click(await screen.findByRole('button', { name: 'Load more' }));
    await waitFor(() => expect(spy.mock.calls.at(-1)![0]).toMatchObject({ sort: 'wall', offset: 100 }));
    await screen.findByText(/200 of 310 shown/);
  });

  it('marks the jobs in a range picked on a chart and sorts by that measure', async () => {
    const spy = stubJobs();
    renderList({ sort: 'memory', lo: 2048, hi: 2560, label: 'peak memory 2–2.5 GB' });
    await screen.findByTestId('job-focus');
    await waitFor(() => expect(spy.mock.calls.at(-1)![0]).toMatchObject({ sort: 'memory', order: 'desc' }));
    const marked = await screen.findAllByRole('row').then((rows) => rows.filter((r) => r.dataset.marked === 'true'));
    expect(marked.length).toBeGreaterThan(0);
    for (const r of marked) {
      const text = within(r).getAllByRole('img')[0].getAttribute('aria-label')!;
      const gb = Number(text.match(/Peak memory ([\d.]+) GB/)![1]);
      expect(gb).toBeGreaterThanOrEqual(2);
      expect(gb).toBeLessThanOrEqual(2.5);
    }
    expect(screen.getByTestId('job-focus')).toHaveTextContent(`${marked.length} among those shown`);
  });

  it('says what to do, not that something failed, when the workflow has no jobs here', async () => {
    vi.spyOn(api, 'utilizationJobs').mockRejectedValue(new ApiError(404, 'no such workflow'));
    renderList();
    const msg = await screen.findByText(/no finished jobs in the selected window and filters/);
    expect(msg).toHaveTextContent('Widen the window or clear a filter');
    expect(msg).not.toHaveClass('text-red-700');
  });
});

describe('a job picked on the scatter', () => {
  it('is found even when it sorts onto a later page, and marked alone', async () => {
    const spy = stubJobs();
    // The job with the smallest peak memory sorts last by memory, on the
    // fourth page of 310.
    const all = utilizationJobsFixture('wf-assemble', { sort: 'memory', order: 'asc', page_size: 500 })!.jobs;
    const target = all.find((r) => r.memory_peak_mib !== null)!;
    renderList({
      sort: 'memory',
      lo: target.memory_peak_mib!,
      hi: target.memory_peak_mib!,
      label: `job ${target.id}`,
      job: target.id,
    });
    expect(await screen.findByText(`Job ${target.id}, marked below.`, {}, { timeout: 4000 })).toBeInTheDocument();
    expect(spy.mock.calls.length).toBeGreaterThan(1);
    const marked = screen.getAllByRole('row').filter((r) => r.dataset.marked === 'true');
    expect(marked).toHaveLength(1);
    expect(within(marked[0]).getByRole('link')).toHaveTextContent(target.id);
  });

  it('stops looking after a bound and links the record instead', async () => {
    stubJobs();
    renderList({ sort: 'memory', lo: 0, hi: 0, label: 'job 1.0', job: '1.0' });
    const link = await screen.findByRole('link', { name: 'Open its record' }, { timeout: 4000 });
    expect(link).toHaveAttribute('href', '/archive/1.0');
  });
});
