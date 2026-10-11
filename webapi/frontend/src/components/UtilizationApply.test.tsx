import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { api } from '@/lib/api';
import { fullWorkflows } from '@/lib/utilization.fixture';
import type { UtilApplyResponse, UtilWorkflow } from '@/lib/utilization';
import { ApplyPanel } from './UtilizationApply';
import type { JobsQuery } from './UtilizationJobs';

// Applying a workflow's advice to its waiting jobs: the offer appears
// only when there is something to apply and someone waiting, the review
// says exactly what changes from what to what, the request names advice
// by id (the server picks the values), and the answer reads as a result.

afterEach(() => vi.restoreAllMocks());

const query: JobsQuery = { days: 7, owned_by_me: true, constraint: 'JobBatchName == "x"' };
const blast = fullWorkflows.find((w) => w.key === 'wf-blast')!;
const assemble = fullWorkflows.find((w) => w.key === 'wf-assemble')!;

function renderPanel(workflow: UtilWorkflow, waiting: number | null) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <ApplyPanel workflow={workflow} waitingJobs={waiting} query={query} />
    </QueryClientProvider>,
  );
}

const ok: UtilApplyResponse = {
  edited: 118,
  set: { RequestMemory: 1792, RequestDisk: 3 * 1024 * 1024 },
  declined: [],
  skipped: [
    { job: '81291.4', reason: 'its memory request is a formula' },
    { job: '81291.9', reason: 'its memory request is a formula' },
  ],
  failed: [{ job: '81291.12', reason: 'the schedd refused the edit' }],
};

describe('ApplyPanel', () => {
  it('offers nothing when no job is waiting', () => {
    const { container } = renderPanel(blast, 0);
    expect(container).toBeEmptyDOMElement();
  });

  it('lists each request that changes, from what to what, before anything is applied', () => {
    const spy = vi.spyOn(api, 'utilizationApply');
    renderPanel(blast, 120);
    expect(screen.getByRole('heading', { level: 3 })).toHaveTextContent(
      '120 jobs of this workflow are still waiting — apply these requests to them',
    );
    fireEvent.click(screen.getByRole('button', { name: 'Review the changes' }));
    const rows = within(screen.getByTestId('apply-changes')).getAllByRole('row').slice(1);
    const cells = rows.map((r) => within(r).getAllByRole('cell').slice(1).map((c) => c.textContent));
    // retry_request_memory is part of the memory advice, not a request
    // of its own, so it is not listed as one.
    expect(cells).toEqual([
      ['request_memory', '8 GB', '1792 MB'],
      ['request_disk', '10 GB', '3 GB'],
    ]);
    // Reviewing is not applying.
    expect(spy).not.toHaveBeenCalled();
  });

  it('sends advice ids and the analysis, never values, and reports the result', async () => {
    const spy = vi.spyOn(api, 'utilizationApply').mockResolvedValue(ok);
    renderPanel(blast, 120);
    fireEvent.click(screen.getByRole('button', { name: 'Review the changes' }));
    fireEvent.click(screen.getByRole('button', { name: 'Apply to 120 waiting jobs' }));
    await waitFor(() => expect(spy).toHaveBeenCalled());
    const body = spy.mock.calls[0][0];
    expect(body).toEqual({
      w: 'wf-blast',
      advice: ['memory-retry', 'disk-lower'],
      days: 7,
      owned_by_me: true,
      constraint: 'JobBatchName == "x"',
      owners: undefined,
      limit: undefined,
      schedd: undefined,
    });
    expect(JSON.stringify(body)).not.toMatch(/1792|request_memory|RequestMemory/);

    const result = await screen.findByTestId('apply-result');
    expect(result).toHaveTextContent('Changed 118 waiting jobs: now requesting memory 1.8 GB, disk 3 GB.');
    expect(result).toHaveTextContent('2 jobs — its memory request is a formula');
    expect(result).toHaveTextContent('81291.12 — the schedd refused the edit');
  });

  it('sends only the advice left ticked', async () => {
    const spy = vi.spyOn(api, 'utilizationApply').mockResolvedValue({ ...ok, edited: 1 });
    renderPanel(blast, 120);
    fireEvent.click(screen.getByRole('button', { name: 'Review the changes' }));
    fireEvent.click(screen.getByRole('checkbox', { name: 'Apply request_disk' }));
    fireEvent.click(screen.getByRole('button', { name: 'Apply to 120 waiting jobs' }));
    await waitFor(() => expect(spy).toHaveBeenCalled());
    expect(spy.mock.calls[0][0].advice).toEqual(['memory-retry']);
  });

  it('says which suggestions cannot be applied, and that formula requests are kept', () => {
    const w: UtilWorkflow = {
      ...assemble,
      advice: [
        ...assemble.advice,
        {
          id: 'gpu-memory-small',
          resource: 'gpu',
          severity: 'suggest',
          title: 'Your jobs fit GPUs with 8 GB of memory',
          detail: '',
          submit: ['request_gpus = 1'],
          saves: null,
          confidence: 'high',
          applies: false,
        },
      ],
    };
    renderPanel(w, 40);
    fireEvent.click(screen.getByRole('button', { name: 'Review the changes' }));
    expect(screen.getByText('starts at 2 GB, grows after a memory hold')).toBeInTheDocument();
    expect(screen.getByText(/Jobs whose request is a formula keep it/)).toBeInTheDocument();
    expect(screen.getByTestId('apply-blocked')).toHaveTextContent('Your jobs fit GPUs with 8 GB of memory');
  });
});
