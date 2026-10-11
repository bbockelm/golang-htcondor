import { render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import type { RuntimeEstimate, RuntimeEstimateLevel } from '@/lib/api';
import { approxDuration } from '@/lib/duration';

const runtimeEstimate = vi.fn();
vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api');
  return {
    ...actual,
    api: {
      ...actual.api,
      jobs: { ...actual.api.jobs, runtimeEstimate: (...a: unknown[]) => runtimeEstimate(...a) },
    },
  };
});

import { RuntimeEstimateField, RuntimeEstimateView, runtimeEstimateText } from './RuntimeEstimate';

function estimate(over: Partial<RuntimeEstimate> = {}): RuntimeEstimate {
  return {
    job_id: '12.0',
    available: true,
    estimate_seconds: 4200,
    p10_seconds: 2400,
    p90_seconds: 9000,
    basis: { level: 'template', sample_count: 12 },
    exceeded_history: false,
    model: { trained_through: '2026-10-10T12:00:00Z', jobs_ingested: 5000 },
    ...over,
  };
}

function shown(): string {
  return screen.getByTestId('runtime-estimate').textContent ?? '';
}

describe('RuntimeEstimateView', () => {
  it('gives a waiting job its expected run time, range and basis', () => {
    render(<RuntimeEstimateView estimate={estimate()} status={1} />);
    expect(screen.getByText('Expected run time')).toBeInTheDocument();
    expect(screen.getByText('About 1h10m (usually 40m to 2h30m)')).toBeInTheDocument();
    expect(
      screen.getByText('from 12 of your earlier jobs with the same command and argument pattern'),
    ).toBeInTheDocument();
  });

  it('gives a running job the time left', () => {
    render(
      <RuntimeEstimateView
        estimate={estimate({ elapsed_seconds: 600, remaining_seconds: 3600, p10_seconds: 2400 })}
        status={2}
      />,
    );
    expect(
      screen.getByText('About 1h left · running 10m of about 1h10m (usually 40m to 2h30m)'),
    ).toBeInTheDocument();
  });

  it('says a job has run longer than similar jobs, with no time left', () => {
    render(
      <RuntimeEstimateView
        estimate={estimate({ elapsed_seconds: 20000, exceeded_history: true, estimate_seconds: 3600 })}
        status={2}
      />,
    );
    expect(screen.getByText('Running longer than similar jobs (they took about 1h)')).toBeInTheDocument();
    expect(shown()).not.toMatch(/left|usually/);
  });

  it('renders nothing without an estimate', () => {
    const { container } = render(
      <RuntimeEstimateView
        estimate={{ job_id: '12.0', available: false, reason: 'model_warming_up', exceeded_history: false, model: { jobs_ingested: 0 } }}
        status={1}
      />,
    );
    expect(container).toBeEmptyDOMElement();
  });

  it('renders nothing for a job that is neither waiting nor running', () => {
    for (const status of [3, 4, 5, 6, 7, undefined]) {
      expect(runtimeEstimateText(estimate(), status)).toBeNull();
    }
    expect(runtimeEstimateText(undefined, 1)).toBeNull();
  });

  it('says "1 earlier job" for a single sample', () => {
    const t = runtimeEstimateText(estimate({ basis: { level: 'exact', sample_count: 1 } }), 1);
    expect(t?.sub).toBe('from 1 earlier job with the same command and arguments');
    const c = runtimeEstimateText(estimate({ basis: { level: 'cluster', sample_count: 1 } }), 2);
    expect(c?.sub).toBe('from 1 finished job in this cluster');
    const many = runtimeEstimateText(estimate({ basis: { level: 'cluster', sample_count: 40 } }), 2);
    expect(many?.sub).toBe('from 40 finished jobs in this cluster');
  });

  it('names every basis without a count where a count says nothing', () => {
    const sub = (level: RuntimeEstimateLevel) =>
      runtimeEstimateText(estimate({ basis: { level, sample_count: 7 } }), 1)?.sub;
    expect(sub('batch')).toBe('from 7 of your earlier jobs in the same batch');
    expect(sub('iwd')).toBe('from 7 of your earlier jobs from the same submit directory');
    expect(sub('cmd')).toBe('from 7 of your earlier jobs running the same program');
    expect(sub('owner')).toBe('from your recent jobs');
    expect(sub('global')).toBe('from recent jobs on this access point');
  });

  it('drops a range that would read as one figure', () => {
    const same = runtimeEstimateText(
      estimate({ estimate_seconds: 3600, p10_seconds: 3590, p90_seconds: 3610 }),
      1,
    );
    expect(same?.value).toBe('About 1h');
    // A range that starts at the estimate is still a range.
    const upward = runtimeEstimateText(
      estimate({ estimate_seconds: 3600, p10_seconds: 3600, p90_seconds: 7200 }),
      1,
    );
    expect(upward?.value).toBe('About 1h (usually 1h to 2h)');
  });

  it('never says a forbidden word', () => {
    const texts = [
      runtimeEstimateText(estimate(), 1),
      runtimeEstimateText(estimate({ elapsed_seconds: 60, remaining_seconds: 100 }), 2),
      runtimeEstimateText(estimate({ elapsed_seconds: 60, exceeded_history: true }), 2),
    ];
    for (const t of texts) {
      expect(`${t?.value} ${t?.sub}`).not.toMatch(/model|estimat|window|residual|level|percentile|p90|p10/i);
    }
  });
});

describe('approxDuration', () => {
  it('rounds to what an estimate can claim', () => {
    expect(approxDuration(45)).toBe('45s');
    expect(approxDuration(754)).toBe('13m');
    expect(approxDuration(4210)).toBe('1h10m');
    expect(approxDuration(93_000)).toBe('1d2h');
    expect(approxDuration(-5)).toBe('0s');
  });
});

describe('RuntimeEstimateField', () => {
  // Braces: a function returned from beforeEach is run as a teardown,
  // and mockReset returns the mock.
  beforeEach(() => {
    runtimeEstimate.mockReset();
  });

  let client: QueryClient;
  function renderField(status: number | undefined) {
    client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    return render(
      <QueryClientProvider client={client}>
        <div className="grid">
          <RuntimeEstimateField jobID="12.0" status={status} />
        </div>
      </QueryClientProvider>,
    );
  }

  it('fetches and shows the estimate for a waiting job', async () => {
    runtimeEstimate.mockResolvedValue(estimate());
    renderField(1);
    await waitFor(() => expect(screen.getByTestId('runtime-estimate')).toBeInTheDocument());
    expect(runtimeEstimate).toHaveBeenCalledWith('12.0');
  });

  it('does not ask for a job that is done', () => {
    renderField(4);
    expect(runtimeEstimate).not.toHaveBeenCalled();
    expect(screen.queryByTestId('runtime-estimate')).toBeNull();
  });

  it('shows nothing when the request fails', async () => {
    runtimeEstimate.mockRejectedValue(new Error('boom'));
    renderField(2);
    await waitFor(() =>
      expect(client.getQueryState(['runtime-estimate', '12.0'])?.status).toBe('error'),
    );
    expect(screen.queryByTestId('runtime-estimate')).toBeNull();
  });
});
