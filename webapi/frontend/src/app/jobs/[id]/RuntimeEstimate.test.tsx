import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
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

import { RuntimeEstimateField, RuntimeEstimateView } from './RuntimeEstimate';
import {
  axisMax,
  barGeometry,
  basisLine,
  clockRange,
  clockTime,
  niceDuration,
  runtimeCard,
  type RuntimeCard,
} from './runtimeCard';

// Local wall-clock times, so the clock strings do not depend on the
// machine's time zone. 3:10 PM on a Sunday.
const at = (h: number, m = 0, day = 11) => Math.floor(new Date(2026, 9, day, h, m).getTime() / 1000);
const NOW = at(15, 10);
const L = 'en-US';
// The clock strings use non-breaking spaces; compare them as plain ones.
const plain = (s: string | undefined) => s?.replace(/\s/g, ' ');

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

const runningEstimate = (over: Partial<RuntimeEstimate> = {}) =>
  estimate({
    estimate_seconds: 3600,
    elapsed_seconds: 600,
    remaining_seconds: 3000,
    basis: { level: 'cluster', sample_count: 64 },
    ...over,
  });

const longEstimate = (over: Partial<RuntimeEstimate> = {}) =>
  estimate({
    estimate_seconds: 3600,
    p10_seconds: 1200,
    p90_seconds: 9000,
    elapsed_seconds: 3 * 3600 + 12 * 60,
    exceeded_history: true,
    basis: { level: 'cluster', sample_count: 64 },
    ...over,
  });

const roughEstimate = (over: Partial<RuntimeEstimate> = {}) =>
  estimate({
    rough: true,
    estimate_seconds: 7200,
    p10_seconds: 900,
    p90_seconds: 21600,
    basis: { level: 'owner', sample_count: 40, new_command: true },
    ...over,
  });

function card(r: RuntimeEstimate | undefined, status: number | undefined): RuntimeCard {
  const c = runtimeCard(r, status, NOW, L);
  if (!c) throw new Error('no card');
  return { ...c, headline: plain(c.headline)!, axis: { left: plain(c.axis.left)!, middle: plain(c.axis.middle), right: plain(c.axis.right)! } };
}

describe('niceDuration and axisMax', () => {
  it('ends the axis on a round figure past the usual range', () => {
    expect(niceDuration(0)).toBe(60);
    expect(niceDuration(10800)).toBe(10800);
    expect(niceDuration(10801)).toBe(14400);
    expect(niceDuration(30 * 86400)).toBe(5 * 604800);
    // 2h30m usual top, x1.2 = 3h.
    expect(axisMax({ estimate_seconds: 4200, p90_seconds: 9000 })).toBe(10800);
    // Reaches past a job running long: 3h12m x1.2 = 3h50m -> 4h.
    expect(axisMax({ estimate_seconds: 3600, p90_seconds: 9000, elapsed_seconds: 11520 })).toBe(14400);
  });

  it('stops reaching for a job far past the usual range', () => {
    // 4 x 2h30m = 10h, x1.2 = 12h, however long it has run.
    expect(axisMax({ estimate_seconds: 3600, p90_seconds: 9000, elapsed_seconds: 100 * 3600 })).toBe(43200);
  });

  it('copes with no range and a zero estimate', () => {
    expect(axisMax({ estimate_seconds: 0 })).toBe(60);
    expect(axisMax({ estimate_seconds: 3000 })).toBe(3600);
  });
});

describe('barGeometry', () => {
  it('places the band and tick in proportion', () => {
    const g = barGeometry(estimate(), 10800, false);
    expect(g.band?.from).toBeCloseTo(2400 / 10800);
    expect(g.band?.to).toBeCloseTo(9000 / 10800);
    expect(g.tick).toBeCloseTo(4200 / 10800);
    expect(g.elapsed).toBeUndefined();
  });

  it('draws no band for a range that is one figure, or none', () => {
    expect(barGeometry(estimate({ p10_seconds: 3590, p90_seconds: 3610 }), 7200, false).band).toBeUndefined();
    expect(barGeometry(estimate({ p10_seconds: undefined }), 7200, false).band).toBeUndefined();
    expect(barGeometry(estimate({ estimate_seconds: 0, p10_seconds: undefined, p90_seconds: undefined }), 60, false)).toEqual({ tick: 0 });
  });

  it('fills the elapsed time for a running job, cut at the end of the axis', () => {
    expect(barGeometry(runningEstimate(), 10800, true).elapsed).toBeCloseTo(600 / 10800);
    const far = barGeometry(longEstimate({ elapsed_seconds: 100 * 3600 }), 43200, true);
    expect(far.elapsed).toBe(1);
    expect(far.elapsedCapped).toBe(true);
    // Not for a waiting job, whatever the response carries.
    expect(barGeometry(runningEstimate(), 10800, false).elapsed).toBeUndefined();
  });
});

describe('clock times', () => {
  it('says a time today without a day', () => {
    expect(plain(clockTime(at(15, 40), NOW, L))).toBe('3:40 PM');
  });

  it('adds the weekday this week and the date after that', () => {
    expect(plain(clockTime(at(9, 30, 12), NOW, L))).toBe('Mon 9:30 AM');
    expect(plain(clockTime(at(9, 30, 20), NOW, L))).toBe('Oct 20, 9:30 AM');
  });

  it('rounds a time more than an hour out to five minutes', () => {
    expect(plain(clockTime(at(17, 32), NOW, L))).toBe('5:30 PM');
    expect(plain(clockTime(at(15, 32), NOW, L))).toBe('3:32 PM');
  });

  it('writes a range once where its ends share a day and half', () => {
    expect(plain(clockRange(at(15, 40), at(17, 30), NOW, L))).toBe('3:40 to 5:30 PM');
    expect(plain(clockRange(at(11, 40), at(13, 30), NOW, L))).toBe('11:40 AM to 1:30 PM');
    expect(plain(clockRange(at(9, 0, 12), at(11, 0, 12), NOW, L))).toBe('Mon 9:00 to 11:00 AM');
    expect(plain(clockRange(at(23, 0), at(1, 0, 12), NOW, L))).toBe('11:00 PM to Mon 1:00 AM');
  });
});

describe('runtimeCard', () => {
  it('gives a waiting job its run time, range and basis', () => {
    expect(card(estimate(), 1)).toEqual({
      longer: false,
      rough: false,
      headline: 'About 1h10m once it starts',
      bar: expect.objectContaining({ band: expect.any(Object) }),
      axis: { left: '0', middle: 'usually 40m to 2h30m', right: '3h' },
      lines: [
        'From 12 of your earlier jobs with the same command and argument pattern. Time spent waiting to start depends on the pool and is not included.',
      ],
      actions: false,
      // The basis on its own, for the view to link to those jobs.
      basis: 'From 12 of your earlier jobs with the same command and argument pattern.',
    });
  });

  it('gives a running job the time left and when it is likely done', () => {
    const c = card(runningEstimate(), 2);
    expect(c.headline).toBe('About 50m left · likely done around 4:00 PM');
    expect(c.axis).toEqual({ left: 'started 3:00 PM', middle: 'usually done 3:40 to 5:30 PM', right: '6:00 PM' });
    expect(c.lines).toEqual(['Running 10m of about 1h. From 64 finished jobs in this cluster.']);
    expect(c.bar.elapsed).toBeCloseTo(600 / 10800);
  });

  it('dates a finish that is not today', () => {
    const late = runtimeCard(runningEstimate({ remaining_seconds: 12 * 3600 }), 2, NOW, L)!;
    expect(plain(late.headline)).toBe('About 12h left · likely done around Mon 3:10 AM');
  });

  it('says a job has run longer than similar jobs', () => {
    const c = card(longEstimate(), 2);
    expect(c.longer).toBe(true);
    expect(c.actions).toBe(true);
    expect(c.headline).toBe('Similar jobs took about 1h, nearly all under 2h30m');
    expect(c.axis).toEqual({ left: '0', middle: 'now: 3h12m', right: '4h' });
    expect(c.lines).toEqual([
      'It may be stuck, or this input may need more work than usual.',
      'From 64 finished jobs in this cluster.',
    ]);
  });

  it('keeps the elapsed label truthful when the bar is cut short', () => {
    const c = card(longEstimate({ elapsed_seconds: 30 * 3600 }), 2);
    expect(c.axis).toEqual({ left: '0', right: 'now: 1d6h' });
    expect(c.bar.elapsedCapped).toBe(true);
  });

  it('drops "nearly all under" when there is no top to the range', () => {
    expect(card(longEstimate({ p90_seconds: undefined }), 2).headline).toBe('Similar jobs took about 1h');
  });

  it('calls a rough estimate a rough guess, waiting or running', () => {
    const idle = card(roughEstimate(), 1);
    expect(idle.rough).toBe(true);
    expect(idle.headline).toBe('Roughly 2h');
    expect(idle.axis).toEqual({ left: '0', middle: 'anywhere from 15m to 6h', right: '8h' });
    expect(idle.lines).toEqual([
      'This command has not run recently. Based on your recent jobs in general. Time spent waiting to start depends on the pool and is not included.',
    ]);
    const running = card(roughEstimate({ elapsed_seconds: 600, remaining_seconds: 6600 }), 2);
    expect(running.headline).toBe('Roughly 1h50m left · perhaps done around 5:00 PM');
    expect(running.axis).toEqual({ left: 'started 3:00 PM', middle: 'done anywhere from 3:15 to 9:00 PM', right: '11:00 PM' });
    expect(running.lines).toEqual([
      'Running 10m of roughly 2h. This command has not run recently. Based on your recent jobs in general.',
    ]);
    const long = card(roughEstimate({ elapsed_seconds: 30000, exceeded_history: true }), 2);
    expect(long.longer && long.rough).toBe(true);
    expect(long.headline).toBe('Similar jobs took roughly 2h, nearly all under 6h');
  });

  it('drops a range that would read as one figure', () => {
    const same = card(estimate({ estimate_seconds: 3600, p10_seconds: 3590, p90_seconds: 3610 }), 1);
    expect(same.axis.middle).toBeUndefined();
    expect(same.bar.band).toBeUndefined();
    const running = card(runningEstimate({ p10_seconds: undefined, p90_seconds: undefined }), 2);
    expect(running.axis.middle).toBeUndefined();
  });

  it('shows nothing without an estimate or for a job neither waiting nor running', () => {
    for (const status of [3, 4, 5, 6, 7, undefined]) {
      expect(runtimeCard(estimate(), status, NOW)).toBeNull();
    }
    expect(runtimeCard(undefined, 1, NOW)).toBeNull();
    expect(runtimeCard(estimate({ available: false }), 1, NOW)).toBeNull();
    for (const status of [1, 2]) {
      const none: RuntimeEstimate = { job_id: '12.0', available: false, reason: 'insufficient_history', exceeded_history: false, model: { jobs_ingested: 500 } };
      expect(runtimeCard(none, status, NOW)).toBeNull();
    }
    expect(runtimeCard(estimate({ estimate_seconds: undefined }), 2, NOW)).toBeNull();
  });

  it('never says a forbidden word', () => {
    const cards = [
      card(estimate(), 1),
      card(runningEstimate(), 2),
      card(longEstimate(), 2),
      card(roughEstimate(), 1),
      card(roughEstimate({ basis: { level: 'owner', sample_count: 300, new_command: true } }), 1),
      card(roughEstimate({ elapsed_seconds: 600, remaining_seconds: 6600 }), 2),
    ];
    for (const c of cards) {
      const all = [c.headline, c.axis.left, c.axis.middle, c.axis.right, ...c.lines].join(' ');
      expect(all).not.toMatch(/model|estimat|window|residual|level|percentile|p90|p10/i);
    }
  });
});

describe('basisLine', () => {
  it('says "1 earlier job" for a single sample', () => {
    expect(basisLine({ level: 'exact', sample_count: 1 })).toBe('from 1 earlier job with the same command and arguments');
    expect(basisLine({ level: 'cluster', sample_count: 1 })).toBe('from 1 finished job in this cluster');
    expect(basisLine({ level: 'cluster', sample_count: 40 })).toBe('from 40 finished jobs in this cluster');
  });

  it('names every basis without a count where a count says nothing', () => {
    const sub = (level: RuntimeEstimateLevel) => basisLine({ level, sample_count: 7 });
    expect(sub('batch')).toBe('from 7 of your earlier jobs in the same batch');
    expect(sub('iwd')).toBe('from 7 of your earlier jobs from the same submit directory');
    expect(sub('cmd')).toBe('from 7 of your earlier jobs running the same program');
    expect(sub('owner')).toBe('Based on your recent jobs in general.');
    // A level this page does not know says nothing rather than guess.
    expect(sub('global' as unknown as RuntimeEstimateLevel)).toBeUndefined();
    expect(basisLine({ level: 'owner', sample_count: 7, new_command: true })).toBe(
      'This command has not run recently. Based on your recent jobs in general.',
    );
  });
});

describe('RuntimeEstimateView', () => {
  const view = (r: RuntimeEstimate | undefined, status: number | undefined, actions = {}) =>
    render(<RuntimeEstimateView estimate={r} status={status} fetchedAt={NOW} locale={L} {...actions} />);
  const shown = () => plain(screen.getByTestId('runtime-estimate').textContent ?? '')!;

  it('shows a waiting job its card', () => {
    view(estimate(), 1);
    expect(screen.getByRole('heading', { name: 'Expected run time' })).toBeInTheDocument();
    expect(screen.getByText('About 1h10m once it starts')).toBeInTheDocument();
    expect(screen.getByText('usually 40m to 2h30m')).toBeInTheDocument();
    expect(screen.getByText(/^From 12 of your earlier jobs/)).toBeInTheDocument();
    const bar = screen.getByTestId('runtime-range-bar');
    expect(bar).toHaveAttribute('aria-hidden', 'true');
    expect(bar.querySelector('[data-part="band"]')).toHaveStyle({ left: '22.22%', width: '61.11%' });
    expect(bar.querySelector('[data-part="tick"]')).toHaveStyle({ left: '38.89%' });
    expect(bar.querySelector('[data-part="elapsed"]')).toBeNull();
    expect(screen.queryByText('rough guess')).toBeNull();
    expect(screen.queryByText('Longer than usual')).toBeNull();
  });

  it('shows a running job its time left and clock times', () => {
    view(runningEstimate(), 2);
    expect(shown()).toContain('About 50m left · likely done around 4:00 PM');
    expect(shown()).toContain('started 3:00 PM');
    expect(shown()).toContain('usually done 3:40 to 5:30 PM');
    expect(screen.getByText('Running 10m of about 1h. From 64 finished jobs in this cluster.')).toBeInTheDocument();
    const fill = screen.getByTestId('runtime-range-bar').querySelector('[data-part="elapsed"]');
    expect(fill).toHaveClass('bg-green-700');
    expect(fill).toHaveStyle({ width: '5.56%' });
    const now = screen.getByTestId('runtime-range-bar').querySelector('[data-part="now"]');
    expect(now).toHaveClass('bg-green-700');
    expect(now).toHaveStyle({ left: '5.56%' });
  });

  it('marks a job running longer than usual and offers a look inside', () => {
    const onViewOutput = vi.fn();
    const onOpenShell = vi.fn();
    view(longEstimate(), 2, { onViewOutput, onOpenShell });
    const c = screen.getByTestId('runtime-estimate');
    expect(c).toHaveClass('border-amber-300');
    expect(within(c).getByText('Longer than usual')).toBeInTheDocument();
    expect(within(c).getByText('Similar jobs took about 1h, nearly all under 2h30m')).toBeInTheDocument();
    expect(within(c).getByText('now: 3h12m')).toBeInTheDocument();
    expect(within(c).getByText('It may be stuck, or this input may need more work than usual.')).toBeInTheDocument();
    // Over the band, not under it: the comparison is where they overlap.
    const band = c.querySelector('[data-part="band"]')!;
    const fill = c.querySelector('[data-part="elapsed"]')!;
    expect(fill).toHaveClass('bg-amber-600', 'z-10');
    expect(band).not.toHaveClass('z-10');
    expect(band.compareDocumentPosition(fill) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(c.querySelector('[data-part="now"]')).toHaveClass('bg-amber-600');
    fireEvent.click(screen.getByRole('button', { name: 'View live output' }));
    fireEvent.click(screen.getByRole('button', { name: 'Open a shell in the job' }));
    expect(onViewOutput).toHaveBeenCalledOnce();
    expect(onOpenShell).toHaveBeenCalledOnce();
  });

  it('ends a fill cut at the axis without a mark for now', () => {
    view(longEstimate({ elapsed_seconds: 30 * 3600 }), 2);
    const bar = screen.getByTestId('runtime-range-bar');
    expect(bar.querySelector('[data-part="elapsed"]')).toHaveStyle({ width: '100.00%' });
    expect(bar.querySelector('[data-part="now"]')).toBeNull();
    expect(screen.getByText('now: 1d6h')).toBeInTheDocument();
  });

  it('offers only the actions the page has', () => {
    view(longEstimate(), 2, { onViewOutput: () => {} });
    expect(screen.getByRole('button', { name: 'View live output' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Open a shell in the job' })).toBeNull();
  });

  it('offers no actions to a job within its usual time', () => {
    view(runningEstimate(), 2, { onViewOutput: () => {}, onOpenShell: () => {} });
    expect(screen.queryByRole('button')).toBeNull();
  });

  it('shows a rough guess hatched and grey', () => {
    view(roughEstimate(), 1);
    expect(screen.getByText('rough guess')).toBeInTheDocument();
    expect(shown()).toContain('Roughly 2h');
    expect(screen.getByText('anywhere from 15m to 6h')).toBeInTheDocument();
    const bar = screen.getByTestId('runtime-range-bar');
    expect((bar.querySelector('[data-part="band"]') as HTMLElement).style.backgroundImage).toContain(
      'repeating-linear-gradient',
    );
    expect(bar.querySelector('[data-part="tick"]')).toHaveClass('bg-gray-500');
  });

  it('shows a running rough guess with its elapsed fill', () => {
    view(roughEstimate({ elapsed_seconds: 600, remaining_seconds: 6600 }), 2);
    expect(screen.getByText('rough guess')).toBeInTheDocument();
    expect(shown()).toContain('Roughly 1h50m left · perhaps done around 5:00 PM');
    const bar = screen.getByTestId('runtime-range-bar');
    expect((bar.querySelector('[data-part="band"]') as HTMLElement).style.backgroundImage).toContain(
      'repeating-linear-gradient',
    );
    expect(bar.querySelector('[data-part="elapsed"]')).toHaveClass('bg-green-700');
  });

  it('renders nothing without an estimate or for other states', () => {
    const { container, rerender } = view(
      { job_id: '12.0', available: false, reason: 'model_warming_up', exceeded_history: false, model: { jobs_ingested: 0 } },
      1,
    );
    expect(container).toBeEmptyDOMElement();
    for (const status of [1, 2]) {
      rerender(
        <RuntimeEstimateView
          estimate={{ job_id: '12.0', available: false, reason: 'insufficient_history', exceeded_history: false, model: { jobs_ingested: 500 } }}
          status={status}
          fetchedAt={NOW}
        />,
      );
      expect(container).toBeEmptyDOMElement();
    }
    for (const status of [3, 4, 5, 6, 7, undefined]) {
      rerender(<RuntimeEstimateView estimate={estimate()} status={status} fetchedAt={NOW} />);
      expect(container).toBeEmptyDOMElement();
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
        <RuntimeEstimateField jobID="12.0" status={status} />
      </QueryClientProvider>,
    );
  }

  it('fetches and shows the estimate for a waiting job', async () => {
    runtimeEstimate.mockResolvedValue(estimate());
    renderField(1);
    await waitFor(() => expect(screen.getByTestId('runtime-estimate')).toBeInTheDocument());
    expect(screen.getByText('About 1h10m once it starts')).toBeInTheDocument();
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
