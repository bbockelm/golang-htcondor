import { fireEvent, render, screen, within } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import { MemoryEstimateView } from '@/app/jobs/[id]/MemoryEstimate';
import { RuntimeEstimateView } from '@/app/jobs/[id]/RuntimeEstimate';
import type { RuntimeEstimate, RuntimeMemory } from '@/lib/api';

import { chartEntries, HowToRead, LEGEND_TEXT, RangeLegend } from './RangeLegend';
import { RangePlot, RANGE_TOKENS } from './RangePlot';
import { MemorySpread, RuntimeSpread } from './SimilarJobs';

// One way of drawing a job against its similar jobs, wherever it is
// drawn, and the "How to read" key that names its marks.

const part = (root: HTMLElement, name: string) => root.querySelector(`[data-part="${name}"]`) as HTMLElement | null;

describe('RangePlot', () => {
  it('draws each mark only when it is given', () => {
    render(<RangePlot testID="p" />);
    const bare = screen.getByTestId('p');
    expect(part(bare, 'track')).toBeInTheDocument();
    for (const name of ['band', 'box', 'tick', 'job', 'job-end', 'ref', 'ref-label']) {
      expect(part(bare, name)).toBeNull();
    }
  });

  it('places the band, the box inside it, the tick, the job and a labelled request', () => {
    render(
      <RangePlot
        testID="p"
        band={{ from: 0.2, to: 0.6 }}
        box={{ from: 0.3, to: 0.5 }}
        tick={0.4}
        job={0.7}
        refs={[{ at: 0.9, label: 'Requested' }]}
      />,
    );
    const p = screen.getByTestId('p');
    expect(part(p, 'band')).toHaveStyle({ left: '20.00%', width: '40.00%' });
    expect(part(p, 'band')).toHaveClass(RANGE_TOKENS.band);
    expect(part(p, 'box')).toHaveClass(RANGE_TOKENS.box);
    expect(parseFloat(part(p, 'box')!.style.left)).toBe(30);
    expect(part(p, 'tick')).toHaveClass(RANGE_TOKENS.tick);
    expect(part(p, 'tick')).toHaveStyle({ left: '40.00%' });
    expect(part(p, 'job')).toHaveStyle({ width: '70.00%' });
    expect(part(p, 'job')).toHaveClass(RANGE_TOKENS.job);
    expect(part(p, 'job-end')).toHaveStyle({ left: '70.00%' });
    expect(part(p, 'ref')).toHaveClass('border-dashed', RANGE_TOKENS.ref);
    expect(part(p, 'ref-label')).toHaveTextContent('Requested');
    expect(p).toHaveAttribute('aria-hidden', 'true');
  });

  it('turns the job amber when it is unusual', () => {
    render(<RangePlot testID="p" tick={0.3} job={0.8} unusual />);
    const p = screen.getByTestId('p');
    expect(part(p, 'job')).toHaveClass(RANGE_TOKENS.jobUnusual);
    expect(part(p, 'job-end')).toHaveClass(RANGE_TOKENS.jobUnusual);
    expect(part(p, 'job')).not.toHaveClass(RANGE_TOKENS.job);
  });

  it('hatches a rough guess and greys its tick', () => {
    render(<RangePlot testID="p" band={{ from: 0.1, to: 0.9 }} tick={0.5} rough />);
    const p = screen.getByTestId('p');
    expect(part(p, 'band')!.style.backgroundImage).toContain('repeating-linear-gradient');
    expect(part(p, 'band')).not.toHaveClass(RANGE_TOKENS.band);
    expect(part(p, 'tick')).toHaveClass(RANGE_TOKENS.tickRough);
  });

  it('cuts a job past the axis at its end, with no end dot', () => {
    render(<RangePlot testID="p" tick={0.3} job={1} jobCapped />);
    expect(part(screen.getByTestId('p'), 'job')).toHaveStyle({ width: '100.00%' });
    expect(part(screen.getByTestId('p'), 'job-end')).toBeNull();
  });
});

// The cards and the similar-jobs plots draw the same marks the same way.
describe('one encoding', () => {
  const mem: RuntimeMemory = {
    sample_count: 9, p10_mib: 900, p25_mib: 1000, p50_mib: 1229, p75_mib: 1500, p90_mib: 2048,
    peak_mib: 6246, requested_mib: 4096, above_requested: 0, rough: false, above_usual: true,
  };

  it('gives the memory card and the memory plot the same marks and colours', () => {
    render(<MemoryEstimateView memory={mem} status={2} />);
    render(<MemorySpread memory={{ count: 9, p10: 900, p25: 1000, p50: 1229, p75: 1500, p90: 2048 }} mark={{ mib: 6246, label: 'This job so far', unusual: true }} requestedMiB={4096} />);
    const card = screen.getByTestId('memory-range-bar');
    const plot = screen.getByTestId('memory-spread-plot');
    for (const name of ['band', 'box', 'tick', 'job', 'job-end', 'ref']) {
      expect(part(card, name)!.className, name).toBe(part(plot, name)!.className);
    }
    expect(part(card, 'job')).toHaveClass(RANGE_TOKENS.jobUnusual);
  });

  it('gives the run time card and the run time plot the same job and typical marks', () => {
    const r: RuntimeEstimate = {
      job_id: '1.0', available: true, estimate_seconds: 3600, p10_seconds: 2400, p90_seconds: 9000,
      basis: { level: 'template', sample_count: 12 }, elapsed_seconds: 600, remaining_seconds: 3000,
      exceeded_history: false, model: { jobs_ingested: 1 },
    };
    render(<RuntimeEstimateView estimate={r} status={2} fetchedAt={1_760_000_000} />);
    render(<RuntimeSpread runtimes={{ count: 9, p10: 2400, p25: 3000, p50: 3600, p75: 4200, p90: 9000 }} mark={{ seconds: 600, label: 'This job so far', unusual: false }} />);
    const card = screen.getByTestId('runtime-range-bar');
    const plot = screen.getByTestId('runtime-spread-plot');
    for (const name of ['band', 'tick', 'job', 'job-end']) {
      expect(part(card, name)!.className, name).toBe(part(plot, name)!.className);
    }
    // Only the plot knows the middle half.
    expect(part(card, 'box')).toBeNull();
    expect(part(plot, 'box')).toBeInTheDocument();
  });
});

describe('the legend', () => {
  it('lists each chart\'s marks, and only those', () => {
    expect(chartEntries({ job: true, canBeUnusual: true })).toEqual(['band', 'tick', 'job', 'jobUnusual']);
    expect(chartEntries({ rough: true })).toEqual(['rough']);
    expect(chartEntries({ box: true, job: true, requested: true })).toEqual(['band', 'tick', 'box', 'job', 'requested']);
  });

  it('names every mark in the user\'s terms', () => {
    render(<RangeLegend entries={['band', 'box', 'tick', 'job', 'jobUnusual', 'rough', 'requested']} />);
    const items = within(screen.getByTestId('range-legend')).getAllByRole('listitem');
    expect(items.map((li) => li.textContent)).toEqual([
      'Most similar jobs', 'Half of similar jobs', 'Typical', 'Rough guess', 'This job', 'This job, unusually high', 'Requested',
    ]);
    // The swatches use the chart's own colours.
    expect(items[0].querySelector(`.${CSS.escape(RANGE_TOKENS.band)}`)).toBeInTheDocument();
    expect(items[5].querySelector(`.${CSS.escape(RANGE_TOKENS.jobUnusual)}`)).toBeInTheDocument();
    for (const text of Object.values(LEGEND_TEXT)) {
      expect(text).not.toMatch(/percentile|estimat|window|level|median/i);
    }
  });

  it('opens and closes in place from its toggle', () => {
    render(<HowToRead entries={['band', 'tick']} />);
    const button = screen.getByRole('button', { name: 'How to read' });
    expect(button).toHaveAttribute('aria-expanded', 'false');
    expect(screen.queryByTestId('range-legend')).toBeNull();
    fireEvent.click(button);
    expect(button).toHaveAttribute('aria-expanded', 'true');
    const legend = screen.getByTestId('range-legend');
    expect(button).toHaveAttribute('aria-controls', legend.id);
    expect(within(legend).getAllByRole('listitem')).toHaveLength(2);
    fireEvent.click(button);
    expect(screen.queryByTestId('range-legend')).toBeNull();
  });

  it('keys each chart to what it draws', () => {
    // A running job's run time card: no middle half, no request.
    const r: RuntimeEstimate = {
      job_id: '1.0', available: true, estimate_seconds: 3600, p10_seconds: 2400, p90_seconds: 9000,
      basis: { level: 'template', sample_count: 12 }, elapsed_seconds: 600, remaining_seconds: 3000,
      exceeded_history: false, model: { jobs_ingested: 1 },
    };
    const { unmount } = render(<RuntimeEstimateView estimate={r} status={2} fetchedAt={1_760_000_000} />);
    fireEvent.click(screen.getByRole('button', { name: 'How to read' }));
    expect(within(screen.getByTestId('range-legend')).getAllByRole('listitem').map((li) => li.textContent)).toEqual([
      'Most similar jobs', 'Typical', 'This job', 'This job, unusually high',
    ]);
    unmount();
    // A finished job's memory plot: the middle half and the request, but
    // never an unusual job.
    render(<MemorySpread memory={{ count: 9, p10: 900, p25: 1000, p50: 1229, p75: 1500, p90: 2048 }} mark={{ mib: 1300, label: 'This job' }} requestedMiB={4096} />);
    fireEvent.click(screen.getByRole('button', { name: 'How to read' }));
    expect(within(screen.getByTestId('range-legend')).getAllByRole('listitem').map((li) => li.textContent)).toEqual([
      'Most similar jobs', 'Half of similar jobs', 'Typical', 'This job', 'Requested',
    ]);
  });
});
