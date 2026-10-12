import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import { MetricChart } from './MetricChart';
import { RUN_COLORS, runColor, type MetricSeries } from '@/lib/metrics';

// A job restarted many times: one series per run, each a few samples long,
// one after another in time.
function runsSeries(runs: number): MetricSeries {
  return {
    key: 'memory',
    label: 'Memory',
    unit: 'MB',
    pointCount: runs * 2,
    executions: Array.from({ length: runs }, (_, i) => ({
      run: i + 1,
      points: [
        { t: 1_790_000_000 + i * 3600, value: 1000 + i },
        { t: 1_790_000_000 + i * 3600 + 900, value: 1100 + i },
      ],
    })),
  };
}

describe('runColor', () => {
  it('cycles through the palette so neighbouring runs always differ', () => {
    for (let i = 0; i < 100; i++) {
      expect(runColor(i)).not.toBe(runColor(i + 1));
      expect(runColor(i)).toBe(RUN_COLORS[i % RUN_COLORS.length]);
    }
  });
});

describe('MetricChart', () => {
  it('gives a 68-run job as many colours as the palette has, in turn', () => {
    const { container } = render(<MetricChart series={runsSeries(68)} />);
    const strokes = [...container.querySelectorAll('polyline')].map((p) => p.getAttribute('stroke'));
    expect(strokes).toHaveLength(68);
    expect(new Set(strokes).size).toBe(RUN_COLORS.length);
    for (let i = 1; i < strokes.length; i++) expect(strokes[i]).not.toBe(strokes[i - 1]);
  });

  it('names the run in every tooltip, since colours repeat', () => {
    const { container } = render(<MetricChart series={runsSeries(68)} />);
    const titles = [...container.querySelectorAll('circle > title')].map((t) => t.textContent ?? '');
    expect(titles.filter((t) => t.startsWith('Run 68 — '))).toHaveLength(2);
    expect(titles.filter((t) => t.startsWith('Run 7 — '))).toHaveLength(2);
  });

  // The legend's entries: the HTML spans after the chart, not the SVG titles.
  const legendEntries = (c: HTMLElement) => [...c.querySelectorAll('figure > div > span')].map((e) => e.textContent);

  it('replaces a 68-entry legend with one line', () => {
    const { container } = render(<MetricChart series={runsSeries(68)} />);
    expect(
      screen.getByText('68 runs (Run 1 to Run 68). Colors repeat every 6 runs; hover a point for its run.'),
    ).toBeInTheDocument();
    expect(legendEntries(container)).toEqual([]);
  });

  it('keeps a swatch per run while each run has its own colour', () => {
    const { container } = render(<MetricChart series={runsSeries(3)} />);
    expect(legendEntries(container)).toEqual(['Run 1', 'Run 2', 'Run 3']);
    expect(screen.queryByText(/Colors repeat/)).toBeNull();
  });
});
