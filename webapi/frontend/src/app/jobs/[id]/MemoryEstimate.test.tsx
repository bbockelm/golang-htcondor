import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import type { RuntimeMemory } from '@/lib/api';

import { MemoryEstimateView } from './MemoryEstimate';
import { memoryAxisMax, memoryCard, niceMiB, requestLine } from './memoryCard';
import { memoryLadder } from '@/lib/retryMemory';

// The job page's memory card: what similar jobs peaked at, the job's own
// peak, and how many went past its request -- stated as facts.

function mem(over: Partial<RuntimeMemory> = {}): RuntimeMemory {
  return {
    sample_count: 12,
    p10_mib: 900,
    p25_mib: 1000,
    p50_mib: 1229,
    p75_mib: 1500,
    p90_mib: 2048,
    rough: false,
    above_usual: false,
    ...over,
  };
}

describe('memoryCard', () => {
  it('tells a waiting job what similar jobs peak at, and how many went past its request', () => {
    const c = memoryCard(mem({ requested_mib: 2048, above_requested: 3, peak_mib: 50 }), 1)!;
    expect(c.headline).toBe('Similar jobs peak at about 1.2 GB');
    expect(c.axis.middle).toBe('usually 900 MB to 2 GB');
    expect(c.lines).toEqual(['3 of 12 similar jobs peaked above the 2 GB requested.']);
    // A waiting job has used nothing yet: no fill, whatever the ad says.
    expect(c.bar.elapsed).toBeUndefined();
    expect(c.above).toBe(false);
  });

  it('gives a running job its peak so far against similar jobs', () => {
    const c = memoryCard(mem({ peak_mib: 1100, requested_mib: 4096, above_requested: 0 }), 2)!;
    expect(c.headline).toBe('Peak so far 1.1 GB');
    expect(c.lines).toEqual([
      'Similar jobs peaked at about 1.2 GB; 9 in 10 stayed under 2 GB.',
      'All 12 similar jobs stayed under the 4 GB requested.',
    ]);
    expect(c.bar.elapsed).toBeCloseTo(1100 / memoryAxisMax(mem(), 1100, 4096));
    expect(c.above).toBe(false);
  });

  it('turns amber for a running job above usual, with the peak past the axis cut there', () => {
    const c = memoryCard(mem({ peak_mib: 60_000, above_usual: true }), 2)!;
    expect(c.above).toBe(true);
    expect(c.headline).toBe('Peak so far 58.6 GB');
    expect(c.bar.elapsedCapped).toBe(true);
    expect(c.axis.right).toBe('peak 58.6 GB');
  });

  it('draws the middle half and the request on the same axis', () => {
    const c = memoryCard(mem({ peak_mib: 1100, requested_mib: 4096, above_requested: 0 }), 2)!;
    const max = memoryAxisMax(mem(), 1100, 4096);
    expect(c.bar.box).toEqual({ from: 1000 / max, to: 1500 / max });
    expect(c.bar.refs).toEqual([{ at: 4096 / max, label: 'Requested' }]);
    // A request far past everything else is left off rather than squashing the rest.
    expect(memoryCard(mem({ requested_mib: 500_000, above_requested: 0 }), 1)!.bar.refs).toBeUndefined();
  });

  it('calls a finished job above usual when it was, and a waiting one never', () => {
    expect(memoryCard(mem({ peak_mib: 60_000, above_usual: true }), 4)!.above).toBe(true);
    expect(memoryCard(mem({ peak_mib: 1100, above_usual: false }), 4)!.above).toBe(false);
    expect(memoryCard(mem({ peak_mib: 60_000, above_usual: true }), 1)!.above).toBe(false);
  });

  it('compares a finished job\'s peak with similar jobs, and leaves its request out', () => {
    const c = memoryCard(mem({ peak_mib: 1500, requested_mib: 2048, above_requested: 3 }), 4)!;
    expect(c.headline).toBe('Peaked at 1.5 GB');
    expect(c.lines).toEqual(['Similar jobs peaked at about 1.2 GB; 9 in 10 stayed under 2 GB.']);
    expect(memoryCard(mem(), 4)!.headline).toBe('Similar jobs peaked at about 1.2 GB');
  });

  it('says roughly for a rough group', () => {
    const c = memoryCard(mem({ rough: true }), 1)!;
    expect(c.rough).toBe(true);
    expect(c.headline).toBe('Similar jobs peak at roughly 1.2 GB');
    expect(c.axis.middle).toBe('anywhere from 900 MB to 2 GB');
  });

  it('shows nothing without memory figures, or for a held job', () => {
    expect(memoryCard(undefined, 2)).toBeNull();
    expect(memoryCard(mem({ sample_count: 0 }), 2)).toBeNull();
    expect(memoryCard(mem(), 5)).toBeNull();
  });
});

describe('requestLine', () => {
  it('counts the similar jobs past the request', () => {
    expect(requestLine(mem({ requested_mib: 1024, above_requested: 12 }))).toBe(
      'All 12 similar jobs peaked above the 1 GB requested.',
    );
    expect(requestLine(mem({ sample_count: 1, requested_mib: 1024, above_requested: 0 }))).toBe(
      'The one similar job stayed under the 1 GB requested.',
    );
    expect(requestLine(mem())).toBeUndefined();
  });
});

describe('niceMiB', () => {
  it('ends the axis on a round figure', () => {
    expect(niceMiB(10)).toBe(128);
    expect(niceMiB(1100)).toBe(1536);
    expect(niceMiB(2048)).toBe(2048);
    expect(niceMiB(200_000)).toBe(262_144);
  });
});

describe('MemoryEstimateView', () => {
  it('renders the amber chip and the rough label like the run time card', () => {
    const { rerender } = render(<MemoryEstimateView memory={mem({ peak_mib: 6246, above_usual: true })} status={2} />);
    const card = screen.getByTestId('memory-estimate');
    expect(card).toHaveTextContent('Peak memory');
    expect(card).toHaveTextContent('More memory than usual');
    expect(card).toHaveTextContent('Peak so far 6.1 GB');
    expect(card.className).toContain('border-amber-300');
    rerender(<MemoryEstimateView memory={mem({ rough: true })} status={1} />);
    expect(screen.getByTestId('memory-estimate')).toHaveTextContent('rough guess');
    expect(screen.getByTestId('memory-estimate')).not.toHaveTextContent('More memory than usual');
  });

  it('renders nothing without figures', () => {
    const { container } = render(<MemoryEstimateView memory={undefined} status={2} />);
    expect(container).toBeEmptyDOMElement();
  });
});

// The reported case (12428255.40559): the card drew "Requested" at the
// rung the job finished on, which reads as the size it asked for from
// the start.
describe('a job on a memory retry ladder', () => {
  const climber = (over: Record<string, unknown> = {}) =>
    memoryLadder({
      RequestMemory: 8192,
      RetryRequestMemory: [2048, 4096, 8192, 16384, 32768, 65536],
      RetryRequestMemoryIndex: 3,
      TransformOnEvict: 'RequestMemory RetryRequestMemoryIndex',
      ...over,
    } as never);

  it('says the request it draws is where the job ended up', () => {
    const c = memoryCard(mem({ peak_mib: 7000, requested_mib: 8192 }), 4, climber())!;
    expect(c.lines).toContain(
      'The 8 GB requested is where it ended up: it ran out of memory and started again at a larger request 3 times.',
    );
  });

  it('keeps the line after what similar jobs did, not before it', () => {
    const c = memoryCard(mem({ peak_mib: 7000, requested_mib: 8192 }), 4, climber())!;
    expect(c.lines[0]).toMatch(/^Similar jobs peaked/);
    expect(c.lines[1]).toMatch(/^The 8 GB requested is/);
  });

  it('leaves the count open where the index stops counting', () => {
    const c = memoryCard(
      mem({ peak_mib: 60000, requested_mib: 65536 }),
      4,
      climber({ RequestMemory: 65536, RetryRequestMemoryIndex: 5 }),
    )!;
    expect(c.lines[1]).toMatch(/started again at a larger request at least 5 times\.$/);
  });

  it('says nothing for a ladder the job never had to climb', () => {
    const c = memoryCard(
      mem({ peak_mib: 1100, requested_mib: 2048 }),
      4,
      climber({ RequestMemory: 2048, RetryRequestMemoryIndex: undefined }),
    )!;
    expect(c.lines.join(' ')).not.toMatch(/started again/);
  });

  it('says nothing for a job without a ladder', () => {
    const c = memoryCard(mem({ peak_mib: 1100, requested_mib: 2048 }), 4)!;
    expect(c.lines).toEqual(['Similar jobs peaked at about 1.2 GB; 9 in 10 stayed under 2 GB.']);
  });

  it('reaches the page', () => {
    render(
      <MemoryEstimateView
        memory={mem({ peak_mib: 7000, requested_mib: 8192 })}
        status={4}
        job={
          {
            RequestMemory: 8192,
            RetryRequestMemory: [2048, 4096, 8192, 16384, 32768, 65536],
            RetryRequestMemoryIndex: 2,
            TransformOnEvict: 'RequestMemory RetryRequestMemoryIndex',
          } as never
        }
      />,
    );
    expect(
      screen.getByText(/it ran out of memory and started again at a larger request 2 times\./),
    ).toBeInTheDocument();
  });
});
