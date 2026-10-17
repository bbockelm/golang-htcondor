import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import { BatchMoreMemoryThanUsual, JobTimeLeftCell } from './TimeLeft';
import type { TimedJob } from '@/lib/timeLeft';

// The listing's memory chips as rendered: the job's carries the facts
// behind it on hover.

const now = Math.floor(new Date(2026, 9, 11, 13, 0, 0).getTime() / 1000);

const job = (above: boolean): TimedJob => ({
  status: 'running',
  estimate: {
    available: true,
    estimate_seconds: 3600,
    p10_seconds: 2400,
    p90_seconds: 9000,
    exceeded_history: false,
    elapsed_seconds: 600,
    remaining_seconds: 3000,
    memory: {
      sample_count: 9, p10_mib: 900, p25_mib: 1000, p50_mib: 1229, p75_mib: 1500, p90_mib: 2048,
      peak_mib: above ? 6246 : 1000, rough: false, above_usual: above,
    },
  },
});

describe('JobTimeLeftCell', () => {
  it('shows "More memory than usual" with its facts on hover', () => {
    render(<JobTimeLeftCell job={job(true)} scale={10_000} fetchedAt={now} now={now} />);
    expect(screen.getByText('More memory than usual')).toHaveAttribute(
      'title',
      'Peak so far 6.1 GB; similar jobs peak at about 1.2 GB, 9 in 10 under 2 GB',
    );
  });

  it('shows no chip for a job within its usual memory', () => {
    render(<JobTimeLeftCell job={job(false)} scale={10_000} fetchedAt={now} now={now} />);
    expect(screen.queryByText('More memory than usual')).not.toBeInTheDocument();
  });
});

describe('BatchMoreMemoryThanUsual', () => {
  it('counts the batch\'s jobs above usual, and is absent when there are none', () => {
    const { rerender, container } = render(<BatchMoreMemoryThanUsual jobs={[job(true), job(true), job(false)]} />);
    expect(screen.getByTestId('more-memory-than-usual')).toHaveTextContent('2 using more memory than usual');
    rerender(<BatchMoreMemoryThanUsual jobs={[job(false)]} />);
    expect(container).toBeEmptyDOMElement();
  });
});
