import { fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import type { DisplayStatus } from '@/lib/api';
import { JobStatusStrip } from './JobStatusStrip';

const counts = { running: 3, idle: 2, held: 1 } as Record<DisplayStatus, number>;

function strip(selected: DisplayStatus[] = [], onToggle = vi.fn(), onClear = vi.fn()) {
  render(
    <JobStatusStrip
      counts={counts}
      selected={new Set(selected)}
      onToggle={onToggle}
      onClear={onClear}
      total={6}
    />,
  );
  return { onToggle, onClear };
}

describe('JobStatusStrip', () => {
  it('shows every status that has jobs, with its count', () => {
    strip();
    expect(screen.getByRole('button', { name: /Running, 3 jobs/ })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Idle, 2 jobs/ })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Held, 1 job/ })).toBeInTheDocument();
  });

  it('reads as "showing everything" until something is selected', () => {
    strip();
    // The All chip is the pressed one, so an unfiltered strip does not
    // look like a filter that happens to match everything.
    expect(screen.getByRole('button', { name: /All statuses/ })).toHaveAttribute(
      'aria-pressed',
      'true',
    );
    expect(screen.getByRole('button', { name: /Running, 3 jobs/ })).toHaveAttribute(
      'aria-pressed',
      'false',
    );
    // Nothing to clear yet.
    expect(screen.queryByRole('button', { name: 'clear' })).toBeNull();
  });

  it('asks to show ONLY that status on the first click', () => {
    // The whole point of the strip: one click on Running gets you the
    // running jobs. Chips that started switched on would make that
    // first click switch Running off instead.
    const { onToggle } = strip();
    fireEvent.click(screen.getByRole('button', { name: /Running, 3 jobs/ }));
    expect(onToggle).toHaveBeenCalledWith('running');
  });

  it('keeps a selected chip on screen after its jobs drain away', () => {
    // Filtering to Held and then releasing the last held job must not
    // leave an empty table with no control to undo the filter.
    render(
      <JobStatusStrip
        counts={{ running: 3 } as Record<DisplayStatus, number>}
        selected={new Set<DisplayStatus>(['held'])}
        onToggle={vi.fn()}
        onClear={vi.fn()}
        total={3}
      />,
    );
    expect(screen.getByRole('button', { name: /Held, 0 jobs/ })).toBeInTheDocument();
  });

  it('offers a way back to everything while filtering', () => {
    const { onClear } = strip(['running']);
    fireEvent.click(screen.getByRole('button', { name: 'clear' }));
    expect(onClear).toHaveBeenCalled();
  });
});
