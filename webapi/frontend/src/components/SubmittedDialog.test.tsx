import { fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';

import { SubmittedDialog, batchViewHref } from './SubmittedDialog';

const result = { cluster_id: 42, job_ids: ['42.0', '42.1'] };

describe('batchViewHref', () => {
  it("opens the batch's own page", () => {
    expect(batchViewHref(result)).toBe('/batches/42');
  });

  // A batch in multi-AP mode can span access points, so it has no page
  // of its own; the filtered jobs listing is the closest equivalent.
  it('falls back to the filtered jobs listing in multi-AP mode', () => {
    const href = batchViewHref({ ...result, schedd: 'ap2.example.org' });
    expect(href).toMatch(/^\/jobs\?/);
    const params = new URLSearchParams(href.slice(href.indexOf('?')));
    expect(params.get('constraint')).toBe('ClusterId == 42');
  });
});

describe('SubmittedDialog', () => {
  it('reports what was submitted', () => {
    render(<SubmittedDialog result={result} onDismiss={() => {}} />);
    expect(screen.getByRole('dialog')).toBeInTheDocument();
    expect(screen.getByText('Submitted 2 jobs')).toBeInTheDocument();
    expect(screen.getByText(/Batch 42/)).toBeInTheDocument();
  });

  it('does not pluralize a single job', () => {
    render(
      <SubmittedDialog result={{ cluster_id: 7, job_ids: ['7.0'] }} onDismiss={() => {}} />,
    );
    expect(screen.getByText('Submitted 1 job')).toBeInTheDocument();
  });

  // The whole point of the dialog: neither button may navigate this
  // tab, because this tab is holding the draft the user is iterating
  // on. "View batch" is an anchor with target=_blank, not a push.
  it('opens the batch in a new tab rather than navigating away', () => {
    render(<SubmittedDialog result={result} onDismiss={() => {}} />);
    const link = screen.getByRole('link', { name: 'View batch' });
    expect(link).toHaveAttribute('href', '/batches/42');
    expect(link).toHaveAttribute('target', '_blank');
    expect(link).toHaveAttribute('rel', expect.stringContaining('noopener'));
  });

  it('closes on "Submit more", leaving the page alone', () => {
    const onDismiss = vi.fn();
    render(<SubmittedDialog result={result} onDismiss={onDismiss} />);
    fireEvent.click(screen.getByRole('button', { name: 'Submit more' }));
    expect(onDismiss).toHaveBeenCalledTimes(1);
  });

  it('closes on Escape and on a click outside', () => {
    const onDismiss = vi.fn();
    const { container } = render(
      <SubmittedDialog result={result} onDismiss={onDismiss} />,
    );
    fireEvent.keyDown(screen.getByRole('dialog'), { key: 'Escape' });
    expect(onDismiss).toHaveBeenCalledTimes(1);
    fireEvent.click(container.firstChild as HTMLElement);
    expect(onDismiss).toHaveBeenCalledTimes(2);
  });

  it('does not close on a click inside', () => {
    const onDismiss = vi.fn();
    render(<SubmittedDialog result={result} onDismiss={onDismiss} />);
    fireEvent.click(screen.getByRole('dialog'));
    expect(onDismiss).not.toHaveBeenCalled();
  });

  // The server warns when a submit file throws its output away. The
  // dialog is the only place the user sees it: the jobs are queued, so
  // there is no error page, and by the time they look for the output it
  // is already gone.
  it('shows submit-file warnings', () => {
    render(
      <SubmittedDialog
        result={{ ...result, warnings: ['output is /dev/null, so the job’s stdout is discarded'] }}
        onDismiss={() => {}}
      />,
    );
    expect(screen.getByText(/stdout is discarded/)).toBeInTheDocument();
  });

  // Servers that predate the warnings field send none, and an empty
  // list is not a finding -- neither may produce an empty callout.
  it('shows no warning area when there is nothing to warn about', () => {
    const { rerender } = render(
      <SubmittedDialog result={result} onDismiss={() => {}} />,
    );
    expect(screen.queryByText(/Check this before/)).not.toBeInTheDocument();
    rerender(<SubmittedDialog result={{ ...result, warnings: [] }} onDismiss={() => {}} />);
    expect(screen.queryByText(/Check this before/)).not.toBeInTheDocument();
  });
});
