import { render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { DashboardActivity, GoodputSummary } from '@/lib/api';
import {
  Goodput,
  HoldReasons,
  LiveTicker,
  OtherStatuses,
  RecentActivity,
  ago,
  duration,
} from './DashboardPanels';
import type { ActivityEvent } from '@/lib/useActivityStream';

// The dashboard's activity half has more distinct states than the
// Playwright suite can afford a fixture each for: a list can be
// populated, empty-because-nothing-happened, or empty-because-nothing-
// could-answer, and those three must not look alike. That is what these
// cover -- Playwright covers that the page renders and binds at all.

const emptyActivity: DashboardActivity = {
  completed_available: true,
  completed_partial: false,
  source: 'test',
  computed_at: 0,
};

function activity(over: Partial<DashboardActivity> = {}): DashboardActivity {
  return { ...emptyActivity, ...over };
}

describe('HoldReasons', () => {
  it('renders nothing at all when no jobs are held', () => {
    const { container } = render(<HoldReasons activity={activity()} />);
    // Not "renders an empty panel": a heading reading "Why jobs are
    // held" above nothing is worse than no section, because it implies
    // the breakdown failed rather than that there is nothing to break
    // down.
    expect(container).toBeEmptyDOMElement();
  });

  it('shows the count, the label and the example message', () => {
    render(
      <HoldReasons
        activity={activity({
          hold_reasons: [
            { code: 13, label: 'Failed to transfer output', count: 4, example: '/no/such/file' },
          ],
        })}
      />,
    );
    expect(screen.getByText('4')).toBeInTheDocument();
    expect(screen.getByText('Failed to transfer output')).toBeInTheDocument();
    // The code says the category, the message says which file. Dropping
    // the example leaves every transfer failure looking identical.
    expect(screen.getByText('/no/such/file')).toBeInTheDocument();
  });

  it('marks spooling as a submit in progress rather than a failure', () => {
    render(
      <HoldReasons
        activity={activity({
          hold_reasons: [{ code: 16, label: 'Spooling input data', count: 9 }],
        })}
      />,
    );
    // Code 16 is how condor_submit -spool parks a job mid-transfer. An
    // operator who reads it as nine held jobs goes looking for a
    // problem that does not exist.
    expect(screen.getByText(/a submit in progress, not a failure/)).toBeInTheDocument();
  });

  it('keeps the rows in the order the server sent them', () => {
    render(
      <HoldReasons
        activity={activity({
          hold_reasons: [
            { code: 13, label: 'Dominant cause', count: 900 },
            { code: 3, label: 'Rare cause', count: 2 },
          ],
        })}
      />,
    );
    // The server orders by weight so the actionable cause is first. A
    // component that re-sorted (by code, say) would bury it.
    const rows = screen.getAllByRole('row');
    expect(rows[0]).toHaveTextContent('Dominant cause');
    expect(rows[1]).toHaveTextContent('Rare cause');
  });
});

describe('RecentActivity', () => {
  it('says nothing changed rather than drawing four empty panels', () => {
    render(<RecentActivity activity={activity()} />);
    expect(screen.getByText(/Nothing has changed recently/)).toBeInTheDocument();
  });

  it('distinguishes "nothing happened" from "nothing could answer"', () => {
    render(
      <RecentActivity
        activity={activity({
          completed_available: false,
          recently_submitted: [{ cluster_id: 7, proc_id: 0, at: 1_700_000_000 }],
        })}
      />,
    );
    // Recently submitted is empty because nothing was submitted: "none".
    // Recently completed is empty because the queue destroys finished
    // jobs and no archive answered: that is a gap in what we can see,
    // and reporting it as "none" would be a confident wrong answer.
    expect(screen.getByText(/needs the htcondordb history mirror/)).toBeInTheDocument();
    expect(screen.getAllByText('none').length).toBeGreaterThan(0);
  });

  it('warns when the completed list is only what the queue still holds', () => {
    render(
      <RecentActivity
        activity={activity({
          completed_partial: true,
          recently_completed: [{ cluster_id: 8, proc_id: 1, at: 1_700_000_000 }],
        })}
      />,
    );
    // A short list here is otherwise indistinguishable from a quiet
    // access point, when in fact it is a few seconds of visibility.
    expect(screen.getByText(/the history mirror is not answering/)).toBeInTheDocument();
  });

  it('does not warn about partial data when the archive did answer', () => {
    render(
      <RecentActivity
        activity={activity({
          completed_partial: false,
          recently_completed: [{ cluster_id: 8, proc_id: 1, at: 1_700_000_000 }],
        })}
      />,
    );
    expect(screen.queryByText(/history mirror is not answering/)).not.toBeInTheDocument();
  });

  it('links each job to its detail page', () => {
    render(
      <RecentActivity
        activity={activity({
          recently_started: [{ cluster_id: 12, proc_id: 3, at: 1_700_000_000, detail: 'slot1@host' }],
        })}
      />,
    );
    expect(screen.getByRole('link', { name: '12.3' })).toHaveAttribute('href', '/jobs/12.3');
    expect(screen.getByText('slot1@host')).toBeInTheDocument();
  });

  it('names what answered, because a cached snapshot is minutes old by design', () => {
    render(<RecentActivity activity={activity({ source: 'htcondordb mirror' })} />);
    expect(screen.getByText(/htcondordb mirror/)).toBeInTheDocument();
  });
});

describe('OtherStatuses', () => {
  it('omits the statuses the tiles already show', () => {
    render(<OtherStatuses byStatus={{ idle: 5, running: 2, removed: 1 }} />);
    // idle and running have their own tiles; repeating them here would
    // double-count by eye.
    expect(screen.queryByText(/Idle/)).not.toBeInTheDocument();
    expect(screen.getByText(/Removed/)).toBeInTheDocument();
  });

  it('renders nothing when there is nothing left over', () => {
    const { container } = render(
      <OtherStatuses byStatus={{ idle: 5, running: 2, held: 1, completed: 3 }} />,
    );
    expect(container).toBeEmptyDOMElement();
  });
});

describe('ago', () => {
  // The clock is frozen because ago() reads it: capturing `now` here and
  // letting the real clock advance between the two reads makes this fail
  // roughly once per second of test runtime, which is a flake rather
  // than a finding. (It did, once.)
  const now = 1_700_000_000;
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(now * 1000);
  });
  afterEach(() => vi.useRealTimers());

  it('uses the largest unit that fits', () => {
    expect(ago(now - 5)).toBe('5s');
    expect(ago(now - 90)).toBe('1m');
    expect(ago(now - 7200)).toBe('2h');
    expect(ago(now - 3 * 86400)).toBe('3d');
  });

  it('clamps a future timestamp to zero rather than rendering a negative age', () => {
    // Clock skew between the access point and the browser is normal and
    // "-4s ago" reads as a bug in the page.
    expect(ago(now + 60)).toBe('0s');
  });
});

describe('LiveTicker', () => {
  const base = { events: [], connected: true, unavailable: false };
  const event = (over: Partial<ActivityEvent> = {}): ActivityEvent => ({
    kind: 'started',
    cluster_id: 5,
    proc_id: 0,
    at: Math.floor(Date.now() / 1000) - 10,
    ...over,
  });

  it('renders nothing where there is no mirror to stream from', () => {
    const { container } = render(<LiveTicker {...base} unavailable />);
    // Not an empty panel. One that never moves reads as a broken
    // feature rather than an absent one, and the deployments without a
    // mirror are exactly the ones that cannot have this.
    expect(container).toBeEmptyDOMElement();
  });

  it('distinguishes a quiet stream from one that is not connected yet', () => {
    const { rerender } = render(<LiveTicker {...base} connected />);
    expect(screen.getByText(/Nothing has happened since this page loaded/)).toBeInTheDocument();

    rerender(<LiveTicker {...base} connected={false} />);
    expect(screen.getByText(/Waiting for the stream/)).toBeInTheDocument();
  });

  it('shows the kind, the job and its detail', () => {
    render(
      <LiveTicker
        {...base}
        events={[event({ kind: 'held', cluster_id: 12, proc_id: 3, detail: 'transfer failed', owner: 'alice' })]}
      />,
    );
    expect(screen.getByText('held')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: '12.3' })).toHaveAttribute('href', '/jobs/12.3');
    expect(screen.getByText('transfer failed')).toBeInTheDocument();
    expect(screen.getByText('alice')).toBeInTheDocument();
  });

  it('says when events were dropped rather than letting a gap look quiet', () => {
    render(<LiveTicker {...base} events={[event({ skipped: 17 })]} />);
    expect(screen.getByText(/\+17 not shown/)).toBeInTheDocument();
  });

  it('does not annotate an event that lost nothing', () => {
    render(<LiveTicker {...base} events={[event({ skipped: 0 })]} />);
    expect(screen.queryByText(/not shown/)).not.toBeInTheDocument();
  });

  it('renders two events for the same job without colliding', () => {
    // A job that starts and then completes produces two lines. Keying
    // on the job id alone would make React drop one of them.
    render(
      <LiveTicker
        {...base}
        events={[
          event({ kind: 'completed', cluster_id: 5, proc_id: 0, at: 1_700_000_100 }),
          event({ kind: 'started', cluster_id: 5, proc_id: 0, at: 1_700_000_000 }),
        ]}
      />,
    );
    expect(screen.getByText('completed')).toBeInTheDocument();
    expect(screen.getByText('started')).toBeInTheDocument();
  });
});

describe('Goodput', () => {
  const summary = (over: Partial<GoodputSummary> = {}): GoodputSummary => ({
    window_hours: 24,
    succeeded: 10,
    failed: 2,
    unfinished: 0,
    good_seconds: 3600,
    bad_seconds: 400,
    ...over,
  });

  it('renders nothing when no archive could answer', () => {
    const { container } = render(<Goodput goodput={undefined} />);
    // Absent means nothing could tell us, not that nothing succeeded.
    // Zeros here would be a confident wrong answer.
    expect(container).toBeEmptyDOMElement();
  });

  it('renders nothing when nothing finished in the window', () => {
    const { container } = render(
      <Goodput goodput={summary({ succeeded: 0, failed: 0, unfinished: 0, good_seconds: 0, bad_seconds: 0 })} />,
    );
    expect(container).toBeEmptyDOMElement();
  });

  it('shows the split and the share of compute that survived', () => {
    render(<Goodput goodput={summary({ good_seconds: 3000, bad_seconds: 1000 })} />);
    expect(screen.getByText('10')).toBeInTheDocument();
    // "succeeded" also appears in the sentence below the bar, so match
    // the label exactly rather than by substring.
    expect(screen.getByText('succeeded')).toBeInTheDocument();
    // 3000 of 4000 seconds.
    expect(screen.getByText(/75% of/)).toBeInTheDocument();
  });

  it('counts cancelled jobs apart from failures', () => {
    render(<Goodput goodput={summary({ unfinished: 3 })} />);
    // A job its owner removed is not the access point going wrong.
    expect(screen.getByText(/did not finish/)).toBeInTheDocument();
  });

  it('omits the cancelled row when there are none', () => {
    render(<Goodput goodput={summary({ unfinished: 0 })} />);
    expect(screen.queryByText('did not finish')).not.toBeInTheDocument();
  });

  it('reports a signalled failure as killed rather than as an exit code', () => {
    render(
      <Goodput
        goodput={summary({
          top_failures: [{ code: 0, signal: true, count: 4, seconds: 900 }],
        })}
      />,
    );
    // The exit code recorded beside a signal is meaningless -- rendering
    // "exit 0" for a killed job would report a success.
    expect(screen.getByText(/killed by a signal/)).toBeInTheDocument();
    expect(screen.queryByText(/exit 0/)).not.toBeInTheDocument();
  });

  it('lists failing exit codes with what they cost', () => {
    render(
      <Goodput
        goodput={summary({
          top_failures: [{ code: 127, signal: false, count: 10, seconds: 40000 }],
        })}
      />,
    );
    expect(screen.getByText('exit 127')).toBeInTheDocument();
    expect(screen.getByText(/10 jobs/)).toBeInTheDocument();
    expect(screen.getByText('11h')).toBeInTheDocument();
  });

  it('does not divide by zero when nothing reported wall clock', () => {
    render(<Goodput goodput={summary({ good_seconds: 0, bad_seconds: 0 })} />);
    // Counts still render; the compute line simply does not.
    expect(screen.getByText('succeeded')).toBeInTheDocument();
    expect(screen.queryByText(/of compute/)).not.toBeInTheDocument();
    expect(screen.queryByText(/NaN/)).not.toBeInTheDocument();
  });
});

describe('duration', () => {
  it('uses the unit an operator would say', () => {
    expect(duration(45)).toBe('45s');
    expect(duration(90)).toBe('2m');
    expect(duration(5400)).toBe('1.5h');
    expect(duration(40000)).toBe('11h');
    expect(duration(3 * 86400)).toBe('3d');
  });
});
