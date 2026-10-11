import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import type { DrainSlot, MachineDrain } from '@/lib/drain';
import { DrainCards, DrainCellView, SlotDrainCells, type DrainView } from './PoolDrain';

const now = new Date(2026, 9, 12, 15, 10);
const view: DrainView = { index: new Map(), age: 0, now, available: true };

function node(over: Partial<MachineDrain>): MachineDrain {
  return {
    machine: 'e1',
    draining: false,
    jobs_total: 0,
    jobs_estimated: 0,
    jobs_from_this_ap: 0,
    jobs_unknown_end: 0,
    jobs_unknown_from_other_aps: 0,
    evicted_on_drain: 0,
    exceeded: 0,
    ...over,
  };
}

describe('DrainCellView', () => {
  it('shows the headline and the detail', () => {
    render(
      <DrainCellView
        m={node({
          jobs_total: 6,
          jobs_estimated: 2,
          jobs_unknown_end: 4,
          jobs_unknown_from_other_aps: 4,
          likely_empty_seconds: 5400,
          at_least_seconds: 5400,
          unknown_up_to_seconds: 259200,
        })}
        drain={view}
        running={6}
      />,
    );
    expect(screen.getByText('At least 1h30m')).toBeInTheDocument();
    expect(screen.getByText('2 of 6 jobs estimated · 4 from other access points could run up to 3 days')).toBeInTheDocument();
  });

  it('puts the overrun in amber', () => {
    render(
      <DrainCellView
        m={node({ jobs_total: 1, jobs_unknown_end: 1, exceeded: 1, jobs_from_this_ap: 1, unknown_up_to_seconds: 7200 })}
        drain={view}
        running={1}
      />,
    );
    expect(screen.getByText('Unclear')).toBeInTheDocument();
    expect(screen.getByText('1 job is running longer than usual')).toHaveClass('text-amber-700');
  });

  it('says empty only when the page agrees nothing runs there', () => {
    const { rerender } = render(<DrainCellView m={undefined} drain={view} running={0} />);
    expect(screen.getByText('Empty now')).toBeInTheDocument();
    rerender(<DrainCellView m={undefined} drain={view} running={2} />);
    expect(screen.queryByText('Empty now')).toBeNull();
    expect(screen.getByText('—')).toBeInTheDocument();
  });
});

describe('SlotDrainCells', () => {
  it('names where the job came from and when it ends', () => {
    const s: DrainSlot = {
      name: 'slot1_3@e1',
      cpus: 1,
      from_this_ap: false,
      submitted_from: 'grid-submitter.icecube.wisc.edu',
      exceeded: false,
      evicted_on_drain: false,
      retirement_deadline: new Date(now.getTime() + 2 * 86400_000).toISOString(),
    };
    render(
      <table>
        <tbody>
          <tr>
            <SlotDrainCells d={s} now={now} />
          </tr>
        </tbody>
      </table>,
    );
    expect(screen.getByText('grid-submitter.icecube.wisc.edu')).toBeInTheDocument();
    expect(screen.getByText('No estimate')).toBeInTheDocument();
    expect(screen.getByText(/retirement limit Wed/)).toBeInTheDocument();
  });
});

describe('DrainCards', () => {
  it('shows coverage honestly', () => {
    render(
      <DrainCards
        totals={{ jobsRunning: 15611, jobsEstimated: 2437, coresFreeingNextHour: 340, drainingNodes: 27, drainingLikelyEmptyWithin2h: 19 }}
        available
      />,
    );
    expect(screen.getByText('≈ 340')).toBeInTheDocument();
    expect(screen.getByText('from jobs submitted here only')).toBeInTheDocument();
    expect(screen.getByRole('meter')).toHaveAttribute('aria-valuenow', '2437');
    expect(screen.getByText('the rest come from other access points')).toBeInTheDocument();
    expect(screen.getByText('27 nodes')).toBeInTheDocument();
    expect(screen.getByText('19 likely empty within 2h')).toBeInTheDocument();
  });

  it('says when the access point does not estimate', () => {
    render(
      <DrainCards
        totals={{ jobsRunning: 10, jobsEstimated: 0, coresFreeingNextHour: 0, drainingNodes: 0, drainingLikelyEmptyWithin2h: 0 }}
        available={false}
      />,
    );
    expect(screen.getAllByText('this access point does not estimate run times')).toHaveLength(2);
  });
});
