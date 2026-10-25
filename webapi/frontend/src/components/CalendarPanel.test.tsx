import { render, screen, within } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import type { CalendarDay, CalendarResponse } from '@/lib/api';
import { DAY_SECONDS } from '@/lib/calendar';
import { CalendarPanel } from './CalendarPanel';

// The calendar has more states than the Playwright suite can afford a
// fixture each for, and the ones that matter are the ones that must not
// look alike: a day with no jobs against a day nobody counted, an
// estimate against a measurement, and no history at all against an empty
// window.
//
// Dates are absolute. A window built from "now" moves which weekday it
// starts on, which moves every square in the grid; the repo has been
// bitten by exactly that.
//
// Mon 3 Aug 2026, midnight UTC.
const MONDAY = 1785715200;

function day(at: number, over: Partial<CalendarDay> = {}): CalendarDay {
  return { day: at, submitted: 0, completed: 0, removed: 0, in_queue: 0, ...over };
}

// Four weeks with a busy day, a day nothing happened, and a queue that
// drains across the window.
function window28(): CalendarDay[] {
  return Array.from({ length: 28 }, (_, i) =>
    day(MONDAY + i * DAY_SECONDS, {
      submitted: i === 3 ? 0 : 10 * (i + 1),
      completed: i === 3 ? 0 : 8 * (i + 1),
      removed: i % 7 === 0 ? 2 : 0,
      in_queue: 500 - i * 10,
    }),
  );
}

function calendar(over: Partial<CalendarResponse> = {}): CalendarResponse {
  return {
    enabled: true,
    days: window28(),
    window_days: 28,
    queue_depth: { derived: true, anchor: 230 },
    source: 'test',
    computed_at: MONDAY + 27 * DAY_SECONDS,
    partial: false,
    note: '',
    ...over,
  };
}

describe('CalendarPanel', () => {
  it('draws a grid per flow with the window total beside each', () => {
    render(<CalendarPanel calendar={calendar()} />);
    expect(screen.getByText('Daily activity')).toBeInTheDocument();
    // Each flow gets its own grid, titled -- the table view below
    // repeats the same three words as column headings.
    for (const title of ['Submitted', 'Finished', 'Removed']) {
      expect(screen.getAllByText(title).length).toBeGreaterThan(0);
    }
    // Submitted across 28 days with the fourth blank: 10*(1..28) less
    // the 40 that day would have carried.
    expect(screen.getByText('4,020 jobs')).toBeInTheDocument();
    // Both ends of the shading are named, so a square can be read as a
    // number rather than only compared with its neighbours.
    expect(screen.getByTestId('calendar-scale')).toHaveTextContent('280 a day');
  });

  it('links a day to the jobs behind it, finished work to the archive', () => {
    render(<CalendarPanel calendar={calendar()} />);
    const finished = screen.getByRole('link', {
      name: 'Mon, Aug 3, 2026: 8 jobs finished',
    });
    // The archive, with the day the figure covered -- not /jobs, where a
    // job that finished in August stopped existing within seconds.
    expect(finished).toHaveAttribute(
      'href',
      expect.stringContaining('/archive?constraint='),
    );
    // On EnteredHistoryTime, which is what the server bucketed the day by.
    expect(decodeURIComponent(finished.getAttribute('href')!)).toContain(
      `EnteredHistoryTime >= ${MONDAY} && EnteredHistoryTime < ${MONDAY + DAY_SECONDS}`,
    );
  });

  it('renders a day with no jobs as a zero, not as a gap', () => {
    render(<CalendarPanel calendar={calendar()} />);
    const quiet = screen.getByTitle('Thu, Aug 6, 2026: no jobs submitted');
    expect(quiet).toHaveAttribute('data-day-state', 'zero');
    // Nothing to drill into, so it is not a link: a quiet day's list is
    // empty, and a link to an empty list reads as a broken query.
    expect(quiet.tagName.toLowerCase()).not.toBe('a');
    // And it is in the text too, as a counted zero.
    expect(
      within(screen.getByRole('table')).getAllByText('0').length,
    ).toBeGreaterThan(0);
  });

  it('renders a day nobody counted differently from a day with no jobs', () => {
    const days = window28().filter((d) => d.day !== MONDAY + 10 * DAY_SECONDS);
    render(
      <CalendarPanel
        calendar={calendar({ days, partial: true, note: 'One day could not be counted.' })}
      />,
    );
    const gap = screen.getAllByTitle('Thu, Aug 13, 2026: not counted')[0];
    expect(gap).toHaveAttribute('data-day-state', 'uncounted');
    // The two states are present at once and are not the same state --
    // which is the whole point of the server sending a zero day rather
    // than leaving it out.
    expect(screen.getByTitle('Thu, Aug 6, 2026: no jobs submitted')).toHaveAttribute(
      'data-day-state',
      'zero',
    );
    // A reader who opens the table instead of hovering sees it too.
    expect(within(screen.getByRole('table')).getByText('not counted')).toBeInTheDocument();
  });

  it('surfaces the note when the window is incomplete', () => {
    render(
      <CalendarPanel
        calendar={calendar({ partial: true, note: 'History before 1 Sep was not available.' })}
      />,
    );
    expect(screen.getByText('History before 1 Sep was not available.')).toBeInTheDocument();
  });

  it('says so even when an incomplete window carries no note', () => {
    render(<CalendarPanel calendar={calendar({ partial: true, note: '' })} />);
    expect(screen.getByText(/some days could not be counted/i)).toBeInTheDocument();
  });

  it('renders nothing at all where there is no history to count', () => {
    // Not an empty calendar: a panel that never fills reads as broken
    // rather than absent, which is the rule the live ticker follows.
    const { container } = render(
      <CalendarPanel calendar={{ enabled: false, window_days: 90, partial: false, note: '' }} />,
    );
    expect(container).toBeEmptyDOMElement();
  });

  it('renders nothing while the answer has not arrived', () => {
    const { container } = render(<CalendarPanel calendar={undefined} />);
    expect(container).toBeEmptyDOMElement();
  });

  it('presents a derived queue depth as an estimate, not as a measurement', () => {
    render(<CalendarPanel calendar={calendar()} />);
    const depth = screen.getByTestId('queue-depth');
    expect(depth).toHaveAttribute('data-derived', 'true');
    // Said in words beside the title rather than hidden in a tooltip.
    expect(depth).toHaveTextContent(/estimated; only the figure for today was counted/);
    // The hover text hedges every past day the same way.
    expect(
      within(depth).getByText('Tue, Aug 4, 2026: about 490 in the queue'),
    ).toBeInTheDocument();
    // The table marks the column and every figure in it.
    const table = screen.getByRole('table');
    expect(within(table).getByText('In queue (estimated)')).toBeInTheDocument();
    expect(within(table).getByText('~230')).toBeInTheDocument();
    // The key names the mark that says "not counted".
    expect(screen.getByRole('button', { name: 'How to read' })).toBeInTheDocument();
  });

  it('leaves the derived depth with nothing to click but today', () => {
    render(<CalendarPanel calendar={calendar()} />);
    const depth = screen.getByTestId('queue-depth');
    const links = within(depth).getAllByRole('link');
    // One link, and it is the figure that was counted. A past day's
    // depth names no set of jobs, so a drill-down from it would disagree
    // with whatever it showed.
    expect(links).toHaveLength(1);
    expect(links[0]).toHaveAttribute('href', '/jobs');
    expect(links[0]).toHaveTextContent('230 in the queue now');
  });

  it('drops the hedging where the depth was actually counted each day', () => {
    render(<CalendarPanel calendar={calendar({ queue_depth: { derived: false, anchor: 230 } })} />);
    const depth = screen.getByTestId('queue-depth');
    expect(depth).toHaveAttribute('data-derived', 'false');
    expect(depth).toHaveTextContent('counted each day');
    expect(within(depth).getByText('Tue, Aug 4, 2026: 490 in the queue')).toBeInTheDocument();
    // Nothing in the table is hedged, because nothing in it is a guess.
    const table = screen.getByRole('table');
    expect(within(table).queryByText(/^~/)).toBeNull();
    expect(within(table).queryByText(/estimated/)).toBeNull();
  });
});
