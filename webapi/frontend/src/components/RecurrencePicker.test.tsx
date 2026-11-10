import { fireEvent, render, screen } from '@testing-library/react';
import { useState } from 'react';
import { describe, expect, it } from 'vitest';

import { RecurrencePicker } from './RecurrencePicker';
import { draftFromReservation, type ScheduleDraft } from '@/lib/recurrence';
import type { AdminReservation, WireRecurrence } from '@/lib/api';

// Which control is live when, and what each one leaves behind. The
// arithmetic is tested in src/lib/recurrence.test.ts; this is about the
// controls -- above all that every one of them can be undone, which is
// the thing a picker gets wrong.

const CHICAGO = 'America/Chicago';

function reservation(over: Partial<AdminReservation> = {}): AdminReservation {
  return {
    id: 'cs301',
    owner: 'jsmith',
    project: 'cs301-f26',
    submit: 'executable = /usr/bin/python3\nqueue\n',
    seats: 20,
    standing: 0,
    duration_seconds: 3600,
    lead_seconds: 6 * 3600,
    hold_seconds: 900,
    schedule_kind: 'recurrence',
    schedule: '0 14 * * 1,3',
    recurrence: {
      freq: 'weekly',
      interval: 1,
      by_weekday: [1, 3],
      time_of_day: '14:00',
    },
    timezone: CHICAGO,
    enabled: true,
    starts_at: '',
    ends_at: '',
    occurrences: 0,
    ...over,
  };
}

// The picker is controlled, so a test of it needs something to hold the
// state -- otherwise every change is thrown away and every assertion
// passes against the initial render.
function Harness({ initial }: { initial: AdminReservation }) {
  const [draft, setDraft] = useState<ScheduleDraft>(() => draftFromReservation(initial));
  return (
    <>
      <RecurrencePicker value={draft} onChange={setDraft} timezone={CHICAGO} />
      <output data-testid="state">{JSON.stringify(draft)}</output>
    </>
  );
}

const state = (): ScheduleDraft => JSON.parse(screen.getByTestId('state').textContent!);
const cron = () => screen.getByLabelText('Schedule') as HTMLInputElement;

describe('RecurrencePicker', () => {
  it('opens on the days a stored recurrence fires on', () => {
    render(<Harness initial={reservation()} />);
    expect(screen.getByLabelText('Weekly')).toBeChecked();
    expect(screen.getByLabelText('Monday')).toHaveAttribute('aria-pressed', 'true');
    expect(screen.getByLabelText('Wednesday')).toHaveAttribute('aria-pressed', 'true');
    expect(screen.getByLabelText('Tuesday')).toHaveAttribute('aria-pressed', 'false');
    expect(screen.getByLabelText('Start time')).toHaveValue('14:00');
  });

  it('offers the time of day in quarter hours', () => {
    render(<Harness initial={reservation()} />);
    // A step, not a list: 14:50 is still typeable, and a dropdown of
    // four values would have made it unreachable.
    expect(screen.getByLabelText('Start time')).toHaveAttribute('step', '900');
  });

  it('rewrites the recurrence as days are ticked', () => {
    render(<Harness initial={reservation()} />);
    fireEvent.click(screen.getByLabelText('Friday'));
    expect(state().rec.weekdays).toEqual([1, 3, 5]);
    fireEvent.click(screen.getByLabelText('Monday'));
    expect(state().rec.weekdays).toEqual([3, 5]);
  });

  it('asks for the week an every-other-week schedule is counted from', () => {
    render(<Harness initial={reservation()} />);
    fireEvent.change(screen.getByLabelText('Repeat every'), { target: { value: '2' } });
    // Filled in where it can be seen and changed, rather than left for
    // the server to refuse.
    expect(screen.getByLabelText('Start date')).not.toHaveValue('');
    // And if it is cleared anyway, the form says what is missing
    // instead of sending a reservation the server will reject.
    fireEvent.change(screen.getByLabelText('Start date'), { target: { value: '' } });
    expect(screen.getByText(/needs a start date to count from/)).toBeVisible();
  });

  it('shows the interval only where there is something to repeat', () => {
    render(<Harness initial={reservation()} />);
    expect(screen.getByLabelText('Repeat every')).toBeVisible();
    fireEvent.click(screen.getByLabelText('Always on'));
    expect(screen.queryByLabelText('Repeat every')).toBeNull();
    fireEvent.click(screen.getByLabelText('Custom'));
    expect(screen.queryByLabelText('Repeat every')).toBeNull();
  });

  it('hides the weekday row for the repeats that have no weekdays', () => {
    render(<Harness initial={reservation()} />);
    fireEvent.click(screen.getByLabelText('Daily'));
    expect(screen.queryByLabelText('Monday')).toBeNull();
    expect(state().rec.repeat).toBe('daily');
  });

  it('hides the end controls for a reservation held once', () => {
    render(<Harness initial={reservation()} />);
    fireEvent.click(screen.getByLabelText('Does not repeat'));
    expect(screen.queryByLabelText('Repeat until')).toBeNull();
    // Nothing else stops a daily recurrence, so the single window is
    // the bound and it has to be in the state.
    expect(state().rec.occurrences).toBe(1);
    expect(state().rec.end).toBe('after');
  });

  it('turns an end date into the bound without touching the repeat', () => {
    render(<Harness initial={reservation()} />);
    // Filling the box picks the option: no radio is clicked here on
    // purpose, because that is the sequence an operator uses.
    expect(screen.getByLabelText('Repeat until')).toBeEnabled();
    fireEvent.change(screen.getByLabelText('Repeat until'), {
      target: { value: '2026-12-11' },
    });
    expect(state().rec.end).toBe('on');
    expect(state().rec.endDate).toBe('2026-12-11');
    expect(state().rec.weekdays).toEqual([1, 3]);
  });

  it('counts windows instead, never as well', () => {
    render(<Harness initial={reservation()} />);
    fireEvent.change(screen.getByLabelText('Repeat until'), {
      target: { value: '2026-12-11' },
    });
    fireEvent.change(screen.getByLabelText('Number of windows'), {
      target: { value: '6' },
    });
    expect(state().rec.end).toBe('after');
    expect(state().rec.occurrences).toBe(6);
    // The end date is still in its box, but the bound is the count --
    // the server refuses a reservation carrying both.
    expect(state().rec.endDate).toBe('2026-12-11');
  });

  describe('monthly', () => {
    it('starts on the start date and offers the dates of the month', () => {
      render(
        <Harness initial={reservation({ starts_at: '2026-09-17T14:00:00-05:00' })} />,
      );
      fireEvent.click(screen.getByLabelText('Monthly'));
      expect(screen.getByLabelText('Day 17 of the month')).toHaveAttribute(
        'aria-pressed',
        'true',
      );
      fireEvent.click(screen.getByLabelText('Day 1 of the month'));
      expect(state().rec.monthdays).toEqual([1, 17]);
      fireEvent.click(screen.getByLabelText('Day 17 of the month'));
      expect(state().rec.monthdays).toEqual([1]);
    });

    it('counts a day within the month, by position and by kind', () => {
      render(<Harness initial={reservation()} />);
      fireEvent.click(screen.getByLabelText('Monthly'));
      fireEvent.click(screen.getByLabelText('On the'));
      fireEvent.change(screen.getByLabelText('Which one in the month'), {
        target: { value: '-1' },
      });
      fireEvent.change(screen.getByLabelText('Day of the month to count'), {
        target: { value: '5' },
      });
      expect(state().rec.setpos).toBe(-1);
      expect(state().rec.setposWeekday).toBe(5);
      expect(state().rec.dayKind).toBe('');

      fireEvent.change(screen.getByLabelText('Day of the month to count'), {
        target: { value: 'weekend' },
      });
      expect(state().rec.dayKind).toBe('weekend');
      // The weekday is kept, so changing your mind back costs nothing.
      expect(state().rec.setposWeekday).toBe(5);
    });

    it('offers the positions a month can be counted to from either end', () => {
      render(<Harness initial={reservation()} />);
      fireEvent.click(screen.getByLabelText('Monthly'));
      fireEvent.click(screen.getByLabelText('On the'));
      const options = Array.from(
        (screen.getByLabelText('Which one in the month') as HTMLSelectElement).options,
      ).map((o) => o.textContent);
      expect(options).toEqual([
        'First',
        'Second',
        'Third',
        'Fourth',
        'Fifth',
        'Last',
        'Next to last',
      ]);
    });

    it('asks for a date once the last one is unticked, rather than repeating on nothing', () => {
      render(<Harness initial={reservation()} />);
      fireEvent.click(screen.getByLabelText('Monthly'));
      // Whichever day it filled in from the start date -- untick it and
      // the recurrence describes nothing, so the form says so.
      const filled = state().rec.monthdays;
      expect(filled).toHaveLength(1);
      fireEvent.click(screen.getByLabelText(`Day ${filled[0]} of the month`));
      expect(state().rec.monthdays).toEqual([]);
      expect(screen.getByText('Choose at least one day of the month.')).toBeVisible();
    });
  });

  describe('the expression', () => {
    it('is shown only while it is the schedule', () => {
      render(<Harness initial={reservation()} />);
      expect(screen.queryByLabelText('Schedule')).toBeNull();
      fireEvent.click(screen.getByLabelText('Custom'));
      expect(cron()).toHaveValue('0 14 * * 1,3');
      expect(screen.getByRole('link', { name: 'What the fields mean' })).toHaveAttribute(
        'href',
        'https://en.wikipedia.org/wiki/Cron',
      );
    });

    it('is undone by one click, which is the whole complaint', () => {
      render(<Harness initial={reservation()} />);
      fireEvent.click(screen.getByLabelText('Custom'));
      fireEvent.change(cron(), { target: { value: '*/15 9-17 * * 1-5' } });

      fireEvent.click(screen.getByLabelText('Weekly'));
      // Back exactly where it was: no reload, nothing retyped.
      expect(screen.getByLabelText('Monday')).toHaveAttribute('aria-pressed', 'true');
      expect(screen.getByLabelText('Wednesday')).toHaveAttribute('aria-pressed', 'true');
      expect(screen.getByLabelText('Start time')).toHaveValue('14:00');
      // And the expression is still there to go back to.
      fireEvent.click(screen.getByLabelText('Custom'));
      expect(cron()).toHaveValue('*/15 9-17 * * 1-5');
    });

    it('is never rewritten by the controls', () => {
      render(<Harness initial={reservation()} />);
      fireEvent.click(screen.getByLabelText('Custom'));
      fireEvent.change(cron(), { target: { value: '*/15 9-17 * * 1-5' } });
      fireEvent.click(screen.getByLabelText('Daily'));
      fireEvent.click(screen.getByLabelText('Custom'));
      expect(cron()).toHaveValue('*/15 9-17 * * 1-5');
    });

    it('is the control a reservation timed by one opens on', () => {
      render(<Harness initial={reservation({ schedule_kind: 'cron', recurrence: null })} />);
      expect(screen.getByLabelText('Custom')).toBeChecked();
      expect(cron()).toHaveValue('0 14 * * 1,3');
      // The time of day is in the expression, so there is no box here
      // claiming to set it.
      expect(screen.queryByLabelText('Start time')).toBeNull();
    });

    it('leaves the bounds usable over an expression', () => {
      render(<Harness initial={reservation({ schedule_kind: 'cron', recurrence: null })} />);
      fireEvent.change(screen.getByLabelText('Number of windows'), {
        target: { value: '3' },
      });
      expect(state().rec.occurrences).toBe(3);
      expect(cron()).toHaveValue('0 14 * * 1,3');
    });

    it('is still the schedule after a start date is set', () => {
      // The start date bounds whichever schedule is in force rather
      // than being part of one, so setting it must not quietly hand the
      // schedule to the controls.
      render(<Harness initial={reservation({ schedule_kind: 'cron', recurrence: null })} />);
      fireEvent.change(screen.getByLabelText('Start date'), {
        target: { value: '2026-09-02' },
      });
      expect(state().kind).toBe('cron');
      expect(screen.getByLabelText('Custom')).toBeChecked();
      expect(cron()).toHaveValue('0 14 * * 1,3');
    });
  });

  describe('always on', () => {
    it('has no windows to count, and says what it does instead', () => {
      render(<Harness initial={reservation({ schedule_kind: 'always' })} />);
      expect(screen.getByLabelText('Always on')).toBeChecked();
      expect(screen.getByText(/held continuously/)).toBeVisible();
      // An end date still bounds it; a number of windows cannot,
      // because it has none.
      expect(screen.getByLabelText('Repeat until')).toBeVisible();
      expect(screen.queryByLabelText('Number of windows')).toBeNull();
      expect(screen.queryByLabelText('Start time')).toBeNull();
      expect(screen.queryByLabelText('Schedule')).toBeNull();
    });

    it('is left as freely as it is entered', () => {
      render(<Harness initial={reservation()} />);
      fireEvent.click(screen.getByLabelText('Always on'));
      fireEvent.click(screen.getByLabelText('Weekly'));
      expect(state().kind).toBe('recurrence');
      expect(screen.getByLabelText('Monday')).toHaveAttribute('aria-pressed', 'true');
    });
  });

  it('keeps a recurrence the controls cannot state, and says so', () => {
    // Monthly weekdays with no position: legal on the wire, outside
    // these controls. Drawing the nearest thing would make the next
    // save a silent edit.
    const stored: WireRecurrence = {
      freq: 'monthly',
      interval: 1,
      by_weekday: [1, 3],
      time_of_day: '14:00',
    };
    render(<Harness initial={reservation({ recurrence: stored })} />);
    expect(screen.getByText(/Every Monday and Wednesday of every month/)).toBeVisible();
    expect(state().stored).toEqual(stored);
    // A bound says nothing about the recurrence, so setting one leaves
    // it where it is.
    fireEvent.change(screen.getByLabelText('Start date'), {
      target: { value: '2026-09-02' },
    });
    expect(state().stored).toEqual(stored);
    // A repeat control is the operator saying to replace it.
    fireEvent.click(screen.getByLabelText('Weekly'));
    expect(state().stored).toBeNull();
  });
});
