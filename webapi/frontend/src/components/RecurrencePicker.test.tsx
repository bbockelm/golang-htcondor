import { fireEvent, render, screen } from '@testing-library/react';
import { useState } from 'react';
import { describe, expect, it } from 'vitest';

import { RecurrencePicker } from './RecurrencePicker';
import { draftFromReservation, type ScheduleDraft } from '@/lib/recurrence';
import type { AdminReservation } from '@/lib/api';

// What the controls do to the expression, and the one thing they must
// never do to it. The arithmetic is tested in src/lib/recurrence.test.ts;
// this is about which control is live when.

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
    schedule: '0 14 * * 1,3',
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

const cron = () => screen.getByLabelText('Schedule') as HTMLInputElement;
const state = (): ScheduleDraft => JSON.parse(screen.getByTestId('state').textContent!);

describe('RecurrencePicker', () => {
  it('opens on the weekdays a stored schedule fires on', () => {
    render(<Harness initial={reservation()} />);
    expect(screen.getByLabelText('Monday')).toHaveAttribute('aria-pressed', 'true');
    expect(screen.getByLabelText('Wednesday')).toHaveAttribute('aria-pressed', 'true');
    expect(screen.getByLabelText('Tuesday')).toHaveAttribute('aria-pressed', 'false');
    expect(screen.getByLabelText('Start time')).toHaveValue('14:00');
    expect(cron()).toHaveValue('0 14 * * 1,3');
  });

  it('rewrites the expression as weekdays are ticked', () => {
    render(<Harness initial={reservation()} />);
    fireEvent.click(screen.getByLabelText('Friday'));
    expect(cron()).toHaveValue('0 14 * * 1,3,5');
    fireEvent.click(screen.getByLabelText('Monday'));
    expect(cron()).toHaveValue('0 14 * * 3,5');
  });

  it('offers the time of day in quarter hours', () => {
    render(<Harness initial={reservation()} />);
    // A step, not a list: 14:50 is still typeable, and a dropdown of
    // four values would have made it unreachable.
    expect(screen.getByLabelText('Start time')).toHaveAttribute('step', '900');
  });

  it('hides the weekday row for the repeats that have no weekdays', () => {
    render(<Harness initial={reservation()} />);
    fireEvent.click(screen.getByLabelText('Daily'));
    expect(cron()).toHaveValue('0 14 * * *');
    expect(screen.queryByLabelText('Monday')).toBeNull();
  });

  it('hides the end controls for a schedule that does not repeat', () => {
    render(<Harness initial={reservation({ starts_at: '2026-09-02T14:00:00-05:00' })} />);
    fireEvent.click(screen.getByLabelText('Does not repeat'));
    expect(cron()).toHaveValue('0 14 2 9 *');
    expect(screen.queryByLabelText('Repeat until')).toBeNull();
    // Nothing else stops an annual expression, so the single window is
    // the bound and it has to be in the state.
    expect(state().rec.occurrences).toBe(1);
  });

  it('turns an end date into the bound and leaves the expression alone', () => {
    render(<Harness initial={reservation()} />);
    // Filling the box picks the option: no radio is clicked here on
    // purpose, because that is the sequence an operator uses.
    expect(screen.getByLabelText('Repeat until')).toBeEnabled();
    fireEvent.change(screen.getByLabelText('Repeat until'), {
      target: { value: '2026-12-11' },
    });
    expect(state().rec.end).toBe('on');
    expect(state().rec.endDate).toBe('2026-12-11');
    expect(cron()).toHaveValue('0 14 * * 1,3');
  });

  it('counts windows instead, never as well', () => {
    render(<Harness initial={reservation()} />);
    fireEvent.change(screen.getByLabelText('Repeat until'), {
      target: { value: '2026-12-11' },
    });
    expect(screen.getByLabelText('Number of windows')).toBeEnabled();
    fireEvent.change(screen.getByLabelText('Number of windows'), {
      target: { value: '6' },
    });
    expect(state().rec.end).toBe('after');
    expect(state().rec.occurrences).toBe(6);
    // The end date is still in its box, but the bound is the count --
    // the server refuses a reservation carrying both.
    expect(state().rec.endDate).toBe('2026-12-11');
  });

  it('goes read-only, and stays there, once an expression is typed', () => {
    render(<Harness initial={reservation()} />);
    fireEvent.change(cron(), { target: { value: '*/15 9-17 * * 1-5' } });

    expect(screen.getByLabelText('Custom')).toBeChecked();
    expect(screen.getByLabelText('Start time')).toBeDisabled();
    // The weekday row is gone with the weekly repeat it belonged to,
    // so there is nothing left that could write over what was typed.
    expect(screen.queryByLabelText('Monday')).toBeNull();

    fireEvent.click(screen.getByLabelText('Daily'));
    expect(cron()).toHaveValue('*/15 9-17 * * 1-5');
  });

  it('leaves the bounds usable over a typed expression', () => {
    render(<Harness initial={reservation()} />);
    fireEvent.change(cron(), { target: { value: '*/15 9-17 * * 1-5' } });
    fireEvent.change(screen.getByLabelText('Number of windows'), {
      target: { value: '3' },
    });
    expect(state().rec.occurrences).toBe(3);
    expect(cron()).toHaveValue('*/15 9-17 * * 1-5');
  });

  it('takes the controls back only when the operator says so', () => {
    render(<Harness initial={reservation({ schedule: '*/15 9-17 * * 1-5' })} />);
    expect(screen.getByLabelText('Custom')).toBeChecked();
    fireEvent.click(screen.getByRole('button', { name: 'Set it above instead' }));
    expect(screen.getByLabelText('Custom')).not.toBeChecked();
    expect(cron()).not.toHaveValue('*/15 9-17 * * 1-5');
  });

  it('opens in the cron box for a schedule it cannot draw', () => {
    render(<Harness initial={reservation({ schedule: '0 14 * * 3,1' })} />);
    // It parses, but the picker would renumber it. Showing the picker
    // over it would make the next save a silent edit.
    expect(screen.getByLabelText('Custom')).toBeChecked();
    expect(cron()).toHaveValue('0 14 * * 3,1');
  });
});
