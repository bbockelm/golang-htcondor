import { describe, expect, it } from 'vitest';

import type { AdminReservation, WireRecurrence } from '@/lib/api';
import {
  DEFAULT_START_TIME,
  defaultRecurrence,
  describeBounds,
  describeRecurrence,
  describeSchedule,
  draftFromReservation,
  parseTimeOfDay,
  recurrenceFromWire,
  recurrenceToBounds,
  recurrenceToWire,
  repeatChoice,
  scheduleFields,
  scheduleNeeds,
  setposDayValue,
  todayInZone,
  toggleMonthday,
  toggleWeekday,
  whyNoWindows,
  withBounds,
  withCron,
  withRecurrence,
  withRepeatChoice,
  withSetposDay,
  zonedDateTime,
  zonedRFC3339,
  type Recurrence,
  type ScheduleDraft,
} from '@/lib/recurrence';

// Every zone here is named explicitly: these cases are about what a
// reservation's own zone does to a date, and a test that depended on
// the machine's zone would pass or fail by where it ran.
const CHICAGO = 'America/Chicago';

function rec(over: Partial<Recurrence> = {}): Recurrence {
  return { ...defaultRecurrence(), startTime: '14:00', weekdays: [1, 3], ...over };
}

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
    schedule_kind: 'cron',
    schedule: '0 14 * * 1,3',
    recurrence: null,
    timezone: CHICAGO,
    enabled: true,
    starts_at: '',
    ends_at: '',
    occurrences: 0,
    ...over,
  };
}

function draft(over: Partial<ScheduleDraft> = {}): ScheduleDraft {
  return { kind: 'recurrence', rec: rec(), cron: '', stored: null, ...over };
}

describe('parseTimeOfDay', () => {
  it('reads a time of day', () => {
    expect(parseTimeOfDay('14:00')).toEqual({ hour: 14, minute: 0 });
    expect(parseTimeOfDay('9:05')).toEqual({ hour: 9, minute: 5 });
    expect(parseTimeOfDay(' 23:59 ')).toEqual({ hour: 23, minute: 59 });
  });

  it('refuses what is not one', () => {
    // Seconds included: the schedule has no field to put them in, so
    // accepting them would silently drop them.
    expect(parseTimeOfDay('14:00:00')).toBeNull();
    expect(parseTimeOfDay('24:00')).toBeNull();
    expect(parseTimeOfDay('12:60')).toBeNull();
    expect(parseTimeOfDay('')).toBeNull();
  });
});

describe('recurrenceToWire', () => {
  it('sends only the fields the chosen frequency admits', () => {
    // A daily recurrence carrying weekdays is a weekly one wearing the
    // wrong frequency, and the server refuses it as such.
    expect(recurrenceToWire(rec({ repeat: 'daily', interval: 3 }))).toEqual({
      freq: 'daily',
      interval: 3,
      time_of_day: '14:00',
    });
    expect(recurrenceToWire(rec({ repeat: 'weekly', interval: 2 }))).toEqual({
      freq: 'weekly',
      interval: 2,
      by_weekday: [1, 3],
      time_of_day: '14:00',
    });
  });

  it('says a one-off as the single daily window it is', () => {
    expect(recurrenceToWire(rec({ repeat: 'once', interval: 4 }))).toEqual({
      freq: 'daily',
      interval: 1,
      time_of_day: '14:00',
    });
  });

  it('sorts and dedupes the day toggles', () => {
    expect(
      recurrenceToWire(rec({ repeat: 'weekly', weekdays: [5, 1, 5, 3] })).by_weekday,
    ).toEqual([1, 3, 5]);
    expect(
      recurrenceToWire(
        rec({ repeat: 'monthly', monthlyMode: 'monthday', monthdays: [15, 1, 15] }),
      ).by_monthday,
    ).toEqual([1, 15]);
  });

  it('sends a monthly position with one weekday, or with a category, never both', () => {
    expect(
      recurrenceToWire(
        rec({ repeat: 'monthly', monthlyMode: 'setpos', setpos: -1, setposWeekday: 5 }),
      ),
    ).toEqual({
      freq: 'monthly',
      interval: 1,
      by_setpos: -1,
      by_weekday: [5],
      time_of_day: '14:00',
    });
    expect(
      recurrenceToWire(
        rec({
          repeat: 'monthly',
          monthlyMode: 'setpos',
          setpos: 1,
          setposWeekday: 5,
          dayKind: 'weekday',
        }),
      ),
    ).toEqual({
      freq: 'monthly',
      interval: 1,
      by_setpos: 1,
      day_kind: 'weekday',
      time_of_day: '14:00',
    });
  });

  it('reads a cleared interval box as every period', () => {
    expect(recurrenceToWire(rec({ repeat: 'daily', interval: 0 })).interval).toBe(1);
    expect(recurrenceToWire(rec({ repeat: 'daily', interval: NaN })).interval).toBe(1);
  });
});

describe('recurrenceFromWire', () => {
  const base = defaultRecurrence();

  it('round-trips every recurrence the controls can state', () => {
    const cases: WireRecurrence[] = [
      { freq: 'daily', interval: 1, time_of_day: '09:00' },
      { freq: 'daily', interval: 3, time_of_day: '23:45' },
      { freq: 'weekly', interval: 1, by_weekday: [1, 3], time_of_day: '14:00' },
      { freq: 'weekly', interval: 2, by_weekday: [2], time_of_day: '14:00' },
      { freq: 'monthly', interval: 1, by_monthday: [1, 15], time_of_day: '08:30' },
      { freq: 'monthly', interval: 1, by_setpos: -1, by_weekday: [5], time_of_day: '10:00' },
      { freq: 'monthly', interval: 2, by_setpos: -2, by_weekday: [0], time_of_day: '10:00' },
      { freq: 'monthly', interval: 1, by_setpos: 1, day_kind: 'weekday', time_of_day: '07:00' },
      { freq: 'monthly', interval: 1, by_setpos: 5, day_kind: 'weekend', time_of_day: '07:00' },
    ];
    for (const wire of cases) {
      const { rec: back, exact } = recurrenceFromWire(wire, base, 0);
      expect(exact, JSON.stringify(wire)).toBe(true);
      expect(recurrenceToWire(back), JSON.stringify(wire)).toEqual(wire);
    }
  });

  it('shows a single daily window as a one-off, which is what it is', () => {
    const wire: WireRecurrence = { freq: 'daily', interval: 1, time_of_day: '14:00' };
    expect(recurrenceFromWire(wire, base, 1).rec.repeat).toBe('once');
    expect(recurrenceFromWire(wire, base, 0).rec.repeat).toBe('daily');
  });

  it('reports a recurrence the controls cannot state rather than drawing the nearest one', () => {
    // Monthly weekdays with no position to count them to: the server
    // takes it, these controls have no way to say it, and showing it as
    // a position would make the next save a silent edit.
    const wire: WireRecurrence = {
      freq: 'monthly',
      interval: 1,
      by_weekday: [1, 3],
      time_of_day: '14:00',
    };
    expect(recurrenceFromWire(wire, base, 0).exact).toBe(false);
  });

  it('is not fooled by a spelling the controls would normalise', () => {
    // Ticked in another order and with the interval left out: the same
    // recurrence, so it is still exact.
    const wire: WireRecurrence = {
      freq: 'weekly',
      interval: 0,
      by_weekday: [3, 1, 3],
      time_of_day: '14:00',
    };
    const { rec: back, exact } = recurrenceFromWire(wire, base, 0);
    expect(exact).toBe(true);
    expect(back.weekdays).toEqual([1, 3]);
  });

  it('keeps the position weekday when a category takes over, and gives it back', () => {
    const wire: WireRecurrence = {
      freq: 'monthly',
      interval: 1,
      by_setpos: 1,
      by_weekday: [4],
      time_of_day: '14:00',
    };
    const { rec: back } = recurrenceFromWire(wire, base, 0);
    expect(setposDayValue(back)).toBe('4');
    const asKind = withSetposDay(back, 'weekend');
    expect(setposDayValue(asKind)).toBe('weekend');
    expect(setposDayValue(withSetposDay(asKind, '4'))).toBe('4');
  });
});

describe('draftFromReservation', () => {
  it('opens on the stored recurrence', () => {
    const d = draftFromReservation(
      reservation({
        schedule_kind: 'recurrence',
        schedule: '',
        recurrence: { freq: 'weekly', interval: 2, by_weekday: [2], time_of_day: '14:00' },
        starts_at: '2026-09-02T14:00:00-05:00',
      }),
    );
    expect(d.kind).toBe('recurrence');
    expect(repeatChoice(d)).toBe('weekly');
    expect(d.rec.interval).toBe(2);
    expect(d.rec.weekdays).toEqual([2]);
    expect(d.rec.startDate).toBe('2026-09-02');
    expect(d.stored).toBeNull();
  });

  it('keeps a recurrence the controls cannot state, verbatim', () => {
    const stored: WireRecurrence = {
      freq: 'monthly',
      interval: 1,
      by_weekday: [1, 3],
      time_of_day: '14:00',
    };
    const d = draftFromReservation(
      reservation({ schedule_kind: 'recurrence', recurrence: stored }),
    );
    expect(d.stored).toEqual(stored);
    // And it is what goes back on the wire, so opening the form and
    // saving does not rewrite it.
    expect(scheduleFields(d, CHICAGO).recurrence).toEqual(stored);
  });

  it('reads a reservation stored before the recurrence existed as cron', () => {
    expect(draftFromReservation(reservation({ schedule_kind: '' })).kind).toBe('cron');
    expect(repeatChoice(draftFromReservation(reservation()))).toBe('custom');
  });

  it('opens an always-on reservation on the control that says so', () => {
    const d = draftFromReservation(
      reservation({ schedule_kind: 'always', schedule: '' }),
    );
    expect(repeatChoice(d)).toBe('always');
  });

  it('reads the bounds back into the end controls', () => {
    const until = draftFromReservation(
      reservation({ ends_at: '2026-12-11T23:59:59-06:00' }),
    );
    expect(until.rec.end).toBe('on');
    expect(until.rec.endDate).toBe('2026-12-11');

    const count = draftFromReservation(reservation({ occurrences: 6 }));
    expect(count.rec.end).toBe('after');
    expect(count.rec.occurrences).toBe(6);

    expect(draftFromReservation(reservation()).rec.end).toBe('never');
  });

  it('reads the start bound in the reservation zone, not the browser one', () => {
    const d = draftFromReservation(
      reservation({ timezone: 'Asia/Tokyo', starts_at: '2026-09-02T09:00:00+09:00' }),
    );
    expect(d.rec.startDate).toBe('2026-09-02');
    expect(d.rec.startTime).toBe('09:00');
  });

  it('falls back to a stated default time rather than midnight', () => {
    expect(draftFromReservation(reservation()).rec.startTime).toBe(DEFAULT_START_TIME);
  });
});

describe('switching between the ways a reservation is timed', () => {
  it('loses nothing on the way out to the expression and back', () => {
    const picked = withRecurrence(draft(), rec({ weekdays: [1, 3, 5] }), CHICAGO);
    const typed = withCron(picked, '*/15 9-17 * * 1-5');
    expect(typed.kind).toBe('cron');
    // The whole complaint: the repeat is still exactly where it was.
    expect(typed.rec).toEqual(picked.rec);

    const back = withRepeatChoice(typed, 'weekly', CHICAGO);
    expect(back.kind).toBe('recurrence');
    expect(back.rec.weekdays).toEqual([1, 3, 5]);
    // And the expression is still there to go back to.
    expect(back.cron).toBe('*/15 9-17 * * 1-5');
  });

  it('keeps the expression across always-on as well', () => {
    const typed = withCron(draft(), '0 14 * * 1,3');
    const always = withRepeatChoice(typed, 'always', CHICAGO);
    expect(always.kind).toBe('always');
    expect(always.cron).toBe('0 14 * * 1,3');
    expect(withRepeatChoice(always, 'custom', CHICAGO).cron).toBe('0 14 * * 1,3');
  });

  it('never derives one from the other', () => {
    // Nothing writes the cron box from the controls. If it did, a
    // recurrence saying "every other Tuesday" would have to be rounded
    // to an expression that runs on different days.
    const d = withRecurrence(
      draft({ cron: '0 14 * * 1,3' }),
      rec({ interval: 2, weekdays: [2], startDate: '2026-09-02' }),
      CHICAGO,
    );
    expect(d.cron).toBe('0 14 * * 1,3');
  });

  it('drops a recurrence it cannot state as soon as a control is used', () => {
    const d = draft({
      stored: { freq: 'monthly', interval: 1, by_weekday: [1, 3], time_of_day: '14:00' },
    });
    expect(withRecurrence(d, rec({ repeat: 'daily' }), CHICAGO).stored).toBeNull();
  });
});

describe('withBounds', () => {
  it('leaves the expression in charge, because a bound is not a schedule', () => {
    const typed = withCron(draft(), '*/15 9-17 * * 1-5');
    const bounded = withBounds(typed, { ...typed.rec, end: 'after', occurrences: 3 }, CHICAGO);
    expect(bounded.kind).toBe('cron');
    expect(scheduleFields(bounded, CHICAGO).schedule).toBe('*/15 9-17 * * 1-5');
    expect(bounded.rec.occurrences).toBe(3);
  });

  it('leaves an always-on reservation always on', () => {
    const always = withRepeatChoice(draft(), 'always', CHICAGO);
    expect(
      withBounds(always, { ...always.rec, endDate: '2026-12-11', end: 'on' }, CHICAGO).kind,
    ).toBe('always');
  });

  it('keeps a recurrence it cannot state, which the bound says nothing about', () => {
    const stored: WireRecurrence = {
      freq: 'monthly',
      interval: 1,
      by_weekday: [1, 3],
      time_of_day: '14:00',
    };
    const d = draft({ stored });
    expect(withBounds(d, { ...d.rec, endDate: '2026-12-11' }, CHICAGO).stored).toEqual(stored);
  });

  it('asks for a start date once, and does not put one back over a clearing', () => {
    // Raising the interval fills the anchor in; clearing it then has to
    // stay cleared, or the form could never say it was needed.
    const raised = withRecurrence(draft(), rec({ interval: 2 }), CHICAGO);
    expect(raised.rec.startDate).not.toBe('');
    const cleared = withBounds(raised, { ...raised.rec, startDate: '' }, CHICAGO);
    expect(cleared.rec.startDate).toBe('');
    expect(scheduleNeeds(cleared).map((n) => n.field)).toEqual(['start']);
  });
});

describe('withRecurrence', () => {
  it('does not put a day of the month back over an unticking', () => {
    // Otherwise the last day of the month cannot be removed, and the
    // form can never ask which days are wanted.
    const monthly = withRepeatChoice(
      draft({ rec: rec({ startDate: '2026-09-17' }) }),
      'monthly',
      CHICAGO,
    );
    expect(monthly.rec.monthdays).toEqual([17]);
    const emptied = withRecurrence(monthly, toggleMonthday(monthly.rec, 17), CHICAGO);
    expect(emptied.rec.monthdays).toEqual([]);
  });

  it('bounds a one-off to a single window, as state rather than as a guess', () => {
    const d = withRepeatChoice(draft(), 'once', CHICAGO);
    expect(d.rec.end).toBe('after');
    expect(d.rec.occurrences).toBe(1);
    expect(d.rec.startDate).not.toBe('');
  });

  it('fills in an anchor for the repeats that are counted from one', () => {
    const today = todayInZone(CHICAGO);
    // "Every other week" has no meaning until somebody says which week,
    // so the week is filled in where it can be seen and changed.
    expect(withRecurrence(draft(), rec({ interval: 2 }), CHICAGO).rec.startDate).toBe(
      today,
    );
    expect(
      withRecurrence(draft(), rec({ end: 'after', occurrences: 5 }), CHICAGO).rec
        .startDate,
    ).toBe(today);
    // And not for the ones that are not.
    expect(withRecurrence(draft(), rec(), CHICAGO).rec.startDate).toBe('');
  });

  it('defaults a monthly recurrence to the start date it already has', () => {
    const d = withRepeatChoice(
      draft({ rec: rec({ startDate: '2026-09-17' }) }),
      'monthly',
      CHICAGO,
    );
    expect(d.rec.monthdays).toEqual([17]);
    expect(d.rec.startDate).toBe('2026-09-17');
  });

  it('leaves the dates already chosen alone', () => {
    const d = withRepeatChoice(
      draft({ rec: rec({ startDate: '2026-09-17', monthdays: [1, 15] }) }),
      'monthly',
      CHICAGO,
    );
    expect(d.rec.monthdays).toEqual([1, 15]);
  });
});

describe('the day toggles', () => {
  it('tick and untick, and stay in the order occurrences happen in', () => {
    expect(toggleWeekday(rec({ weekdays: [1, 3] }), 5).weekdays).toEqual([1, 3, 5]);
    expect(toggleWeekday(rec({ weekdays: [1, 3] }), 0).weekdays).toEqual([0, 1, 3]);
    expect(toggleWeekday(rec({ weekdays: [1, 3] }), 1).weekdays).toEqual([3]);
    expect(toggleMonthday(rec({ monthdays: [15] }), 1).monthdays).toEqual([1, 15]);
    expect(toggleMonthday(rec({ monthdays: [1, 15] }), 15).monthdays).toEqual([1]);
  });
});

describe('scheduleNeeds', () => {
  it('requires a start date for an interval above one, against the date box', () => {
    const needs = scheduleNeeds(draft({ rec: rec({ interval: 2 }) }));
    expect(needs).toHaveLength(1);
    expect(needs[0].field).toBe('start');
    expect(needs[0].message).toContain('every 2 weeks');
  });

  it('requires one for a count of windows too', () => {
    const needs = scheduleNeeds(draft({ rec: rec({ end: 'after', occurrences: 4 }) }));
    expect(needs.map((n) => n.field)).toEqual(['start']);
  });

  it('asks a weekly recurrence which day, and a monthly one which date', () => {
    expect(
      scheduleNeeds(draft({ rec: rec({ weekdays: [] }) })).map((n) => n.message),
    ).toEqual(['Choose at least one day of the week.']);
    expect(
      scheduleNeeds(
        draft({ rec: rec({ repeat: 'monthly', monthlyMode: 'monthday', monthdays: [] }) }),
      ).map((n) => n.message),
    ).toEqual(['Choose at least one day of the month.']);
    // A position needs no date: it finds its own day within the month.
    expect(
      scheduleNeeds(
        draft({ rec: rec({ repeat: 'monthly', monthlyMode: 'setpos', monthdays: [] }) }),
      ),
    ).toEqual([]);
  });

  it('asks nothing of an always-on reservation, which has no schedule to finish', () => {
    expect(
      scheduleNeeds(draft({ kind: 'always', rec: rec({ interval: 2, weekdays: [] }) })),
    ).toEqual([]);
  });

  it('asks nothing of an expression, which only the server can read', () => {
    expect(
      scheduleNeeds(draft({ kind: 'cron', cron: '*/15 9-17 * * 1-5', rec: rec({ weekdays: [] }) })),
    ).toEqual([]);
  });

  it('says nothing about a recurrence it is keeping verbatim', () => {
    // The controls are not what is being sent, so asking them to be
    // filled in would block a save that was going to be correct.
    const d = draft({
      rec: rec({ repeat: 'monthly', monthlyMode: 'monthday', monthdays: [] }),
      stored: { freq: 'monthly', interval: 1, by_weekday: [1], time_of_day: '14:00' },
    });
    expect(scheduleNeeds(d)).toEqual([]);
  });

  it('is satisfied by a start date, whichever way it got there', () => {
    expect(scheduleNeeds(draft({ rec: rec({ interval: 2, startDate: '2026-09-02' }) }))).toEqual(
      [],
    );
  });
});

describe('scheduleFields', () => {
  it('sends the recurrence, and nothing of the expression behind it', () => {
    const out = scheduleFields(
      draft({ cron: '0 14 * * 1,3', rec: rec({ startDate: '2026-09-02' }) }),
      CHICAGO,
    );
    expect(out.schedule_kind).toBe('recurrence');
    expect(out.schedule).toBe('');
    expect(out.recurrence).toEqual({
      freq: 'weekly',
      interval: 1,
      by_weekday: [1, 3],
      time_of_day: '14:00',
    });
    expect(out.starts_at).toBe('2026-09-02T14:00:00-05:00');
  });

  it('sends the expression, and no recurrence, when the expression is the schedule', () => {
    const out = scheduleFields(
      draft({ kind: 'cron', cron: '  */15 9-17 * * 1-5  ' }),
      CHICAGO,
    );
    expect(out.schedule_kind).toBe('cron');
    expect(out.schedule).toBe('*/15 9-17 * * 1-5');
    expect(out.recurrence).toBeNull();
  });

  it('sends neither for an always-on reservation, and no count of windows', () => {
    const out = scheduleFields(
      draft({
        kind: 'always',
        cron: '0 14 * * 1,3',
        rec: rec({ startDate: '2026-09-02', end: 'after', occurrences: 6 }),
      }),
      CHICAGO,
    );
    expect(out.schedule_kind).toBe('always');
    expect(out.schedule).toBe('');
    expect(out.recurrence).toBeNull();
    // There are no occurrences to count, and sending the number left
    // over from another repeat is a 400 the operator never asked for.
    expect(out.occurrences).toBe(0);
    expect(out.starts_at).toBe('2026-09-02T14:00:00-05:00');
  });

  it('keeps an always-on end date, which is the one bound it does have', () => {
    const out = scheduleFields(
      draft({ kind: 'always', rec: rec({ end: 'on', endDate: '2026-12-11' }) }),
      CHICAGO,
    );
    expect(out.ends_at).toBe('2026-12-11T23:59:59-06:00');
    expect(out.occurrences).toBe(0);
  });
});

describe('recurrenceToBounds', () => {
  it('sets neither bound when the schedule never ends', () => {
    expect(recurrenceToBounds(rec({ end: 'never', startDate: '2026-09-02' }), CHICAGO)).toEqual({
      starts_at: '2026-09-02T14:00:00-05:00',
      ends_at: '',
      occurrences: 0,
    });
  });

  it('never sets both bounds at once, whatever the end mode', () => {
    const both = rec({ startDate: '2026-09-02', endDate: '2026-12-11', occurrences: 6 });
    for (const end of ['never', 'on', 'after'] as const) {
      const out = recurrenceToBounds({ ...both, end }, CHICAGO);
      expect(out.ends_at !== '' && out.occurrences > 0).toBe(false);
    }
  });

  it('ends on the last second of the chosen day, so that day still happens', () => {
    expect(recurrenceToBounds(rec({ end: 'on', endDate: '2026-12-11' }), CHICAGO).ends_at).toBe(
      '2026-12-11T23:59:59-06:00',
    );
  });

  it('counts windows, and counts at least one', () => {
    expect(recurrenceToBounds(rec({ end: 'after', occurrences: 6 }), CHICAGO).occurrences).toBe(6);
    expect(recurrenceToBounds(rec({ end: 'after', occurrences: 0 }), CHICAGO).occurrences).toBe(1);
    expect(recurrenceToBounds(rec({ end: 'after', occurrences: NaN }), CHICAGO).occurrences).toBe(1);
  });

  it('sends no start bound for a blank date', () => {
    expect(recurrenceToBounds(rec({ startDate: '' }), CHICAGO).starts_at).toBe('');
  });
});

describe('describeRecurrence', () => {
  it('says each shape the way an operator asked for it', () => {
    expect(describeRecurrence({ freq: 'daily', interval: 1, time_of_day: '09:00' })).toBe(
      'Every day',
    );
    expect(describeRecurrence({ freq: 'daily', interval: 3, time_of_day: '09:00' })).toBe(
      'Every 3 days',
    );
    expect(
      describeRecurrence({ freq: 'weekly', interval: 1, by_weekday: [1, 3], time_of_day: '09:00' }),
    ).toBe('Every week on Monday and Wednesday');
    expect(
      describeRecurrence({ freq: 'weekly', interval: 2, by_weekday: [2], time_of_day: '09:00' }),
    ).toBe('Every 2 weeks on Tuesday');
    expect(
      describeRecurrence({
        freq: 'weekly',
        interval: 1,
        by_weekday: [1, 3, 5],
        time_of_day: '09:00',
      }),
    ).toBe('Every week on Monday, Wednesday and Friday');
    expect(
      describeRecurrence({ freq: 'monthly', interval: 1, by_monthday: [1, 15], time_of_day: '09:00' }),
    ).toBe('The 1st and 15th of every month');
    expect(
      describeRecurrence({ freq: 'monthly', interval: 1, by_monthday: [3], time_of_day: '09:00' }),
    ).toBe('The 3rd of every month');
    expect(
      describeRecurrence({
        freq: 'monthly',
        interval: 1,
        by_setpos: -1,
        by_weekday: [5],
        time_of_day: '09:00',
      }),
    ).toBe('The last Friday of every month');
    expect(
      describeRecurrence({
        freq: 'monthly',
        interval: 1,
        by_setpos: -2,
        day_kind: 'weekend',
        time_of_day: '09:00',
      }),
    ).toBe('The next to last weekend day of every month');
    expect(
      describeRecurrence({
        freq: 'monthly',
        interval: 2,
        by_setpos: 1,
        day_kind: 'weekday',
        time_of_day: '09:00',
      }),
    ).toBe('The first weekday of every 2 months');
  });

  it('spells the awkward ordinals', () => {
    expect(
      describeRecurrence({
        freq: 'monthly',
        interval: 1,
        by_monthday: [2, 11, 12, 13, 22, 31],
        time_of_day: '09:00',
      }),
    ).toBe('The 2nd, 11th, 12th, 13th, 22nd and 31st of every month');
  });
});

describe('describeSchedule', () => {
  it('names each of the three ways a reservation is timed', () => {
    expect(describeSchedule(reservation())).toBe('0 14 * * 1,3');
    expect(describeSchedule(reservation({ schedule_kind: '' }))).toBe('0 14 * * 1,3');
    expect(describeSchedule(reservation({ schedule_kind: 'always', schedule: '' }))).toBe(
      'Always on',
    );
    expect(
      describeSchedule(
        reservation({
          schedule_kind: 'recurrence',
          schedule: '',
          recurrence: { freq: 'weekly', interval: 2, by_weekday: [2], time_of_day: '14:00' },
        }),
      ),
    ).toBe('Every 2 weeks on Tuesday');
  });
});

describe('whyNoWindows', () => {
  const now = Date.parse('2026-10-14T12:00:00-05:00');

  it('tells a reservation holding capacity right now from one that is over', () => {
    expect(whyNoWindows('always', reservation(), 14, now)).toContain('continuously');
    expect(
      whyNoWindows('recurrence', reservation({ ends_at: '2026-09-01T00:00:00-05:00' }), 14, now),
    ).toContain('has ended');
    expect(whyNoWindows('cron', reservation(), 14, now)).toBe(
      'Nothing scheduled in the next 14 days.',
    );
  });

  it('does not call a schedule over while its end is still ahead', () => {
    expect(
      whyNoWindows('recurrence', reservation({ ends_at: '2026-12-11T23:59:59-06:00' }), 14, now),
    ).toBe('Nothing scheduled in the next 14 days.');
  });

  it('says the same thing for a reservation whose kind the answer did not carry', () => {
    expect(whyNoWindows(undefined, reservation(), 30, now)).toBe(
      'Nothing scheduled in the next 30 days.',
    );
  });
});

describe('zonedRFC3339', () => {
  it('uses the offset the zone was on that day, not the one it is on now', () => {
    // Both are "09:00 in Chicago"; the offsets differ because one is in
    // daylight saving time and the other is not.
    expect(zonedRFC3339('2026-09-02', '09:00', CHICAGO)).toBe('2026-09-02T09:00:00-05:00');
    expect(zonedRFC3339('2026-12-11', '09:00', CHICAGO)).toBe('2026-12-11T09:00:00-06:00');
  });

  it('writes UTC as Z and a half-hour zone with its minutes', () => {
    expect(zonedRFC3339('2026-09-02', '09:00', 'UTC')).toBe('2026-09-02T09:00:00Z');
    expect(zonedRFC3339('2026-09-02', '09:00', 'Asia/Kolkata')).toBe(
      '2026-09-02T09:00:00+05:30',
    );
  });

  it('carries the seconds it is given', () => {
    expect(zonedRFC3339('2026-12-11', '23:59', CHICAGO, 59)).toBe('2026-12-11T23:59:59-06:00');
  });

  it('writes nothing for a date or time it cannot read', () => {
    expect(zonedRFC3339('', '09:00', CHICAGO)).toBe('');
    expect(zonedRFC3339('2026-09-02', '', CHICAGO)).toBe('');
  });
});

describe('zonedDateTime', () => {
  it('round-trips a bound through the wire and back', () => {
    for (const [date, time] of [
      ['2026-09-02', '14:00'],
      ['2026-12-11', '23:59'],
      ['2026-03-08', '09:00'],
    ] as const) {
      const iso = zonedRFC3339(date, time, CHICAGO);
      expect(zonedDateTime(iso, CHICAGO)).toEqual({ date, time });
    }
  });

  it('reads an instant in the zone that was asked for', () => {
    // 14:00 in Chicago is the next morning in Tokyo, which is the whole
    // reason the reservation carries a zone.
    expect(zonedDateTime('2026-09-02T14:00:00-05:00', 'Asia/Tokyo')).toEqual({
      date: '2026-09-03',
      time: '04:00',
    });
  });

  it('returns nothing for what is not a timestamp', () => {
    expect(zonedDateTime('', CHICAGO)).toBeNull();
    expect(zonedDateTime('never', CHICAGO)).toBeNull();
  });
});

describe('todayInZone', () => {
  it('names the day in the reservation zone', () => {
    // Just past midnight UTC: still yesterday in Chicago.
    const ms = Date.parse('2026-09-03T02:00:00Z');
    expect(todayInZone(CHICAGO, ms)).toBe('2026-09-02');
    expect(todayInZone('UTC', ms)).toBe('2026-09-03');
  });
});

describe('describeBounds', () => {
  it('says nothing about a schedule nothing stops', () => {
    expect(describeBounds(reservation())).toBe('');
  });

  it('names each bound', () => {
    expect(describeBounds(reservation({ starts_at: '2026-09-02T14:00:00-05:00' }))).toBe(
      'from Sep 2, 2026',
    );
    expect(describeBounds(reservation({ ends_at: '2026-12-11T23:59:59-06:00' }))).toBe(
      'until Dec 11, 2026',
    );
    expect(
      describeBounds(
        reservation({
          starts_at: '2026-09-02T14:00:00-05:00',
          ends_at: '2026-12-11T23:59:59-06:00',
        }),
      ),
    ).toBe('Sep 2, 2026 – Dec 11, 2026');
    expect(
      describeBounds(reservation({ starts_at: '2026-09-02T14:00:00-05:00', occurrences: 1 })),
    ).toBe('once, Sep 2, 2026');
    expect(
      describeBounds(reservation({ starts_at: '2026-09-02T14:00:00-05:00', occurrences: 6 })),
    ).toBe('6 windows from Sep 2, 2026');
  });
});
