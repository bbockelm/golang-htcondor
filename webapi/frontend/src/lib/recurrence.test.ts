import { describe, expect, it } from 'vitest';

import type { AdminReservation } from '@/lib/api';
import {
  DEFAULT_START_TIME,
  adoptCron,
  describeBounds,
  draftFromReservation,
  initialRecurrence,
  parseCron,
  parseTimeOfDay,
  recurrenceToBounds,
  recurrenceToCron,
  todayInZone,
  withCron,
  withPicker,
  withRecurrence,
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
  return {
    startDate: '',
    startTime: '14:00',
    repeat: 'weekly',
    weekdays: [1, 3],
    end: 'never',
    endDate: '',
    occurrences: 1,
    ...over,
  };
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
    schedule: '0 14 * * 1,3',
    timezone: CHICAGO,
    enabled: true,
    starts_at: '',
    ends_at: '',
    occurrences: 0,
    ...over,
  };
}

describe('parseTimeOfDay', () => {
  it('reads a time of day', () => {
    expect(parseTimeOfDay('14:00')).toEqual({ hour: 14, minute: 0 });
    expect(parseTimeOfDay('9:45')).toEqual({ hour: 9, minute: 45 });
    expect(parseTimeOfDay('00:00')).toEqual({ hour: 0, minute: 0 });
  });

  it('refuses what is not one', () => {
    // Seconds have nowhere to go: cron's finest field is the minute.
    expect(parseTimeOfDay('14:00:00')).toBeNull();
    expect(parseTimeOfDay('24:00')).toBeNull();
    expect(parseTimeOfDay('12:60')).toBeNull();
    expect(parseTimeOfDay('')).toBeNull();
    expect(parseTimeOfDay('2pm')).toBeNull();
  });
});

describe('recurrenceToCron', () => {
  it('writes the repeats the picker offers', () => {
    expect(recurrenceToCron(rec({ repeat: 'daily' }))).toBe('0 14 * * *');
    expect(recurrenceToCron(rec({ repeat: 'weekly', weekdays: [1, 3, 5] }))).toBe(
      '0 14 * * 1,3,5',
    );
    expect(
      recurrenceToCron(rec({ repeat: 'monthly', startDate: '2026-09-02' })),
    ).toBe('0 14 2 * *');
    expect(
      recurrenceToCron(rec({ repeat: 'never', startDate: '2026-09-02' })),
    ).toBe('0 14 2 9 *');
  });

  it('sorts and dedupes the weekday toggles', () => {
    expect(recurrenceToCron(rec({ weekdays: [5, 1, 3, 1] }))).toBe('0 14 * * 1,3,5');
  });

  it('carries the minute through', () => {
    expect(recurrenceToCron(rec({ startTime: '09:30', repeat: 'daily' }))).toBe(
      '30 9 * * *',
    );
  });

  it('writes nothing for a state that is not a schedule yet', () => {
    // A weekly repeat with no day ticked, and the two repeats that take
    // their day from a start date that is not set. Guessing one would
    // put a schedule on the wire nobody chose.
    expect(recurrenceToCron(rec({ repeat: 'weekly', weekdays: [] }))).toBeNull();
    expect(recurrenceToCron(rec({ repeat: 'monthly', startDate: '' }))).toBeNull();
    expect(recurrenceToCron(rec({ repeat: 'never', startDate: '' }))).toBeNull();
    expect(recurrenceToCron(rec({ startTime: 'half two' }))).toBeNull();
  });
});

describe('parseCron', () => {
  it('recognises the shapes the picker can draw', () => {
    expect(parseCron('0 14 * * *')).toMatchObject({ repeat: 'daily', time: '14:00' });
    expect(parseCron('0 14 * * 1,3')).toMatchObject({
      repeat: 'weekly',
      weekdays: [1, 3],
      time: '14:00',
    });
    expect(parseCron('30 9 2 * *')).toMatchObject({
      repeat: 'monthly',
      dayOfMonth: 2,
      time: '09:30',
    });
    expect(parseCron('0 14 2 9 *')).toMatchObject({
      repeat: 'never',
      dayOfMonth: 2,
      month: 9,
    });
  });

  it('declines everything it would have to redraw', () => {
    // Each of these is a legal schedule the picker has no control for,
    // or one it has a control for but a different spelling of.
    expect(parseCron('*/15 * * * *')).toBeNull();
    expect(parseCron('0 14 * * MON,WED')).toBeNull();
    expect(parseCron('0 14 * * 7')).toBeNull(); // Sunday, spelled the other way
    expect(parseCron('0 14 * * 3,1')).toBeNull(); // descending
    expect(parseCron('0 14 * * 1,1')).toBeNull(); // repeated
    expect(parseCron('0 14 1-5 * *')).toBeNull();
    expect(parseCron('0 14 * * 1,3 extra')).toBeNull();
    expect(parseCron('0 14 * *')).toBeNull();
    expect(parseCron('0 25 * * *')).toBeNull();
    expect(parseCron('60 14 * * *')).toBeNull();
    expect(parseCron('0 14 0 * *')).toBeNull();
    expect(parseCron('0 14 1 13 *')).toBeNull();
    expect(parseCron('0 14 1 1 1')).toBeNull(); // every field pinned at once
    expect(parseCron('')).toBeNull();
  });
});

describe('adoptCron', () => {
  it('round-trips every expression it accepts', () => {
    const cases: [string, Recurrence][] = [
      ['0 14 * * *', rec()],
      ['0 14 * * 1,3,5', rec()],
      ['45 6 * * 0,6', rec()],
      ['30 9 2 * *', rec({ startDate: '2026-09-02' })],
      ['0 14 2 9 *', rec({ startDate: '2026-09-02' })],
    ];
    for (const [cron, base] of cases) {
      const adopted = adoptCron(cron, base);
      expect(adopted, cron).not.toBeNull();
      expect(recurrenceToCron(adopted!)).toBe(cron);
    }
  });

  it('refuses an expression it would come back as something else', () => {
    // The whole point of the regeneration check: both of these parse,
    // and the picker would render both as `0 14 * * 1,3`. Opening a
    // reservation must not be a way to renumber its schedule.
    expect(adoptCron('0 14 * * 3,1', rec())).toBeNull();
    expect(adoptCron('00 14 * * 1,3', rec())).toBeNull();
  });

  it('tolerates the surrounding whitespace the form would trim anyway', () => {
    expect(adoptCron('  0 14 * * 1,3  ', rec())).not.toBeNull();
    // Inner spacing is a different matter: the picker only emits one
    // space, so reproducing this one is beyond it.
    expect(adoptCron('0  14 * * 1,3', rec())).toBeNull();
  });

  it('needs a start date to show a day-of-month expression', () => {
    expect(adoptCron('30 9 2 * *', rec({ startDate: '' }))).toBeNull();
    expect(adoptCron('30 9 2 * *', rec({ startDate: '2026-09-17' }))).toBeNull();
    expect(adoptCron('0 14 2 9 *', rec({ startDate: '2026-10-02' }))).toBeNull();
  });

  it('takes the time of day from the expression, not from the state', () => {
    const adopted = adoptCron('30 7 * * 2', rec({ startTime: '14:00' }));
    expect(adopted?.startTime).toBe('07:30');
    expect(adopted?.weekdays).toEqual([2]);
  });
});

describe('initialRecurrence', () => {
  it('opens the picker on a schedule it can draw', () => {
    const { rec: r, custom } = initialRecurrence(reservation());
    expect(custom).toBe(false);
    expect(r.repeat).toBe('weekly');
    expect(r.weekdays).toEqual([1, 3]);
    expect(r.startTime).toBe('14:00');
  });

  it('leaves an expression it cannot draw in the cron box', () => {
    const { custom } = initialRecurrence(reservation({ schedule: '*/15 9-17 * * 1-5' }));
    expect(custom).toBe(true);
  });

  it('treats a reservation with no schedule as one to pick, not one to type', () => {
    const { rec: r, custom } = initialRecurrence(reservation({ schedule: '' }));
    expect(custom).toBe(false);
    expect(r.startTime).toBe(DEFAULT_START_TIME);
    expect(r.weekdays).toEqual([]);
  });

  it('reads the bounds back into the end controls', () => {
    const until = initialRecurrence(
      reservation({ ends_at: '2026-12-11T23:59:59-06:00' }),
    ).rec;
    expect(until.end).toBe('on');
    expect(until.endDate).toBe('2026-12-11');

    const after = initialRecurrence(reservation({ occurrences: 6 })).rec;
    expect(after.end).toBe('after');
    expect(after.occurrences).toBe(6);

    expect(initialRecurrence(reservation()).rec.end).toBe('never');
  });

  it('reads the start bound in the reservation zone, not the browser one', () => {
    const r = initialRecurrence(
      reservation({ starts_at: '2026-09-02T14:00:00-05:00' }),
    ).rec;
    expect(r.startDate).toBe('2026-09-02');
  });

  it('will not call an unbounded annual expression a one-off', () => {
    // `0 14 2 9 *` fires every September. Drawn as "does not repeat" it
    // would pick up a bound of one window on the next save, which is a
    // change to the schedule nobody asked for.
    const bounded = reservation({
      schedule: '0 14 2 9 *',
      starts_at: '2026-09-02T14:00:00-05:00',
      occurrences: 1,
    });
    expect(initialRecurrence(bounded).custom).toBe(false);
    expect(initialRecurrence(bounded).rec.repeat).toBe('never');

    const unbounded = { ...bounded, occurrences: 0 };
    expect(initialRecurrence(unbounded).custom).toBe(true);
  });
});

describe('recurrenceToBounds', () => {
  it('sets neither bound when the schedule never ends', () => {
    expect(recurrenceToBounds(rec({ end: 'never' }), CHICAGO)).toEqual({
      starts_at: '',
      ends_at: '',
      occurrences: 0,
    });
  });

  it('never sets both bounds at once, whatever the end mode', () => {
    // The server refuses a reservation carrying both, so the form must
    // be structurally incapable of sending one.
    for (const end of ['never', 'on', 'after'] as const) {
      const b = recurrenceToBounds(
        rec({ end, startDate: '2026-09-02', endDate: '2026-12-11', occurrences: 4 }),
        CHICAGO,
      );
      expect(b.ends_at !== '' && b.occurrences > 0, end).toBe(false);
    }
  });

  it('writes the start at the time of day the schedule fires', () => {
    const b = recurrenceToBounds(
      rec({ startDate: '2026-09-02', startTime: '14:00' }),
      CHICAGO,
    );
    expect(b.starts_at).toBe('2026-09-02T14:00:00-05:00');
  });

  it('ends on the last second of the chosen day, so that day still happens', () => {
    const b = recurrenceToBounds(
      rec({ end: 'on', endDate: '2026-12-11' }),
      CHICAGO,
    );
    expect(b.ends_at).toBe('2026-12-11T23:59:59-06:00');
    expect(b.occurrences).toBe(0);
  });

  it('counts windows, and counts at least one', () => {
    expect(recurrenceToBounds(rec({ end: 'after', occurrences: 6 }), CHICAGO)).toEqual({
      starts_at: '',
      ends_at: '',
      occurrences: 6,
    });
    expect(
      recurrenceToBounds(rec({ end: 'after', occurrences: 0 }), CHICAGO).occurrences,
    ).toBe(1);
    expect(
      recurrenceToBounds(rec({ end: 'after', occurrences: NaN }), CHICAGO).occurrences,
    ).toBe(1);
  });

  it('sends no start bound for a blank date', () => {
    expect(recurrenceToBounds(rec({ startDate: '' }), CHICAGO).starts_at).toBe('');
  });
});

describe('zonedRFC3339', () => {
  it('uses the offset the zone was on that day, not the one it is on now', () => {
    // The same wall-clock hour, either side of a daylight-saving
    // change. Writing both with one offset would move one of them by an
    // hour -- which is exactly what the zone field exists to prevent.
    expect(zonedRFC3339('2026-07-15', '14:00', CHICAGO)).toBe('2026-07-15T14:00:00-05:00');
    expect(zonedRFC3339('2026-01-15', '14:00', CHICAGO)).toBe('2026-01-15T14:00:00-06:00');
  });

  it('writes UTC as Z and a half-hour zone with its minutes', () => {
    expect(zonedRFC3339('2026-07-15', '14:00', 'UTC')).toBe('2026-07-15T14:00:00Z');
    expect(zonedRFC3339('2026-07-15', '14:00', 'Asia/Kolkata')).toBe(
      '2026-07-15T14:00:00+05:30',
    );
  });

  it('carries the seconds it is given', () => {
    expect(zonedRFC3339('2026-07-15', '23:59', 'UTC', 59)).toBe('2026-07-15T23:59:59Z');
  });

  it('writes nothing for a date or time it cannot read', () => {
    expect(zonedRFC3339('', '14:00', CHICAGO)).toBe('');
    expect(zonedRFC3339('2026-07-15', '', CHICAGO)).toBe('');
  });
});

describe('zonedDateTime', () => {
  it('round-trips a bound through the wire and back', () => {
    for (const [date, time] of [
      ['2026-07-15', '14:00'],
      ['2026-01-15', '14:00'],
      ['2026-03-08', '23:45'],
    ] as const) {
      const iso = zonedRFC3339(date, time, CHICAGO);
      expect(zonedDateTime(iso, CHICAGO)).toEqual({ date, time });
    }
  });

  it('reads an instant in the zone that was asked for', () => {
    // Late evening in Chicago is the next day in UTC, and a date box
    // showing the wrong day is a whole window in the wrong place.
    const iso = '2026-07-15T23:00:00-05:00';
    expect(zonedDateTime(iso, CHICAGO)).toEqual({ date: '2026-07-15', time: '23:00' });
    expect(zonedDateTime(iso, 'UTC')).toEqual({ date: '2026-07-16', time: '04:00' });
  });

  it('returns nothing for what is not a timestamp', () => {
    expect(zonedDateTime('', CHICAGO)).toBeNull();
    expect(zonedDateTime('next tuesday', CHICAGO)).toBeNull();
  });
});

describe('todayInZone', () => {
  it('names the day in the reservation zone', () => {
    const justAfterMidnightChicago = Date.parse('2026-07-16T00:30:00-05:00');
    expect(todayInZone(CHICAGO, justAfterMidnightChicago)).toBe('2026-07-16');
    expect(todayInZone('UTC', justAfterMidnightChicago)).toBe('2026-07-16');
    expect(todayInZone('America/Los_Angeles', justAfterMidnightChicago)).toBe(
      '2026-07-15',
    );
  });
});

describe('the draft the form holds', () => {
  const draft = (over: Partial<AdminReservation> = {}): ScheduleDraft =>
    draftFromReservation(reservation(over));

  it('regenerates the expression as the controls move', () => {
    let d = draft({ schedule: '', starts_at: '' });
    expect(d.cron).toBe('');
    d = withRecurrence(d, { ...d.rec, weekdays: [1, 3, 5] }, CHICAGO);
    expect(d.cron).toBe('0 9 * * 1,3,5');
    d = withRecurrence(d, { ...d.rec, startTime: '14:15' }, CHICAGO);
    expect(d.cron).toBe('15 14 * * 1,3,5');
  });

  it('fills in a date for the repeats that need one, where it can be seen', () => {
    const d = withRecurrence(
      draft({ schedule: '', starts_at: '' }),
      { ...draft({ schedule: '' }).rec, repeat: 'monthly', startDate: '' },
      CHICAGO,
    );
    expect(d.rec.startDate).not.toBe('');
    expect(d.cron).not.toBe('');
  });

  it('bounds a one-off to a single window, as state rather than as a guess', () => {
    const d = withRecurrence(
      draft({ schedule: '' }),
      { ...draft({ schedule: '' }).rec, repeat: 'never', startDate: '2026-09-02' },
      CHICAGO,
    );
    expect(d.cron).toBe('0 9 2 9 *');
    expect(d.rec.end).toBe('after');
    expect(d.rec.occurrences).toBe(1);
    expect(recurrenceToBounds(d.rec, CHICAGO).occurrences).toBe(1);
  });

  it('hands control to the cron box the moment somebody types in it', () => {
    const d = withCron(draft(), '*/15 9-17 * * 1-5');
    expect(d.custom).toBe(true);
    expect(d.cron).toBe('*/15 9-17 * * 1-5');
  });

  it('never rewrites a typed expression from the controls', () => {
    // The repeat and the time of day are the expression; while the cron
    // box is in charge, moving them changes nothing on the wire.
    let d = withCron(draft(), '*/15 9-17 * * 1-5');
    d = withRecurrence(d, { ...d.rec, repeat: 'daily', startTime: '03:00' }, CHICAGO);
    expect(d.cron).toBe('*/15 9-17 * * 1-5');
    expect(d.custom).toBe(true);
  });

  it('keeps the bounds live over a typed expression', () => {
    // A start and an end are limits on the expression rather than part
    // of it, so hand-writing cron is no reason to lose them.
    let d = withCron(draft(), '*/15 9-17 * * 1-5');
    d = withRecurrence(d, { ...d.rec, end: 'after', occurrences: 3 }, CHICAGO);
    expect(d.cron).toBe('*/15 9-17 * * 1-5');
    expect(recurrenceToBounds(d.rec, CHICAGO).occurrences).toBe(3);
  });

  it('gives the controls back only when asked, and keeps what it can', () => {
    let d = withCron(draft({ schedule: '' }), '45 6 * * 2,4');
    expect(d.custom).toBe(true);
    d = withPicker(d, CHICAGO);
    expect(d.custom).toBe(false);
    // Adopted rather than discarded: the schedule was typed, but it is
    // one the controls can show.
    expect(d.rec.weekdays).toEqual([2, 4]);
    expect(d.rec.startTime).toBe('06:45');
    expect(d.cron).toBe('45 6 * * 2,4');
  });

  it('replaces an expression the controls cannot show, and only then', () => {
    let d = withCron(draft({ schedule: '' }), '*/15 9-17 * * 1-5');
    d = withPicker(d, CHICAGO);
    expect(d.custom).toBe(false);
    expect(d.cron).not.toBe('*/15 9-17 * * 1-5');
  });
});

describe('describeBounds', () => {
  it('says nothing about a schedule nothing stops', () => {
    expect(describeBounds(reservation())).toBe('');
  });

  it('names each bound', () => {
    expect(describeBounds(reservation({ occurrences: 1 }))).toBe('once');
    expect(describeBounds(reservation({ occurrences: 4 }))).toBe('4 windows');
    expect(
      describeBounds(reservation({ ends_at: '2026-12-11T23:59:59-06:00' })),
    ).toBe('until Dec 11, 2026');
    expect(
      describeBounds(
        reservation({
          starts_at: '2026-09-02T14:00:00-05:00',
          ends_at: '2026-12-11T23:59:59-06:00',
        }),
      ),
    ).toBe('Sep 2, 2026 – Dec 11, 2026');
  });
});
