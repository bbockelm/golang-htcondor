'use client';

// The schedule controls on the reservations form: when the first window
// is, how it repeats, and what stops it.
//
// Laid out the way a calendar application lays out an event editor --
// Starts, Repeat, End repeat, each on its own row -- because that is
// the shape operators already know, and because a timetable is the
// thing a reservation almost always is.
//
// The cron box stays, under the picker rather than instead of it. The
// server reads cron and only cron, so showing the expression the picker
// produced is the only way an operator can check it; and cron says
// things the picker cannot, so typing into the box takes the picker out
// of the way rather than fighting it. See src/lib/recurrence.ts for the
// rule that keeps the two honest.

import {
  WEEKDAYS,
  withCron,
  withPicker,
  withRecurrence,
  type RepeatMode,
  type ScheduleDraft,
} from '@/lib/recurrence';

// Quarter hours. A class starts on one; the minute spinner that let
// somebody reach 14:07 by holding an arrow down was not helping.
const QUARTER_HOUR_SECONDS = 15 * 60;

const REPEATS: readonly { mode: RepeatMode; label: string }[] = [
  { mode: 'never', label: 'Does not repeat' },
  { mode: 'daily', label: 'Daily' },
  { mode: 'weekly', label: 'Weekly' },
  { mode: 'monthly', label: 'Monthly' },
] as const;

const boxCls =
  'rounded-sm border border-gray-300 px-2 py-1 text-sm focus:border-brand-400 focus:outline-hidden focus:ring-1 focus:ring-brand-400 disabled:bg-gray-100 disabled:text-gray-500';

// One labelled row. `htmlFor` is set where the row is a single box, so
// the label names it; the rows that are groups of controls leave it
// unset, since a label pointing at the first radio of a group would
// name the group after one of its options.
export function ScheduleRow({
  label,
  htmlFor,
  children,
}: {
  label: string;
  htmlFor?: string;
  children: React.ReactNode;
}) {
  const Tag = htmlFor ? 'label' : 'span';
  return (
    <div className="grid gap-1 sm:grid-cols-[7rem_1fr] sm:items-start sm:gap-3">
      <Tag htmlFor={htmlFor} className="pt-1 text-xs font-medium text-gray-700">
        {label}
      </Tag>
      <div className="min-w-0">{children}</div>
    </div>
  );
}

export function RecurrencePicker({
  value,
  onChange,
  timezone,
}: {
  value: ScheduleDraft;
  onChange: (next: ScheduleDraft) => void;
  // The zone the schedule is read in: the dates in these boxes are
  // wall-clock dates there, not in the browser's zone.
  timezone: string;
}) {
  const { rec, cron, custom } = value;
  const set = (patch: Partial<typeof rec>) =>
    onChange(withRecurrence(value, { ...rec, ...patch }, timezone));

  const toggleWeekday = (day: number) => {
    const next = rec.weekdays.includes(day)
      ? rec.weekdays.filter((d) => d !== day)
      : [...rec.weekdays, day].sort((a, b) => a - b);
    set({ weekdays: next });
  };

  return (
    <div data-testid="recurrence-picker" className="space-y-3">
      <ScheduleRow label="Starts">
        <div className="flex flex-wrap items-center gap-2">
          <input
            type="date"
            aria-label="Start date"
            value={rec.startDate}
            onChange={(e) => set({ startDate: e.target.value })}
            className={boxCls}
          />
          <span className="text-xs text-gray-500">at</span>
          <input
            type="time"
            aria-label="Start time"
            step={QUARTER_HOUR_SECONDS}
            value={rec.startTime}
            disabled={custom}
            onChange={(e) => set({ startTime: e.target.value })}
            className={boxCls}
          />
        </div>
        <span className="mt-1 block text-xs text-gray-500">
          Leave the date blank for a schedule that is already running.
        </span>
      </ScheduleRow>

      <ScheduleRow label="Repeat">
        <div className="flex flex-wrap items-center gap-x-4 gap-y-1">
          {REPEATS.map((r) => (
            <label key={r.mode} className="flex items-center gap-1.5 text-xs text-gray-800">
              <input
                type="radio"
                name="reservation-repeat"
                checked={!custom && rec.repeat === r.mode}
                onChange={() => set({ repeat: r.mode })}
                className="border-gray-300"
              />
              {r.label}
            </label>
          ))}
          <label className="flex items-center gap-1.5 text-xs text-gray-800">
            <input
              type="radio"
              name="reservation-repeat"
              checked={custom}
              onChange={() => onChange(withCron(value, cron))}
              className="border-gray-300"
            />
            Custom
          </label>
        </div>

        {!custom && rec.repeat === 'weekly' && (
          <div className="mt-2 flex flex-wrap gap-1">
            {WEEKDAYS.map((d) => {
              const on = rec.weekdays.includes(d.index);
              return (
                <button
                  // The letters repeat (two S, two T), so the name is
                  // what identifies the toggle to anything but an eye.
                  key={d.index}
                  type="button"
                  aria-label={d.name}
                  aria-pressed={on}
                  onClick={() => toggleWeekday(d.index)}
                  className={`h-7 w-7 rounded-full border text-xs font-medium ${
                    on
                      ? 'border-brand-600 bg-brand-600 text-white'
                      : 'border-gray-300 bg-white text-gray-700 hover:bg-gray-50'
                  }`}
                >
                  {d.letter}
                </button>
              );
            })}
          </div>
        )}

        {!custom && rec.repeat === 'monthly' && (
          <span className="mt-1 block text-xs text-gray-500">
            On the same day of the month as the start date.
          </span>
        )}
      </ScheduleRow>

      {/* A schedule that does not repeat has nothing to end. */}
      {(custom || rec.repeat !== 'never') && (
        <ScheduleRow label="End repeat">
          <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
            <label className="flex items-center gap-1.5 text-xs text-gray-800">
              <input
                type="radio"
                name="reservation-end"
                checked={rec.end === 'never'}
                onChange={() => set({ end: 'never' })}
                className="border-gray-300"
              />
              Never
            </label>
            <label className="flex items-center gap-1.5 text-xs text-gray-800">
              <input
                type="radio"
                name="reservation-end"
                checked={rec.end === 'on'}
                onChange={() => set({ end: 'on' })}
                className="border-gray-300"
              />
              On date
            </label>
            {/* Live whichever option is selected: filling one in is
                how somebody says they want it, so it also picks the
                option. A box that had to be unlocked first would make
                the radio a step rather than a statement. */}
            <input
              type="date"
              aria-label="Repeat until"
              value={rec.endDate}
              onChange={(e) => set({ end: 'on', endDate: e.target.value })}
              className={`${boxCls} ${rec.end === 'on' ? '' : 'text-gray-500'}`}
            />
            <label className="flex items-center gap-1.5 text-xs text-gray-800">
              <input
                type="radio"
                name="reservation-end"
                checked={rec.end === 'after'}
                onChange={() => set({ end: 'after' })}
                className="border-gray-300"
              />
              After
            </label>
            <span className="flex items-center gap-1.5 text-xs text-gray-800">
              <input
                type="number"
                min={1}
                aria-label="Number of windows"
                value={String(rec.occurrences)}
                onChange={(e) =>
                  set({ end: 'after', occurrences: Number(e.target.value) })
                }
                className={`w-16 ${boxCls} ${rec.end === 'after' ? '' : 'text-gray-500'}`}
              />
              windows
            </span>
          </div>
        </ScheduleRow>
      )}

      <ScheduleRow label="Schedule" htmlFor="reservation-schedule">
        <input
          id="reservation-schedule"
          type="text"
          value={cron}
          onChange={(e) => onChange(withCron(value, e.target.value))}
          placeholder="0 14 * * 1,3"
          className={`w-full font-mono ${boxCls}`}
        />
        {custom ? (
          <div className="mt-1 flex flex-wrap items-center gap-2 text-xs text-gray-500">
            <span>
              This schedule is set here. The repeat controls above are showing
              what it was.
            </span>
            <button
              type="button"
              onClick={() => onChange(withPicker(value, timezone))}
              className="rounded-sm border border-gray-300 bg-white px-2 py-0.5 text-gray-700 hover:bg-gray-50"
            >
              Set it above instead
            </button>
          </div>
        ) : (
          <span className="mt-1 block text-xs text-gray-500">
            Cron: minute, hour, day of month, month, day of week. Typing here
            takes over from the controls above.
          </span>
        )}
      </ScheduleRow>
    </div>
  );
}
