'use client';

// The schedule controls on the reservations form: when the first window
// is, how it repeats, and what stops it.
//
// Laid out the way a calendar application lays out a repeating event --
// Repeat, Starts, End repeat, each on its own row -- because that is the
// shape operators already know, and because a timetable is the thing a
// reservation almost always is. The repeat comes first here because it
// decides which of the rows below it mean anything.
//
// One radio group covers every way a reservation can be timed, including
// the two that are not repeats at all: held continuously, and timed by a
// cron expression typed by hand. They belong together because they are
// alternatives to each other, and because putting them in one group is
// what makes every one of them a click away from every other. The
// controls and the expression both stay in the draft whichever is
// selected, so choosing the wrong one costs nothing but another click.
//
// The expression box is shown only while the expression is the schedule.
// It is the one control here that needs to be learned, so it appears
// when it is being used and not before.

import {
  SETPOS_DAYS,
  SET_POSITIONS,
  WEEKDAYS,
  describeRecurrence,
  repeatChoice,
  scheduleNeeds,
  setposDayValue,
  toggleMonthday,
  toggleWeekday,
  withBounds,
  withCron,
  withRecurrence,
  withRepeatChoice,
  withSetposDay,
  type RepeatChoice,
  type ScheduleDraft,
} from '@/lib/recurrence';

// Quarter hours. A class starts on one; the minute spinner that let
// somebody reach 14:07 by holding an arrow down was not helping.
const QUARTER_HOUR_SECONDS = 15 * 60;

const REPEATS: readonly { choice: RepeatChoice; label: string }[] = [
  { choice: 'always', label: 'Always on' },
  { choice: 'once', label: 'Does not repeat' },
  { choice: 'daily', label: 'Daily' },
  { choice: 'weekly', label: 'Weekly' },
  { choice: 'monthly', label: 'Monthly' },
  { choice: 'custom', label: 'Custom' },
] as const;

// Which unit the "every N" counts, for the repeats that have one.
const INTERVAL_UNITS: Partial<Record<RepeatChoice, string>> = {
  daily: 'days',
  weekly: 'weeks',
  monthly: 'months',
};

const MONTH_DAYS = Array.from({ length: 31 }, (_, i) => i + 1);

const boxCls =
  'rounded-sm border border-gray-300 px-2 py-1 text-sm focus:border-brand-400 focus:outline-hidden focus:ring-1 focus:ring-brand-400 disabled:bg-gray-100 disabled:text-gray-500';

const toggleCls = (on: boolean) =>
  `rounded-full border text-xs font-medium ${
    on
      ? 'border-brand-600 bg-brand-600 text-white'
      : 'border-gray-300 bg-white text-gray-700 hover:bg-gray-50'
  }`;

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

function Hint({ children }: { children: React.ReactNode }) {
  return <span className="mt-1 block text-xs text-gray-500">{children}</span>;
}

// What the schedule still needs, where the control that needs it is.
function Needs({ messages }: { messages: string[] }) {
  if (messages.length === 0) return null;
  return (
    <span className="mt-1 block text-xs text-amber-700">{messages.join(' ')}</span>
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
  const { rec, cron, kind, stored } = value;
  const choice = repeatChoice(value);
  // Two setters, because the controls answer two different questions.
  // A repeat control describes the schedule, so using one replaces
  // whatever described it before; a start or end control bounds
  // whichever schedule is in force, so using one must not change which
  // that is.
  const setRepeat = (next: typeof rec) => onChange(withRecurrence(value, next, timezone));
  const repeat = (patch: Partial<typeof rec>) => setRepeat({ ...rec, ...patch });
  const bound = (patch: Partial<typeof rec>) =>
    onChange(withBounds(value, { ...rec, ...patch }, timezone));

  const needs = scheduleNeeds(value);
  const needed = (field: 'start' | 'repeat') =>
    needs.filter((n) => n.field === field).map((n) => n.message);
  const startNeeds = needed('start');
  const intervalUnit = INTERVAL_UNITS[choice];

  return (
    <div data-testid="recurrence-picker" className="space-y-3">
      <ScheduleRow label="Repeat">
        <div className="flex flex-wrap items-center gap-x-4 gap-y-1">
          {REPEATS.map((r) => (
            <label
              key={r.choice}
              className="flex items-center gap-1.5 text-xs text-gray-800"
            >
              <input
                type="radio"
                name="reservation-repeat"
                checked={choice === r.choice}
                onChange={() => onChange(withRepeatChoice(value, r.choice, timezone))}
                className="border-gray-300"
              />
              {r.label}
            </label>
          ))}
        </div>

        {intervalUnit && (
          <div className="mt-2 flex flex-wrap items-center gap-2 text-xs text-gray-800">
            <span>Every</span>
            <input
              type="number"
              min={1}
              max={52}
              aria-label="Repeat every"
              value={String(rec.interval)}
              onChange={(e) => repeat({ interval: Number(e.target.value) })}
              className={`w-16 ${boxCls}`}
            />
            <span>{intervalUnit}</span>
          </div>
        )}

        {stored && kind === 'recurrence' && (
          <div className="mt-2 rounded-sm border border-gray-200 bg-gray-50 px-2 py-1">
            <span className="block text-xs text-gray-800">
              {describeRecurrence(stored)}
            </span>
            <Hint>
              This schedule is kept as it is. Choosing a repeat above replaces it.
            </Hint>
          </div>
        )}

        {choice === 'weekly' && (
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
                  onClick={() => setRepeat(toggleWeekday(rec, d.index))}
                  className={`h-7 w-7 ${toggleCls(on)}`}
                >
                  {d.letter}
                </button>
              );
            })}
          </div>
        )}

        {choice === 'monthly' && (
          <div className="mt-2 space-y-2">
            <label className="flex items-center gap-1.5 text-xs text-gray-800">
              <input
                type="radio"
                name="reservation-monthly"
                checked={rec.monthlyMode === 'monthday'}
                onChange={() => repeat({ monthlyMode: 'monthday' })}
                className="border-gray-300"
              />
              On these dates
            </label>
            {rec.monthlyMode === 'monthday' && (
              <div className="grid grid-cols-7 gap-1 sm:w-max">
                {MONTH_DAYS.map((day) => {
                  const on = rec.monthdays.includes(day);
                  return (
                    <button
                      key={day}
                      type="button"
                      aria-label={`Day ${day} of the month`}
                      aria-pressed={on}
                      onClick={() => setRepeat(toggleMonthday(rec, day))}
                      className={`h-7 ${toggleCls(on)}`}
                    >
                      {day}
                    </button>
                  );
                })}
              </div>
            )}
            <label className="flex items-center gap-1.5 text-xs text-gray-800">
              <input
                type="radio"
                name="reservation-monthly"
                checked={rec.monthlyMode === 'setpos'}
                onChange={() => repeat({ monthlyMode: 'setpos' })}
                className="border-gray-300"
              />
              On the
            </label>
            {rec.monthlyMode === 'setpos' && (
              <div className="flex flex-wrap items-center gap-2">
                <select
                  aria-label="Which one in the month"
                  value={String(rec.setpos)}
                  onChange={(e) => repeat({ setpos: Number(e.target.value) })}
                  className={boxCls}
                >
                  {SET_POSITIONS.map((p) => (
                    <option key={p.value} value={p.value}>
                      {p.label}
                    </option>
                  ))}
                </select>
                <select
                  aria-label="Day of the month to count"
                  value={setposDayValue(rec)}
                  onChange={(e) => setRepeat(withSetposDay(rec, e.target.value))}
                  className={boxCls}
                >
                  {SETPOS_DAYS.map((d) => (
                    <option key={d.value} value={d.value}>
                      {d.label}
                    </option>
                  ))}
                </select>
              </div>
            )}
            <Hint>
              A month that does not reach the day chosen holds nothing: there is
              no 31st of February, and no fifth Monday in most months.
            </Hint>
          </div>
        )}

        {choice === 'always' && (
          <Hint>
            Capacity is held continuously, for as long as the reservation is
            enabled. There are no windows and nothing is drained ahead of one.
          </Hint>
        )}

        <Needs messages={needed('repeat')} />
      </ScheduleRow>

      <ScheduleRow label="Starts">
        <div className="flex flex-wrap items-center gap-2">
          <input
            type="date"
            aria-label="Start date"
            value={rec.startDate}
            onChange={(e) => bound({ startDate: e.target.value })}
            className={boxCls}
          />
          {/* The time of day is part of a recurrence and part of a cron
              expression, so it is a control only for the one this form
              states field by field. */}
          {kind === 'recurrence' && (
            <>
              <span className="text-xs text-gray-500">at</span>
              <input
                type="time"
                aria-label="Start time"
                step={QUARTER_HOUR_SECONDS}
                value={rec.startTime}
                onChange={(e) => repeat({ startTime: e.target.value })}
                className={boxCls}
              />
            </>
          )}
        </div>
        {startNeeds.length > 0 ? (
          <Needs messages={startNeeds} />
        ) : (
          <Hint>
            {kind === 'always'
              ? 'Leave the date blank to hold capacity from now on.'
              : 'Leave the date blank for a schedule that is already running.'}
          </Hint>
        )}
      </ScheduleRow>

      {/* A reservation held once has nothing to end. */}
      {choice !== 'once' && (
        <ScheduleRow label={kind === 'always' ? 'Ends' : 'End repeat'}>
          <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
            <label className="flex items-center gap-1.5 text-xs text-gray-800">
              <input
                type="radio"
                name="reservation-end"
                checked={rec.end === 'never'}
                onChange={() => bound({ end: 'never' })}
                className="border-gray-300"
              />
              Never
            </label>
            <label className="flex items-center gap-1.5 text-xs text-gray-800">
              <input
                type="radio"
                name="reservation-end"
                checked={rec.end === 'on'}
                onChange={() => bound({ end: 'on' })}
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
              onChange={(e) => bound({ end: 'on', endDate: e.target.value })}
              className={`${boxCls} ${rec.end === 'on' ? '' : 'text-gray-500'}`}
            />
            {/* A reservation with no windows has no windows to count. */}
            {kind !== 'always' && (
              <>
                <label className="flex items-center gap-1.5 text-xs text-gray-800">
                  <input
                    type="radio"
                    name="reservation-end"
                    checked={rec.end === 'after'}
                    onChange={() => bound({ end: 'after' })}
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
                      bound({ end: 'after', occurrences: Number(e.target.value) })
                    }
                    className={`w-16 ${boxCls} ${
                      rec.end === 'after' ? '' : 'text-gray-500'
                    }`}
                  />
                  windows
                </span>
              </>
            )}
          </div>
        </ScheduleRow>
      )}

      {kind === 'cron' && (
        <ScheduleRow label="Schedule" htmlFor="reservation-schedule">
          <input
            id="reservation-schedule"
            type="text"
            value={cron}
            onChange={(e) => onChange(withCron(value, e.target.value))}
            placeholder="0 14 * * 1,3"
            className={`w-full font-mono ${boxCls}`}
          />
          <Hint>
            Five fields: minute, hour, day of month, month, day of week.{' '}
            <a
              href="https://en.wikipedia.org/wiki/Cron"
              target="_blank"
              rel="noreferrer noopener"
              className="text-brand-700 underline"
            >
              What the fields mean
            </a>
            . Choosing another repeat above leaves this expression where it is.
          </Hint>
        </ScheduleRow>
      )}
    </div>
  );
}
