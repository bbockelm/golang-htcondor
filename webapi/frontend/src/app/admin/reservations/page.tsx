'use client';

// Reservations — recurring holds of pool capacity for a project.
//
// A reservation is, mostly, a class. The controller starts holding cores
// back `lead` before the window opens, frees `seats` of them by the bell,
// keeps the unclaimed ones for `hold`, and keeps `standing` seats between
// windows so the project's people can work. A job takes a seat by
// carrying the reservation's project as its ProjectName; the shape of a
// seat comes from the submit file.
//
// Two things drive the design:
//
//   * The windows preview is the page. A five-field cron expression is
//     not readable, so the table does not ask anyone to trust one: it
//     shows the next occurrences, and for each, both the bell and the
//     drain. The drain is when other people's jobs start being steered
//     away, hours before the class notices anything, so it is given the
//     same weight as the class time rather than hidden in a lead field.
//     For the same reason the form asks for the schedule the way a
//     calendar asks for a repeating event -- starts, repeats, ends --
//     and keeps the expression itself in a box beneath, where it can be
//     read, and typed, by anyone who needs cron to say something the
//     controls cannot.
//   * The server validates eagerly -- the cron, the zone, the submit
//     file, standing against seats -- and answers 400 with the reason.
//     The form shows that text verbatim. Restating it here in our own
//     words would drift from what the server actually enforces.

import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  ApiError,
  api,
  type AdminReservation,
  type AdminReservationWindow,
} from '@/lib/api';
import { ConfirmButton } from '@/components/ConfirmButton';
import {
  formatHoursMinutes,
  hoursMinutesToSeconds,
  splitHoursMinutes,
} from '@/lib/reservation';
import {
  describeBounds,
  draftFromReservation,
  recurrenceToBounds,
  type ScheduleDraft,
} from '@/lib/recurrence';
import { RecurrencePicker, ScheduleRow } from '@/components/RecurrencePicker';

// The browser's own zone, as the default for a new reservation: most
// reservations are for the pool the operator is sitting in.
function localZone(): string {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC';
  } catch {
    return 'UTC';
  }
}

function blankReservation(): AdminReservation {
  return {
    id: '',
    owner: '',
    project: '',
    // Something that renders: the server refuses a submit file with no
    // executable, since a seat with no Cmd matches nothing.
    submit: 'executable = /usr/bin/python3\nrequest_cpus = 1\nrequest_memory = 4096\nqueue\n',
    seats: 20,
    standing: 0,
    duration_seconds: 3600,
    // Six hours is where the measured benefit of leading saturates.
    lead_seconds: 6 * 3600,
    hold_seconds: 15 * 60,
    schedule: '',
    timezone: localZone(),
    enabled: true,
    // Unbounded until somebody says otherwise: a new reservation that
    // quietly started today and ran out after a term would be a
    // surprise nobody asked for.
    starts_at: '',
    ends_at: '',
    occurrences: 0,
  };
}

export default function AdminReservationsPage() {
  const qc = useQueryClient();
  const list = useQuery({
    queryKey: ['admin', 'reservations'],
    queryFn: api.admin.listReservations,
    retry: false,
  });

  // The reservation open in the form, if any. A blank ID means a new
  // one; editing an existing one starts from its stored values.
  const [draft, setDraft] = useState<AdminReservation | null>(null);
  // Whose upcoming windows are expanded. At most one at a time: two
  // open previews side by side invite comparing dates that are not
  // aligned, which is worse than scrolling.
  const [expanded, setExpanded] = useState<string | null>(null);

  const save = useMutation({
    mutationFn: (res: AdminReservation) => api.admin.putReservation(res),
    onSuccess: (saved) => {
      qc.invalidateQueries({ queryKey: ['admin', 'reservations'] });
      qc.invalidateQueries({ queryKey: ['admin', 'reservation-windows', saved.id] });
      setDraft(null);
      // Open the preview on what was just saved. The schedule was typed
      // as cron a second ago; this is the moment to show what it means.
      setExpanded(saved.id);
    },
  });

  const remove = useMutation({
    mutationFn: (id: string) => api.admin.deleteReservation(id),
    onSuccess: (_void, id) => {
      qc.invalidateQueries({ queryKey: ['admin', 'reservations'] });
      if (expanded === id) setExpanded(null);
    },
  });

  // A server with no application database has nowhere to keep
  // reservations and says so; that is a deployment fact, not an error
  // the operator can act on from here.
  const listError = list.error as ApiError | Error | null;
  const unavailable =
    listError instanceof ApiError && listError.status === 503 ? listError.message : null;

  const reservations = list.data?.reservations ?? [];

  // Polled rather than read once: the authorisation can be taken away
  // while the page is open, and an admin looking at a healthy-looking
  // list should find out.
  const health = useQuery({
    queryKey: ['admin', 'reservations', 'health'],
    queryFn: api.admin.reservationHealth,
    refetchInterval: 60_000,
    retry: false,
  });
  const unhealthy =
    health.data?.running && health.data?.healthy === false ? health.data : null;
  // Separate from unhealthy on purpose. This access point is working;
  // these execute points are not configured to consult the reservation
  // expression, so holding them does nothing. Telling an admin their
  // access point is broken would send them to look in the wrong place.
  const unprovisioned = health.data?.unprovisioned ?? [];

  return (
    <div className="max-w-6xl space-y-4">
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Reservations</h1>
        <p className="text-sm text-gray-500">
          Recurring holds of pool capacity for a project — a class, a
          demonstration, a deadline. The controller starts draining ahead of
          each window so the seats are free by the bell, and jobs claim them
          by carrying the project as their ProjectName.
        </p>
      </div>

      {unhealthy && (
        <div className="rounded-lg border border-amber-300 bg-amber-50 p-4">
          <h2 className="text-sm font-semibold text-amber-900">
            This access point could not update {unhealthy.machine || 'an execute point'}
          </h2>
          <p className="mt-1 text-sm text-amber-800">
            Reservations hold capacity by writing to execute points. Until this
            is fixed, every reservation below will look healthy and hold
            nothing.
          </p>
          {unhealthy.detail && (
            <p className="mt-2 font-mono text-xs break-words text-amber-900">
              {unhealthy.detail}
            </p>
          )}
        </div>
      )}

      {unprovisioned.length > 0 && (
        <div className="rounded-lg border border-amber-300 bg-amber-50 p-4">
          <h2 className="text-sm font-semibold text-amber-900">
            {unprovisioned.length === 1
              ? '1 execute point is not set up for reservations'
              : `${unprovisioned.length} execute points are not set up for reservations`}
          </h2>
          <p className="mt-1 text-sm text-amber-800">
            Reservations cannot hold these machines. Add this line to their
            configuration:
          </p>
          {health.data?.stanza && (
            <pre className="mt-2 overflow-x-auto rounded bg-amber-100 p-2 font-mono text-xs text-amber-900">
              {health.data.stanza}
            </pre>
          )}
          <ul className="mt-2 font-mono text-xs break-words text-amber-900">
            {unprovisioned.map((machine) => (
              <li key={machine}>{machine}</li>
            ))}
          </ul>
        </div>
      )}

      {list.isLoading && <p className="text-gray-400">Loading…</p>}

      {unavailable && (
        <div className="rounded-lg border border-gray-200 bg-white p-4">
          <h2 className="text-sm font-semibold text-gray-900">
            Reservations are not available
          </h2>
          <p className="mt-1 text-sm text-gray-600">{unavailable}</p>
        </div>
      )}
      {listError && !unavailable && (
        <p className="text-sm text-red-600">{listError.message}</p>
      )}

      {!unavailable && !list.isLoading && (
        <div className="flex items-center gap-3">
          <button
            type="button"
            onClick={() => setDraft(blankReservation())}
            disabled={!!draft}
            className="rounded-sm bg-brand-600 px-3 py-1 text-sm font-medium text-white hover:bg-brand-700 disabled:opacity-50"
          >
            New reservation
          </button>
          {reservations.length > 0 && (
            <span className="text-xs text-gray-500">
              {reservations.length} reservation
              {reservations.length === 1 ? '' : 's'}
            </span>
          )}
        </div>
      )}

      {draft && (
        <ReservationForm
          // Remount when the subject changes, so the boxes reset to the
          // reservation being edited rather than keeping the last one's
          // values.
          key={draft.id || '(new)'}
          initial={draft}
          existing={reservations.some((r) => r.id === draft.id)}
          busy={save.isPending}
          error={save.error as Error | null}
          onCancel={() => {
            save.reset();
            setDraft(null);
          }}
          onSubmit={(res) => save.mutate(res)}
        />
      )}

      {!unavailable && list.data && reservations.length === 0 && (
        <p className="text-sm text-gray-500">
          No reservations yet. Nothing is being held back from the pool.
        </p>
      )}

      {reservations.length > 0 && (
        <div className="overflow-x-auto rounded-lg border border-gray-200 bg-white">
          <table className="min-w-full text-sm">
            <thead className="bg-gray-50 text-left text-xs uppercase tracking-wide text-gray-500">
              <tr>
                <th className="px-3 py-2">Reservation</th>
                <th className="px-3 py-2">Schedule</th>
                <th className="px-3 py-2">Window</th>
                <th className="px-3 py-2">Drains from</th>
                <th className="px-3 py-2">Seats</th>
                <th className="px-3 py-2">Standing</th>
                <th className="px-3 py-2">State</th>
                <th className="px-3 py-2"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {reservations.map((res) => (
                <ReservationRows
                  key={res.id}
                  res={res}
                  expanded={expanded === res.id}
                  onToggle={() =>
                    setExpanded((cur) => (cur === res.id ? null : res.id))
                  }
                  onEdit={() => {
                    save.reset();
                    setDraft(res);
                  }}
                  onToggleEnabled={() =>
                    save.mutate({ ...res, enabled: !res.enabled })
                  }
                  onDelete={() => remove.mutate(res.id)}
                  busy={save.isPending && save.variables?.id === res.id}
                  deleting={remove.isPending && remove.variables === res.id}
                />
              ))}
            </tbody>
          </table>
        </div>
      )}

      {remove.isError && (
        <p className="text-sm text-red-600">
          Failed to delete: {(remove.error as Error).message}
        </p>
      )}
      {/* An enable/disable toggle has no form to put its error in. */}
      {save.isError && !draft && (
        <p className="whitespace-pre-line text-sm text-red-600">
          {(save.error as Error).message}
        </p>
      )}
    </div>
  );
}

// A reservation's row, plus the expanded preview beneath it. They are
// siblings rather than one nested table so the columns stay aligned.
function ReservationRows({
  res,
  expanded,
  onToggle,
  onEdit,
  onToggleEnabled,
  onDelete,
  busy,
  deleting,
}: {
  res: AdminReservation;
  expanded: boolean;
  onToggle: () => void;
  onEdit: () => void;
  onToggleEnabled: () => void;
  onDelete: () => void;
  busy: boolean;
  deleting: boolean;
}) {
  const bounds = describeBounds(res);
  return (
    <>
      <tr className="hover:bg-gray-50" data-testid={`reservation-${res.id}`}>
        <td className="px-3 py-2">
          <span className="font-medium text-gray-900">{res.id}</span>
          <span className="block text-xs text-gray-500">
            {res.project}
            {res.owner ? ` · ${res.owner}` : ''}
          </span>
        </td>
        <td className="px-3 py-2">
          <span className="font-mono text-xs text-gray-900">{res.schedule}</span>
          <span className="block text-xs text-gray-500">{res.timezone}</span>
          {/* A schedule with a start or an end is otherwise invisible
              here: the expression looks the same either way. */}
          {bounds && <span className="block text-xs text-gray-500">{bounds}</span>}
        </td>
        <td className="px-3 py-2 text-xs text-gray-700">
          {formatHoursMinutes(res.duration_seconds)}
          <span className="block text-gray-500">
            {res.hold_seconds > 0
              ? `held ${formatHoursMinutes(res.hold_seconds)} past the bell`
              : 'unclaimed seats released at the bell'}
          </span>
        </td>
        <td className="px-3 py-2 text-xs text-gray-700">
          {formatHoursMinutes(res.lead_seconds)} before
        </td>
        <td className="px-3 py-2 text-xs text-gray-700">{res.seats}</td>
        <td className="px-3 py-2 text-xs text-gray-700">
          {res.standing > 0 ? res.standing : '—'}
        </td>
        <td className="px-3 py-2">
          {res.enabled ? (
            <span className="inline-flex rounded-full bg-emerald-100 px-2 py-0.5 text-xs font-medium text-emerald-800">
              Enabled
            </span>
          ) : (
            <span className="inline-flex rounded-full bg-gray-100 px-2 py-0.5 text-xs font-medium text-gray-600">
              Disabled
            </span>
          )}
        </td>
        <td className="px-3 py-2">
          <div className="flex items-center justify-end gap-1">
            <button
              type="button"
              onClick={onToggle}
              aria-expanded={expanded}
              className="rounded-sm border border-gray-300 bg-white px-2 py-0.5 text-xs text-gray-700 hover:bg-gray-50"
            >
              {expanded ? 'Hide upcoming' : 'Upcoming'}
            </button>
            <button
              type="button"
              onClick={onEdit}
              className="rounded-sm border border-gray-300 bg-white px-2 py-0.5 text-xs text-gray-700 hover:bg-gray-50"
            >
              Edit
            </button>
            <button
              type="button"
              onClick={onToggleEnabled}
              disabled={busy}
              className="rounded-sm border border-gray-300 bg-white px-2 py-0.5 text-xs text-gray-700 hover:bg-gray-50 disabled:opacity-50"
            >
              {res.enabled ? 'Disable' : 'Enable'}
            </button>
            <ConfirmButton
              compact
              label="Delete"
              confirmLabel="Delete"
              onConfirm={onDelete}
              pending={deleting}
              title={`Delete reservation "${res.id}" — the pool stops holding seats for ${res.project}`}
            />
          </div>
        </td>
      </tr>
      {expanded && (
        <tr>
          <td colSpan={8} className="bg-gray-50 px-3 py-3">
            <WindowsPreview res={res} />
          </td>
        </tr>
      )}
    </>
  );
}

// How far ahead the preview looks. A fortnight is the server's own
// default and covers a fortnightly timetable; a month answers "does this
// stop at the end of term?".
const HORIZONS = [7, 14, 30];

function WindowsPreview({ res }: { res: AdminReservation }) {
  const [days, setDays] = useState(14);
  const windows = useQuery({
    queryKey: ['admin', 'reservation-windows', res.id, days],
    queryFn: () => api.admin.reservationWindows(res.id, days),
    retry: false,
  });

  const rows = windows.data?.windows ?? [];

  return (
    <div data-testid={`windows-${res.id}`}>
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <h3 className="text-sm font-semibold text-gray-900">
          Upcoming holds
          <span className="ml-2 font-normal text-xs text-gray-500">
            times in {res.timezone}
          </span>
        </h3>
        <label className="text-xs text-gray-600">
          Next{' '}
          <select
            value={days}
            onChange={(e) => setDays(Number(e.target.value))}
            aria-label="Preview horizon"
            className="rounded-sm border border-gray-300 px-1 py-0.5 text-xs"
          >
            {HORIZONS.map((d) => (
              <option key={d} value={d}>
                {d} days
              </option>
            ))}
          </select>
        </label>
      </div>

      {!res.enabled && (
        <p className="mt-1 text-xs text-amber-700">
          This reservation is disabled: these are the windows it would hold if
          it were enabled. Nothing is being drained for it.
        </p>
      )}

      {windows.isLoading && <p className="mt-2 text-xs text-gray-400">Loading…</p>}
      {windows.error && (
        <p className="mt-2 text-xs text-red-600">
          {(windows.error as Error).message}
        </p>
      )}
      {windows.data && rows.length === 0 && (
        <p className="mt-2 text-xs text-gray-500">
          No windows in the next {days} days.
        </p>
      )}

      {rows.length > 0 && (
        <>
          <table className="mt-2 min-w-full text-xs">
            <thead className="text-left text-gray-500">
              <tr>
                <th className="py-1 pr-6 font-medium">Draining starts</th>
                <th className="py-1 pr-6 font-medium">Seats held</th>
                <th className="py-1 font-medium">Until</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((w) => (
                <WindowRow key={w.start} win={w} timezone={res.timezone} />
              ))}
            </tbody>
          </table>
          <p className="mt-2 text-xs text-gray-500">
            Draining is when other people&apos;s jobs stop being sent to the
            machines these seats will come from — {formatHoursMinutes(res.lead_seconds)}{' '}
            before each bell.{' '}
            {res.hold_seconds > 0
              ? `Seats stay reserved for ${res.project} until ${formatHoursMinutes(
                  res.hold_seconds,
                )} past the bell, then unclaimed ones go back to the pool.`
              : `Seats unclaimed by ${res.project} at the bell go straight back to the pool.`}
          </p>
        </>
      )}
    </div>
  );
}

function WindowRow({
  win,
  timezone,
}: {
  win: AdminReservationWindow;
  timezone: string;
}) {
  const start = new Date(win.start);
  const end = new Date(win.end);
  const planFrom = new Date(win.plan_from);
  // The drain and the bell read as one sentence only if the day is
  // stated once; when they fall on different days, say both.
  const sameDay = dayKey(planFrom, timezone) === dayKey(start, timezone);
  return (
    <tr className="border-t border-gray-200">
      <td className="py-1 pr-6 text-amber-800">
        {formatWhen(planFrom, timezone)}
      </td>
      <td className="py-1 pr-6 font-medium text-gray-900">
        {sameDay ? formatTime(start, timezone) : formatWhen(start, timezone)}
        {win.occurrences > 1 && (
          <span className="ml-2 font-normal text-gray-500">
            {win.occurrences} occurrences held as one
          </span>
        )}
      </td>
      <td className="py-1 text-gray-700">
        {dayKey(start, timezone) === dayKey(end, timezone)
          ? formatTime(end, timezone)
          : formatWhen(end, timezone)}
      </td>
    </tr>
  );
}

// Intl throws on a zone it does not know. The server validated the zone
// when the reservation was stored, but tzdata can move underneath a
// running browser, and a preview is not worth an unhandled exception.
function intlOpts(
  timezone: string,
  opts: Intl.DateTimeFormatOptions,
): Intl.DateTimeFormatOptions {
  if (!timezone || timezone === 'Local') return opts;
  try {
    new Intl.DateTimeFormat(undefined, { ...opts, timeZone: timezone }).format();
    return { ...opts, timeZone: timezone };
  } catch {
    return opts;
  }
}

function formatWhen(d: Date, timezone: string): string {
  return d.toLocaleString(
    undefined,
    intlOpts(timezone, {
      weekday: 'short',
      month: 'short',
      day: 'numeric',
      hour: 'numeric',
      minute: '2-digit',
    }),
  );
}

function formatTime(d: Date, timezone: string): string {
  return d.toLocaleTimeString(
    undefined,
    intlOpts(timezone, { hour: 'numeric', minute: '2-digit' }),
  );
}

function dayKey(d: Date, timezone: string): string {
  return d.toLocaleDateString(
    undefined,
    intlOpts(timezone, { year: 'numeric', month: 'short', day: 'numeric' }),
  );
}

const inputCls =
  'mt-1 w-full rounded-sm border border-gray-300 px-2 py-1 text-sm focus:border-brand-400 focus:outline-hidden focus:ring-1 focus:ring-brand-400';

function ReservationForm({
  initial,
  existing,
  busy,
  error,
  onSubmit,
  onCancel,
}: {
  initial: AdminReservation;
  // Whether this ID is already stored. POST creates or replaces either
  // way; the difference is what the buttons say and whether the ID can
  // still be changed.
  existing: boolean;
  busy: boolean;
  error: Error | null;
  onSubmit: (res: AdminReservation) => void;
  onCancel: () => void;
}) {
  const [id, setId] = useState(initial.id);
  const [owner, setOwner] = useState(initial.owner);
  const [project, setProject] = useState(initial.project);
  // The schedule, the picker state behind it, and which of the two is
  // in charge, as one value -- see src/lib/recurrence.ts.
  const [schedule, setSchedule] = useState<ScheduleDraft>(() =>
    draftFromReservation(initial),
  );
  const [timezone, setTimezone] = useState(initial.timezone);
  const [seats, setSeats] = useState(String(initial.seats));
  const [standing, setStanding] = useState(String(initial.standing));
  const [submit, setSubmit] = useState(initial.submit);
  const [enabled, setEnabled] = useState(initial.enabled);
  const [duration, setDuration] = useState(splitHoursMinutes(initial.duration_seconds));
  const [lead, setLead] = useState(splitHoursMinutes(initial.lead_seconds));
  const [hold, setHold] = useState(splitHoursMinutes(initial.hold_seconds));

  const send = () => {
    const zone = timezone.trim();
    onSubmit({
      id: id.trim(),
      owner: owner.trim(),
      project: project.trim(),
      submit,
      seats: Number(seats) || 0,
      standing: Number(standing) || 0,
      duration_seconds: hoursMinutesToSeconds(duration.hours, duration.minutes),
      lead_seconds: hoursMinutesToSeconds(lead.hours, lead.minutes),
      hold_seconds: hoursMinutesToSeconds(hold.hours, hold.minutes),
      schedule: schedule.cron.trim(),
      timezone: zone,
      enabled,
      // The bounds are read in the reservation's own zone, so they are
      // written with that zone's offset rather than the browser's.
      ...recurrenceToBounds(schedule.rec, zone),
    });
  };

  return (
    <div
      data-testid="reservation-form"
      className="rounded-lg border border-gray-200 bg-white p-4"
    >
      <h2 className="text-sm font-semibold text-gray-900">
        {existing ? `Edit ${initial.id}` : 'New reservation'}
      </h2>

      <div className="mt-3 grid gap-3 sm:grid-cols-3">
        <label className="block text-xs">
          <span className="block text-gray-700">Name</span>
          <input
            type="text"
            value={id}
            // Saving under a new ID would leave the old reservation in
            // place and quietly double the hold, so an existing one is
            // renamed by deleting and recreating it.
            disabled={existing}
            onChange={(e) => setId(e.target.value)}
            placeholder="cs301-fall"
            className={`${inputCls} disabled:bg-gray-100 disabled:text-gray-500`}
          />
        </label>
        <div className="block text-xs">
          <label className="block">
            <span className="block text-gray-700">Owner</span>
            <input
              type="text"
              value={owner}
              onChange={(e) => setOwner(e.target.value)}
              placeholder="jsmith"
              className={inputCls}
            />
          </label>
          <span className="mt-1 block text-gray-500">
            Who the capacity is held for.
          </span>
        </div>
        <div className="block text-xs">
          <label className="block">
            <span className="block text-gray-700">Project</span>
            <input
              type="text"
              value={project}
              onChange={(e) => setProject(e.target.value)}
              placeholder="cs301-f26"
              className={inputCls}
            />
          </label>
          <span className="mt-1 block text-gray-500">
            A job takes a seat by carrying this as its ProjectName.
          </span>
        </div>
        <label className="flex items-start gap-2 pt-5 text-xs">
          <input
            type="checkbox"
            checked={enabled}
            onChange={(e) => setEnabled(e.target.checked)}
            className="mt-0.5 rounded-sm border-gray-300"
          />
          <span>
            <span className="font-medium text-gray-900">Enabled</span>
            <span className="block text-gray-500">
              A disabled reservation holds nothing; its schedule is kept.
            </span>
          </span>
        </label>
      </div>

      <div className="mt-3 rounded-sm border border-gray-200 bg-gray-50 p-3">
        <RecurrencePicker
          value={schedule}
          onChange={setSchedule}
          timezone={timezone.trim()}
        />
        <div className="mt-3">
          <ScheduleRow label="Time zone" htmlFor="reservation-timezone">
            <input
              id="reservation-timezone"
              type="text"
              value={timezone}
              onChange={(e) => setTimezone(e.target.value)}
              list="reservation-timezones"
              placeholder="America/Chicago"
              className="w-full rounded-sm border border-gray-300 px-2 py-1 text-sm focus:border-brand-400 focus:outline-hidden focus:ring-1 focus:ring-brand-400 sm:max-w-xs"
            />
            <TimezoneOptions />
            <span className="mt-1 block text-xs text-gray-500">
              Every date and time above is read here, so a window keeps its
              clock time across a daylight-saving change.
            </span>
          </ScheduleRow>
        </div>
      </div>

      <div className="mt-3 grid gap-3 sm:grid-cols-3">
        <label className="block text-xs">
          <span className="block text-gray-700">Seats</span>
          <input
            type="number"
            min={1}
            value={seats}
            onChange={(e) => setSeats(e.target.value)}
            className={inputCls}
          />
        </label>
        <div className="block text-xs">
          <label className="block">
            <span className="block text-gray-700">Standing seats</span>
            <input
              type="number"
              min={0}
              value={standing}
              onChange={(e) => setStanding(e.target.value)}
              className={inputCls}
            />
          </label>
          <span className="mt-1 block text-gray-500">Kept between windows.</span>
        </div>
      </div>

      <div className="mt-3 grid gap-3 sm:grid-cols-3">
        <HoursMinutesField
          label="Window length"
          hint="How long one window lasts."
          value={duration}
          onChange={setDuration}
        />
        <HoursMinutesField
          label="Drain lead"
          hint="How far ahead of the bell the controller starts holding cores back."
          value={lead}
          onChange={setLead}
        />
        <HoursMinutesField
          label="Hold after the bell"
          hint="How long unclaimed seats stay reserved once the window opens."
          value={hold}
          onChange={setHold}
        />
      </div>

      <div className="mt-3 block text-xs">
        <label className="block">
          <span className="block text-gray-700">Submit file</span>
          <textarea
            value={submit}
            onChange={(e) => setSubmit(e.target.value)}
            rows={8}
            spellCheck={false}
            className={`${inputCls} font-mono`}
          />
        </label>
        <span className="mt-1 block text-gray-500">
          The shape of one seat. It is run through the real submit machinery,
          so anything that will not render is refused here rather than hours
          later in a drain.
        </span>
      </div>

      {error && (
        <p
          data-testid="reservation-error"
          className="mt-3 whitespace-pre-line rounded-sm border border-red-200 bg-red-50 px-3 py-2 text-xs text-red-700"
        >
          {error.message}
        </p>
      )}

      <div className="mt-3 flex items-center gap-3">
        <button
          type="button"
          onClick={send}
          disabled={busy}
          className="rounded-sm bg-brand-600 px-3 py-1 text-sm font-medium text-white hover:bg-brand-700 disabled:opacity-50"
        >
          {busy ? 'Saving…' : existing ? 'Save changes' : 'Create reservation'}
        </button>
        <button
          type="button"
          onClick={onCancel}
          className="rounded-sm border border-gray-300 bg-white px-3 py-1 text-sm text-gray-700 hover:bg-gray-50"
        >
          Cancel
        </button>
      </div>
    </div>
  );
}

function HoursMinutesField({
  label,
  hint,
  value,
  onChange,
}: {
  label: string;
  hint: string;
  value: { hours: number; minutes: number };
  onChange: (v: { hours: number; minutes: number }) => void;
}) {
  return (
    <div className="block text-xs">
      <span className="block text-gray-700">{label}</span>
      <div className="mt-1 flex items-center gap-2">
        <input
          type="number"
          min={0}
          aria-label={`${label} hours`}
          value={String(value.hours)}
          onChange={(e) => onChange({ ...value, hours: Number(e.target.value) })}
          className="w-20 rounded-sm border border-gray-300 px-2 py-1 text-sm focus:border-brand-400 focus:outline-hidden focus:ring-1 focus:ring-brand-400"
        />
        <span className="text-gray-500">h</span>
        <input
          type="number"
          min={0}
          max={59}
          // Quarter hours on the spinner, which is what almost every
          // one of these is set to. A step is not a restriction: a
          // 50-minute class is a real timetable, and typing 50 still
          // works -- a list of 0/15/30/45 would make that value
          // unreachable and rewrite it on the next save.
          step={15}
          aria-label={`${label} minutes`}
          value={String(value.minutes)}
          onChange={(e) => onChange({ ...value, minutes: Number(e.target.value) })}
          className="w-20 rounded-sm border border-gray-300 px-2 py-1 text-sm focus:border-brand-400 focus:outline-hidden focus:ring-1 focus:ring-brand-400"
        />
        <span className="text-gray-500">min</span>
      </div>
      <span className="mt-1 block text-gray-500">{hint}</span>
    </div>
  );
}

// Suggestions for the zone box, from whatever the browser knows. It is a
// suggestion list rather than a <select>: the server has the authority on
// which zones exist, and a browser missing supportedValuesOf must still
// leave the field usable.
function TimezoneOptions() {
  const zones = (() => {
    try {
      return Intl.supportedValuesOf?.('timeZone') ?? [];
    } catch {
      return [];
    }
  })();
  if (zones.length === 0) return null;
  return (
    <datalist id="reservation-timezones">
      {zones.map((z) => (
        <option key={z} value={z} />
      ))}
    </datalist>
  );
}
