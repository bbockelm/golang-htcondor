'use client';

// Reservations — recurring holds of pool capacity for a project.
//
// A reservation holds slots of a stated shape, on a schedule. The
// controller starts holding cores back `lead` before a reservation
// begins, has `seats` slots free by the time it does, keeps the
// unclaimed ones for `hold`, and keeps `standing` slots between
// occurrences so the project's people can work in between. A job uses a
// reservation by carrying its project as ProjectName; the shape of one
// slot comes from the submit file.
//
// Three things drive the design:
//
//   * The schedule preview is the page. A schedule is a rule and the
//     days it lands on are the thing anybody actually cares about, so
//     neither the list nor the form asks anyone to work them out: both
//     show the next occurrences, and for each, both the start and the
//     drain. The drain is when other people's jobs start being steered
//     away, hours before the project notices anything, so it is given
//     the same weight as the start rather than hidden in a lead field.
//     The form's preview is of the draft in the boxes, from the same
//     enumeration the controller runs, and it is the quickest way to
//     tell a schedule that says what was meant from one that does not.
//   * The form is sections rather than one column of boxes. Its fields
//     answer four separate questions -- who it is for, when it runs, how
//     much it holds, what one slot looks like -- and on a phone the
//     whole form is one column however it is written, so the headings
//     are what makes it readable there at all.
//   * The server validates eagerly -- the cron, the zone, the submit
//     file, `standing` against `seats` -- and answers 400 with the
//     reason. The form shows that text verbatim. Restating it here in
//     our own words would drift from what the server actually enforces.

import { useEffect, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  ApiError,
  api,
  type AdminReservation,
  type AdminReservationWindow,
} from '@/lib/api';
import { ConfirmButton } from '@/components/ConfirmButton';
import {
  carryHoursMinutes,
  formatHoursMinutes,
  hoursMinutesToSeconds,
  splitHoursMinutes,
} from '@/lib/reservation';
import {
  describeBounds,
  describeSchedule,
  draftFromReservation,
  scheduleFields,
  scheduleNeeds,
  whyNoWindows,
  type ScheduleDraft,
} from '@/lib/recurrence';
import { RecurrencePicker, ScheduleRow } from '@/components/RecurrencePicker';
import {
  ResourceRequestPanel,
  type ResourceRequest,
} from '@/components/ResourceRequest';
import { SubmitLinesField } from '@/components/SubmitLinesField';
import {
  parseReservationSubmit,
  renderReservationSubmit,
  withResourceRequest,
  type ReservationSubmit,
} from '@/lib/reservationSubmit';

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
    // executable, since a slot with no Cmd matches nothing.
    submit: 'executable = /usr/bin/python3\nrequest_cpus = 1\nrequest_memory = 4096\nqueue\n',
    seats: 20,
    standing: 0,
    duration_seconds: 3600,
    // Six hours is where the measured benefit of leading saturates.
    lead_seconds: 6 * 3600,
    hold_seconds: 15 * 60,
    // A new reservation is described by the repeat controls. The
    // expression is still there to switch to, and switching back is
    // free, so there is nothing to lose by starting on the controls.
    schedule_kind: 'recurrence',
    schedule: '',
    recurrence: null,
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
          Capacity held for a project on a schedule — a course, a
          demonstration, a deadline. The access point starts draining ahead
          of each reservation so the slots are free when it begins, and jobs
          use them by carrying the project as their ProjectName.
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
        <p className="text-sm text-gray-500">No reservations yet.</p>
      )}

      {reservations.length > 0 && (
        <div className="overflow-x-auto rounded-lg border border-gray-200 bg-white">
          <table className="min-w-full text-sm">
            <thead className="bg-gray-50 text-left text-xs uppercase tracking-wide text-gray-500">
              <tr>
                <th className="px-3 py-2">Reservation</th>
                <th className="px-3 py-2">Schedule</th>
                <th className="px-3 py-2">Length</th>
                <th className="px-3 py-2">Drains from</th>
                <th className="px-3 py-2">Slots</th>
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
          {/* Monospaced only for an expression. The other two timings
              are sentences, and setting a sentence in a code face says
              it is something to be read character by character. */}
          <span
            className={`text-xs text-gray-900 ${
              res.schedule_kind === 'recurrence' || res.schedule_kind === 'always'
                ? ''
                : 'font-mono'
            }`}
          >
            {describeSchedule(res)}
          </span>
          <span className="block text-xs text-gray-500">{res.timezone}</span>
          {/* A schedule with a start or an end is otherwise invisible
              here: the schedule reads the same either way. */}
          {bounds && <span className="block text-xs text-gray-500">{bounds}</span>}
        </td>
        <td className="px-3 py-2 text-xs text-gray-700">
          {formatHoursMinutes(res.duration_seconds)}
          <span className="block text-gray-500">
            {res.hold_seconds > 0
              ? `unclaimed slots held ${formatHoursMinutes(res.hold_seconds)} past the start`
              : 'unclaimed slots released at the start'}
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
              title={`Delete reservation "${res.id}" — the pool stops holding slots for ${res.project}`}
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
// default and covers a fortnightly schedule; a month answers "does this
// stop, and when?".
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
          This reservation is disabled: these are the holds it would place if
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
          {whyNoWindows(windows.data.schedule_kind, res, days)}
        </p>
      )}

      {rows.length > 0 && (
        <>
          <WindowsTable rows={rows} timezone={res.timezone} />
          <p className="mt-2 text-xs text-gray-500">
            Draining is when other people&apos;s jobs stop being sent to the
            machines these slots will come from — {formatHoursMinutes(res.lead_seconds)}{' '}
            before each start.{' '}
            {res.hold_seconds > 0
              ? `Slots stay reserved for ${res.project} until ${formatHoursMinutes(
                  res.hold_seconds,
                )} past the start, then unclaimed ones go back to the pool.`
              : `Slots unclaimed by ${res.project} at the start go straight back to the pool.`}
          </p>
        </>
      )}
    </div>
  );
}

// The upcoming holds, as a table. Shared by the saved reservation's
// preview and the draft's, so the two cannot come to disagree about
// what a window is or which of its times matter.
function WindowsTable({
  rows,
  timezone,
}: {
  rows: AdminReservationWindow[];
  timezone: string;
}) {
  return (
    <table className="mt-2 min-w-full text-xs">
      <thead className="text-left text-gray-500">
        <tr>
          <th className="py-1 pr-6 font-medium">Draining starts</th>
          <th className="py-1 pr-6 font-medium">Slots held</th>
          <th className="py-1 font-medium">Until</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((w) => (
          <WindowRow key={w.start} win={w} timezone={timezone} />
        ))}
      </tbody>
    </table>
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
  // The drain and the start read as one sentence only if the day is
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

// How far ahead the form's own preview asks, and how much of the answer
// it shows. A count rather than a horizon, because the question an
// operator is asking of a draft is "are these the right days?" and five
// of them answers it; the horizon is wide enough that a monthly
// recurrence still produces a few.
const DRAFT_HORIZON_DAYS = 90;
const DRAFT_ROWS = 5;

// useSettled holds a value still until it has stopped changing.
function useSettled(value: string, ms: number): string {
  const [settled, setSettled] = useState(value);
  useEffect(() => {
    const timer = setTimeout(() => setSettled(value), ms);
    return () => clearTimeout(timer);
  }, [value, ms]);
  return settled;
}

// The next few occurrences of the reservation being written, from the
// server.
//
// The enumeration is the controller's own, asked about this draft. A
// preview computed in the browser would be a second implementation of
// the schedule, and the first time the two disagreed the page would be
// confidently showing an operator days that nothing is going to hold.
function DraftWindowsPreview({
  res,
  blocked,
}: {
  res: AdminReservation;
  // True while the schedule is missing something the form has already
  // asked for. The server would refuse it, and repeating the refusal
  // underneath the question would read as a second problem.
  blocked: boolean;
}) {
  // Which draft this is, as far as the answer is concerned. The whole
  // reservation goes in the request, but only these fields can change
  // which days come back -- the schedule, its bounds, where each window
  // ends and when draining would start -- so a keystroke in the submit
  // file or the project name asks the server nothing.
  const timing = JSON.stringify({
    schedule_kind: res.schedule_kind,
    schedule: res.schedule,
    recurrence: res.recurrence,
    starts_at: res.starts_at,
    ends_at: res.ends_at,
    occurrences: res.occurrences,
    duration_seconds: res.duration_seconds,
    lead_seconds: res.lead_seconds,
    timezone: res.timezone,
  });
  const settled = useSettled(timing, 400);
  const alwaysOn = res.schedule_kind === 'always';
  const needsLength = !alwaysOn && res.duration_seconds <= 0;
  const windows = useQuery({
    queryKey: ['admin', 'reservation-window-preview', settled],
    queryFn: () => api.admin.previewReservationWindows(res, DRAFT_HORIZON_DAYS),
    enabled: !blocked && !needsLength,
    retry: false,
    // Keep the last answer on screen while the next one is fetched: the
    // list is being read while it is being changed, and blanking it on
    // every keystroke is how a preview becomes something to ignore.
    placeholderData: (prev) => prev,
  });

  const rows = windows.data?.windows ?? [];
  const shown = rows.slice(0, DRAFT_ROWS);
  // Whether what is on screen is still the answer to what is in the
  // boxes: false while a change is settling as well as while the
  // request for it is in flight.
  const behind = settled !== timing || (windows.isFetching && !!windows.data);

  return (
    <div data-testid="reservation-window-preview" className="rounded-sm bg-gray-50 px-3 py-2">
      <h3 className="text-xs font-semibold text-gray-900">
        Next occurrences
        {res.timezone && (
          <span className="ml-2 font-normal text-gray-500">times in {res.timezone}</span>
        )}
        {/* The last answer stays on screen while the next one is
            fetched, so while that is happening the list has to say it
            is behind the controls rather than look like the answer to
            them. */}
        {behind && <span className="ml-2 font-normal text-gray-500">updating…</span>}
      </h3>

      {needsLength && (
        <p className="mt-1 text-xs text-gray-500">
          Set a reservation length to see when this runs.
        </p>
      )}
      {blocked && !needsLength && (
        <p className="mt-1 text-xs text-gray-500">
          Finish the schedule above to see when this runs.
        </p>
      )}
      {windows.isFetching && !windows.data && (
        <p className="mt-1 text-xs text-gray-400">Loading…</p>
      )}
      {windows.error && (
        <p className="mt-1 whitespace-pre-line text-xs text-red-600">
          {(windows.error as Error).message}
        </p>
      )}

      {windows.data && shown.length === 0 && !blocked && !needsLength && (
        <p className="mt-1 text-xs text-gray-500">
          {whyNoWindows(windows.data.schedule_kind, res, DRAFT_HORIZON_DAYS)}
        </p>
      )}

      {shown.length > 0 && (
        <>
          <WindowsTable rows={shown} timezone={res.timezone} />
          {rows.length > shown.length && (
            <p className="mt-1 text-xs text-gray-500">
              And {rows.length - shown.length} more in the next{' '}
              {DRAFT_HORIZON_DAYS} days.
            </p>
          )}
        </>
      )}
    </div>
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
  const [enabled, setEnabled] = useState(initial.enabled);
  const [duration, setDuration] = useState(splitHoursMinutes(initial.duration_seconds));
  const [lead, setLead] = useState(splitHoursMinutes(initial.lead_seconds));
  const [hold, setHold] = useState(splitHoursMinutes(initial.hold_seconds));
  // The submit file, as fields where they can give it back exactly and
  // as text where they cannot -- see src/lib/reservationSubmit.ts.
  // `fields` is the live state whenever it is not null; `text` is what
  // the other mode holds.
  const [fields, setFields] = useState<ReservationSubmit | null>(() =>
    parseReservationSubmit(initial.submit),
  );
  const [text, setText] = useState(initial.submit);
  const submit = fields ? renderReservationSubmit(fields) : text;

  const zone = timezone.trim();
  // The reservation the boxes currently describe. The same value is
  // saved and previewed, so the preview can never be of a draft the
  // Save button would not send.
  const current: AdminReservation = {
    id: id.trim(),
    owner: owner.trim(),
    project: project.trim(),
    submit,
    seats: Number(seats) || 0,
    standing: Number(standing) || 0,
    duration_seconds: hoursMinutesToSeconds(duration.hours, duration.minutes),
    lead_seconds: hoursMinutesToSeconds(lead.hours, lead.minutes),
    hold_seconds: hoursMinutesToSeconds(hold.hours, hold.minutes),
    timezone: zone,
    enabled,
    // The schedule, and the bounds on it. The bounds are read in the
    // reservation's own zone, so they are written with that zone's
    // offset rather than the browser's.
    ...scheduleFields(schedule, zone),
  };
  // What the schedule still needs before the server could act on it.
  // Saving over one of these is a 400 that names a rule rather than a
  // box, so the form asks for it here instead.
  const needs = scheduleNeeds(schedule);
  const alwaysOn = schedule.kind === 'always';

  return (
    <div
      data-testid="reservation-form"
      className="rounded-lg border border-gray-200 bg-white p-4"
    >
      <h2 className="text-sm font-semibold text-gray-900">
        {existing ? `Edit ${initial.id}` : 'New reservation'}
      </h2>

      <FormSection title="Reservation">
        <div className="grid gap-3 sm:grid-cols-3">
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
              A job must be in this project to use the reservation.
            </span>
          </div>
        </div>
        <label className="flex items-start gap-2 text-xs">
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
      </FormSection>

      <FormSection title="Schedule">
        {/* The recurrence controls: start, repeat, end, and the cron
            expression behind them. */}
        <RecurrencePicker
          value={schedule}
          onChange={setSchedule}
          timezone={timezone.trim()}
        />
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
            Every date and time above is read here, so a reservation keeps its
            clock time across a daylight-saving change.
          </span>
        </ScheduleRow>
        {/* A reservation held continuously has no window, so it has no
            length. */}
        {!alwaysOn && (
          <div className="grid gap-3 sm:grid-cols-3">
            <HoursMinutesField
              label="Reservation length"
              hint="How long the capacity is held, each time the schedule comes round."
              value={duration}
              onChange={setDuration}
            />
          </div>
        )}
        <DraftWindowsPreview res={current} blocked={needs.length > 0} />
      </FormSection>

      <FormSection title="Capacity">
        <div className="grid gap-3 sm:grid-cols-3">
          <div className="block text-xs">
            <label className="block">
              <span className="block text-gray-700">Slots</span>
              <input
                type="number"
                min={1}
                value={seats}
                onChange={(e) => setSeats(e.target.value)}
                className={inputCls}
              />
            </label>
            <span className="mt-1 block text-gray-500">
              Held while the reservation is running.
            </span>
          </div>
          <div className="block text-xs">
            <label className="block">
              <span className="block text-gray-700">Standing slots</span>
              <input
                type="number"
                min={0}
                value={standing}
                onChange={(e) => setStanding(e.target.value)}
                className={inputCls}
              />
            </label>
            <span className="mt-1 block text-gray-500">
              Spare slots kept available at all times, on top of whatever the
              project is already running, so the next person to arrive finds
              one waiting. Never more than the number of slots above.
            </span>
          </div>
        </div>
      </FormSection>

      {/* Both of these describe what happens around a start, so a
          reservation that never starts and never stops has neither. */}
      {!alwaysOn && (
        <FormSection
          title="Draining"
          hint="Other people's jobs stop being sent to the machines these slots will come from ahead of each start, so the slots are free when the reservation begins."
        >
          <div className="grid gap-3 sm:grid-cols-3">
            <HoursMinutesField
              label="Drain lead"
              hint="How far ahead of each start the draining begins."
              value={lead}
              onChange={setLead}
            />
            <HoursMinutesField
              label="Hold after the start"
              hint="How long unclaimed slots stay reserved for the project."
              value={hold}
              onChange={setHold}
            />
          </div>
        </FormSection>
      )}

      <FormSection
        title="Slot shape"
        hint="This submit file describes one slot the reservation holds. It is not submitted as a job."
      >
        <SubmitFileField
          fields={fields}
          text={text}
          onFields={setFields}
          onText={setText}
        />
      </FormSection>

      {error && (
        <p
          data-testid="reservation-error"
          className="mt-3 whitespace-pre-line rounded-sm border border-red-200 bg-red-50 px-3 py-2 text-xs text-red-700"
        >
          {error.message}
        </p>
      )}

      <div className="mt-3 flex flex-wrap items-center gap-3">
        <button
          type="button"
          onClick={() => onSubmit(current)}
          disabled={busy || needs.length > 0}
          className="rounded-sm bg-brand-600 px-3 py-1 text-sm font-medium text-white hover:bg-brand-700 disabled:opacity-50"
        >
          {busy ? 'Saving…' : existing ? 'Save changes' : 'Create reservation'}
        </button>
        {/* Repeated from the schedule section on purpose: on a phone the
            button and the control it is waiting on are screens apart,
            and a button that is disabled for no stated reason is worse
            than one that fails. */}
        {needs.length > 0 && (
          <span className="text-xs text-amber-700">
            {needs.map((n) => n.message).join(' ')}
          </span>
        )}
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

// A labelled group of fields. The form is one column on a phone however
// it is written, so these headings are the only thing that says where
// one question ends and the next begins.
function FormSection({
  title,
  hint,
  children,
}: {
  title: string;
  hint?: string;
  children: React.ReactNode;
}) {
  return (
    <fieldset className="mt-3 rounded-sm border border-gray-200 px-3 pb-3">
      <legend className="px-1 text-xs font-medium uppercase tracking-wide text-gray-500">
        {title}
      </legend>
      {hint && <p className="mb-3 text-xs text-gray-500">{hint}</p>}
      <div className="space-y-3">{children}</div>
    </fieldset>
  );
}

// The submit file, as the resource request the submit and interactive
// pages already ask for, plus the lines that panel has no field for.
//
// A reservation stores a submit file, not a set of numbers, so the two
// modes are not interchangeable: the fields show only over a file they
// can give back byte for byte, and anything else is edited as text.
// That check is parseReservationSubmit's, and it is the reason opening a
// reservation and pressing Save cannot reformat its submit file.
function SubmitFileField({
  fields,
  text,
  onFields,
  onText,
}: {
  fields: ReservationSubmit | null;
  text: string;
  onFields: (next: ReservationSubmit | null) => void;
  onText: (next: string) => void;
}) {
  if (fields) {
    return (
      <div className="space-y-3" data-testid="reservation-submit-fields">
        <ResourceRequestPanel
          value={fields.request}
          onChange={(r: ResourceRequest) => onFields(withResourceRequest(fields, r))}
        />
        <SubmitLinesField
          label="Other submit commands"
          note=""
          hint={
            <>
              One <code className="font-mono">name = value</code> per line; the
              executable is one of them.
            </>
          }
          placeholder={'executable = /usr/bin/python3\n+WantWholeMachine = true'}
          value={fields.extraLines}
          onChange={(v) => onFields({ ...fields, extraLines: v })}
        />
        <button
          type="button"
          onClick={() => {
            onText(renderReservationSubmit(fields));
            onFields(null);
          }}
          className="rounded-sm border border-gray-300 bg-white px-2 py-0.5 text-xs text-gray-700 hover:bg-gray-50"
        >
          Edit as text
        </button>
      </div>
    );
  }

  const asFields = parseReservationSubmit(text);
  return (
    <div className="space-y-2" data-testid="reservation-submit-text">
      <label className="block text-xs">
        <span className="block text-gray-700">Submit file</span>
        <textarea
          value={text}
          onChange={(e) => onText(e.target.value)}
          rows={8}
          spellCheck={false}
          className={`${inputCls} font-mono`}
        />
      </label>
      {asFields ? (
        <button
          type="button"
          onClick={() => onFields(asFields)}
          className="rounded-sm border border-gray-300 bg-white px-2 py-0.5 text-xs text-gray-700 hover:bg-gray-50"
        >
          Use fields
        </button>
      ) : (
        <p className="text-xs text-gray-500">
          Edited as text: the fields would not give this file back exactly as
          it is written.
        </p>
      )}
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
          onChange={(e) => onChange(carryHoursMinutes(Number(e.target.value), value.minutes))}
          className="w-20 rounded-sm border border-gray-300 px-2 py-1 text-sm focus:border-brand-400 focus:outline-hidden focus:ring-1 focus:ring-brand-400"
        />
        <span className="text-gray-500">h</span>
        <input
          type="number"
          // Quarter hours on the spinner, which is what almost every
          // one of these is set to. A step is not a restriction: a
          // 50-minute reservation is a real one, and typing 50 still
          // works -- a list of 0/15/30/45 would make that value
          // unreachable and rewrite it on the next save.
          step={15}
          // No floor and no ceiling on this box, so the spinner can
          // step past both and be read as the hour it means: up from 45
          // is 60, which is the next hour at zero, and down from 0 is
          // -15, which is the previous hour at 45. Clamping at 0 and 59
          // instead is why the up arrow did nothing at 45.
          aria-label={`${label} minutes`}
          value={String(value.minutes)}
          onChange={(e) => onChange(carryHoursMinutes(value.hours, Number(e.target.value)))}
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
