'use client';

import { useEffect, useId, useMemo, useRef, useState, type RefObject } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { api, type ClassAd } from '@/lib/api';
import { environmentEntries } from '@/lib/environment';
import { EVALUATED_KEY } from '@/lib/jobRequests';
import { useNarrow } from '@/lib/useNarrow';

// AttributeType is what the user picks (or what we infer from the
// existing value) to decide how to encode the new value into a
// ClassAd literal at write time. "raw" lets the user supply any
// expression — useful for references like `Memory * 2` or for
// resetting an attribute to UNDEFINED.
type AttributeType = 'string' | 'integer' | 'real' | 'boolean' | 'raw';

interface AttributeRow {
  name: string;
  value: string;        // human-readable rendering of the current value
  type: AttributeType;  // best-guess type from the JSON shape
}

// inferAttributeType picks a reasonable default editor type from a
// JSON-decoded ClassAd attribute value. The user can override in the
// edit row; we just want the dropdown to land on the most common
// answer for each kind of value. Numbers split int/real; everything
// else falls back to 'raw' (objects, arrays, expressions decoded as
// strings that already look like ClassAd code, etc.).
function inferAttributeType(v: unknown): AttributeType {
  if (typeof v === 'boolean') return 'boolean';
  if (typeof v === 'number') {
    return Number.isInteger(v) ? 'integer' : 'real';
  }
  if (typeof v === 'string') return 'string';
  return 'raw';
}

// formatAttributeForEdit renders the *editable* default text for the
// edit-row's value input given the existing value. For strings we
// surface the text *unquoted* — quotes are an encoding concern, the
// user shouldn't have to type them. Everything else round-trips
// through stringifyAdValue.
function formatAttributeForEdit(v: unknown): string {
  if (typeof v === 'string') return v;
  return stringifyAdValue(v);
}

// validateAttributeInput runs the same checks the server will run, so
// the user gets fast inline feedback ("not a valid integer") instead
// of a 400 round-trip. We deliberately do NOT do the string quoting
// here — that lives on the Go side using classad.Quote, which has the
// authoritative escape table for ClassAd literals (\, ", \n, \t,
// control chars, …). Mirroring it in JS would just recreate the
// hand-rolled-quote-loop bug we hit the first time around.
//
// Returns null if valid, or an error message string if not.
function validateAttributeInput(
  type: AttributeType,
  raw: string,
): string | null {
  switch (type) {
    case 'string':
      // Any text is a valid string; the empty string is meaningful
      // (`""` after server quoting), so don't reject.
      return null;
    case 'integer': {
      const trimmed = raw.trim();
      const n = Number.parseInt(trimmed, 10);
      if (!Number.isFinite(n) || String(n) !== trimmed) {
        return `"${raw}" is not a valid integer`;
      }
      return null;
    }
    case 'real': {
      const n = Number.parseFloat(raw.trim());
      if (!Number.isFinite(n)) return `"${raw}" is not a valid real number`;
      return null;
    }
    case 'boolean': {
      const v = raw.trim().toLowerCase();
      if (v === 'true' || v === 'false') return null;
      return `boolean must be "true" or "false", not "${raw}"`;
    }
    case 'raw':
      // Trust the user but reject empty / whitespace-only — too easy
      // to "set X to nothing" silently.
      if (raw.trim() === '') return 'expression must not be empty';
      return null;
  }
}

// --- Long values -------------------------------------------------------
//
// A job ad carries a few values far longer than the rest: Environment,
// Requirements, Arguments, transfer lists, encoded blobs. Shown whole,
// one of them fills the table's box; on a phone, beside a name column,
// it left the value about one character wide. So every value is clamped
// to CLAMP_LINES lines with a toggle to show the rest.
//
// Whether a value overflows its clamp is measured: it depends on the
// column's width, so the same value fits on a desktop and not on a
// phone. Before the browser has laid the value out (the pre-rendered
// HTML, a test without layout) its length decides instead.

export const CLAMP_LINES = 3;
// About three lines of the narrowest value column, a phone's card.
export const CLAMP_CHARS = 150;
// Shorter than this, a value cannot fill three lines of any column the
// layouts draw, so it is not measured at all.
const MEASURE_MIN_CHARS = 40;
// Expanded, a value longer than this, or an environment with more
// variables than BOUNDED_ENTRIES, scrolls inside a box of its own rather
// than taking over the page.
export const BOUNDED_CHARS = 2000;
export const BOUNDED_ENTRIES = 25;

// looksLong is the length rule used until a value can be measured.
export function looksLong(value: string): boolean {
  return value.length > CLAMP_CHARS || value.split('\n').length > CLAMP_LINES;
}

function mightOverflow(value: string): boolean {
  return value.length > MEASURE_MIN_CHARS || value.includes('\n');
}

// useClampOverflow reports whether the clamped element's text is cut
// off, or null until the browser has measured it. The observer fires
// once the element is laid out and again whenever its size changes, so
// a rotated phone or a resized window re-decides.
function useClampOverflow(
  ref: RefObject<HTMLElement | null>,
  value: string,
  active: boolean,
): boolean | null {
  const [measured, setMeasured] = useState<{ value: string; overflows: boolean } | null>(null);
  useEffect(() => {
    const el = ref.current;
    if (!active || !el || typeof ResizeObserver === 'undefined') return;
    const ro = new ResizeObserver(() => {
      // Not rendered (a hidden ancestor): nothing to measure yet.
      if (el.clientHeight === 0) return;
      setMeasured({ value, overflows: el.scrollHeight > el.clientHeight + 1 });
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, [ref, value, active]);
  return measured !== null && measured.value === value ? measured.overflows : null;
}

// AttributeValue renders one value, clamped, with a Show more / Show
// less toggle when the clamp hides part of it. Text without whitespace
// breaks anywhere rather than widening the page.
//
// An environment (Environment, or the older Env) collapses to its raw
// text like any other value and expands to one NAME=value per line.
export function AttributeValue({
  name,
  value,
  expanded,
  onToggle,
}: {
  name: string;
  value: string;
  expanded: boolean;
  onToggle: () => void;
}) {
  const id = useId();
  const ref = useRef<HTMLDivElement>(null);
  const entries = useMemo(() => environmentEntries(name, value), [name, value]);
  const candidate = mightOverflow(value);
  const measured = useClampOverflow(ref, value, candidate && !expanded);
  const overflows = candidate && (measured ?? looksLong(value));
  const showToggle = overflows || expanded;
  const env = entries !== null && entries.length > 0;
  const bounded =
    value.length > BOUNDED_CHARS || (env && entries.length > BOUNDED_ENTRIES);
  // A box that scrolls has to be reachable from the keyboard.
  const scrollProps =
    expanded && bounded
      ? { tabIndex: 0, role: 'region', 'aria-label': `${name} value` }
      : {};
  const boxCls = expanded && bounded ? ' max-h-72 overflow-y-auto' : '';

  return (
    <div className="min-w-0">
      {expanded && env ? (
        <ul id={id} data-testid="environment-list" className={`space-y-0.5${boxCls}`} {...scrollProps}>
          {entries.map((e, i) => (
            // Hanging indent: a wrapped variable stays visibly one entry.
            <li key={i} className="whitespace-pre-wrap wrap-anywhere pl-4 -indent-4">
              {e}
            </li>
          ))}
        </ul>
      ) : (
        <div
          id={id}
          ref={ref}
          className={`whitespace-pre-wrap wrap-anywhere${expanded ? boxCls : ' line-clamp-3'}`}
          {...scrollProps}
        >
          {value}
        </div>
      )}
      {showToggle && (
        <div className="mt-0.5 flex items-baseline gap-2 font-sans">
          <button
            type="button"
            aria-expanded={expanded}
            aria-controls={id}
            onClick={onToggle}
            className="py-0.5 text-[11px] font-medium text-brand-700 hover:underline focus-visible:outline-2 focus-visible:outline-brand-500"
          >
            {expanded ? 'Show less' : 'Show more'}
          </button>
          {env && (
            <span className="text-[11px] text-gray-400 tabular-nums">
              {entries.length} {entries.length === 1 ? 'variable' : 'variables'}
            </span>
          )}
        </div>
      )}
    </div>
  );
}

// AttributesTable surfaces the entire ClassAd as a searchable list,
// in between the curated Resource/Execution rollups and the raw JSON
// drop-down. Power users routinely need to peek at attributes that
// don't have first-class UI (RemoteSysCpu, JobCurrentStartDate,
// custom site-specific tags, …) without scrolling through 200 lines
// of ClassAd JSON.
//
// Rows are also editable in place — click "edit" or double-click the
// row to expand it into a value+type form. The (value, type) tuple
// is encoded into a ClassAd expression (encodeAttributeForWire) and
// PATCHed at /api/v1/jobs/{id}; the schedd refuses immutable /
// protected attributes with a 403, surfaced inline.
//
// The table caps its visible rows at MAX_VISIBLE so it doesn't push
// the rest of the page off-screen on a busy job; the rest scrolls
// inside the body. A filter input matches case-insensitively against
// either the attribute name or the rendered value.
//
// Under Tailwind's `sm` (640px) the table is a list of cards instead:
// beside a name and a type column a phone has almost no width left for
// the value, so each card puts the name above its value and gives the
// value the full width.
export function AttributesTable({
  jobID,
  job,
  editable = true,
}: {
  jobID: string;
  job: ClassAd;
  // editable=false renders the table in pure read-only mode: no edit
  // button column, no double-click-to-edit, no AttributeEditRow path.
  // Used by the archive detail page since history records are
  // immutable. Defaults to true so the live-job detail page (the
  // first / canonical caller) doesn't have to opt in.
  editable?: boolean;
}) {
  const [filter, setFilter] = useState('');
  const narrow = useNarrow();

  // Which row, if any, is currently in edit mode. Stored as the
  // attribute name so it survives reorders / re-renders that might
  // change row indices in the filtered list. null = nobody editing.
  const [editingName, setEditingName] = useState<string | null>(null);

  // The values shown in full, by attribute name, so they stay open
  // across a refetch of the ad or a change of filter.
  const [expanded, setExpanded] = useState<ReadonlySet<string>>(() => new Set());
  const toggle = (name: string) =>
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(name)) next.delete(name);
      else next.add(name);
      return next;
    });

  const queryClient = useQueryClient();

  const rows = useMemo<AttributeRow[]>(() => {
    // The server's evaluated requests ride beside the ad; they are not one
    // of its attributes and cannot be edited as one.
    const all = Object.entries(job).filter(([name]) => name !== EVALUATED_KEY).map(([name, raw]) => ({
      name,
      value: stringifyAdValue(raw),
      type: inferAttributeType(raw),
    }));
    all.sort((a, b) => a.name.localeCompare(b.name));
    return all;
  }, [job]);

  const filtered = useMemo(() => {
    const q = filter.trim().toLowerCase();
    if (!q) return rows;
    return rows.filter(
      (r) =>
        r.name.toLowerCase().includes(q) ||
        r.value.toLowerCase().includes(q),
    );
  }, [rows, filter]);

  // 7 rows of ~28px (py-1.5 + line-height) plus a header. Keeping
  // this in line-height-units rather than a fixed px height means
  // the cap stays right if the row padding ever shifts. The edit
  // row blows the cap when active (it has form fields), but that's
  // intentional — once you're editing, you want to see the controls
  // without scrolling.
  //
  // An expanded value raises the cap to most of the screen: a value
  // opened to be read should not then have to be scrolled inside a
  // seven-row box. Cards always take that height, since a card is two
  // or more lines tall.
  const MAX_VISIBLE = 7;
  const ROW_HEIGHT_PX = 28;
  const TALL_CAP = '70vh';
  const anyExpanded = filtered.some((r) => expanded.has(r.name));
  const maxHeight = narrow
    ? TALL_CAP
    : editingName
      ? undefined
      : anyExpanded
        ? TALL_CAP
        : ROW_HEIGHT_PX * MAX_VISIBLE;

  const onSaved = () => {
    // Refresh the job ad so the row reflects the schedd's
    // authoritative value (it may have canonicalised our expression).
    queryClient.invalidateQueries({ queryKey: ['job', jobID] });
    setEditingName(null);
  };

  return (
    <div>
      <div className="flex items-baseline justify-between gap-3 mb-2">
        <h3 className="text-xs font-semibold uppercase tracking-wide text-gray-500">
          All Attributes
        </h3>
        <span className="text-[11px] text-gray-400 tabular-nums">
          {filter ? `${filtered.length} / ${rows.length}` : `${rows.length}`}
        </span>
      </div>
      <input
        type="text"
        value={filter}
        onChange={(e) => setFilter(e.target.value)}
        placeholder="Filter by attribute name or value…"
        // 16px text on a phone: iOS zooms the page into any smaller
        // input that takes focus.
        className="mb-2 w-full rounded-sm border border-gray-300 px-2 py-1.5 text-base sm:py-1 sm:text-xs"
        aria-label="Filter ClassAd attributes"
      />
      {narrow ? (
        <div className="overflow-hidden rounded-sm border border-gray-200">
          {filtered.length === 0 ? (
            <p className="px-3 py-2 text-xs text-gray-500">No matches.</p>
          ) : (
            <ul
              className="divide-y divide-gray-100 overflow-y-auto"
              style={{ maxHeight }}
              aria-label="ClassAd attributes"
            >
              {filtered.map((r) =>
                editable && editingName === r.name ? (
                  <AttributeEditCard
                    key={r.name}
                    jobID={jobID}
                    row={r}
                    onCancel={() => setEditingName(null)}
                    onSaved={onSaved}
                  />
                ) : (
                  <AttributeCard
                    key={r.name}
                    row={r}
                    expanded={expanded.has(r.name)}
                    onToggle={() => toggle(r.name)}
                    onEdit={editable ? () => setEditingName(r.name) : undefined}
                  />
                ),
              )}
            </ul>
          )}
        </div>
      ) : (
        <div className="overflow-hidden rounded-sm border border-gray-200">
          <table className="min-w-full text-xs table-fixed">
            <thead className="bg-gray-50 text-left text-[10px] uppercase tracking-wide text-gray-500">
              <tr>
                <th className="px-3 py-1.5 w-56">Attribute</th>
                <th className="px-3 py-1.5 w-20">Type</th>
                <th className="px-3 py-1.5">Value</th>
                {editable && <th className="px-3 py-1.5 w-16 text-right" />}
              </tr>
            </thead>
          </table>
          {filtered.length === 0 ? (
            <p className="px-3 py-2 text-xs text-gray-500">
              No matches.
            </p>
          ) : (
            <div className="overflow-y-auto" style={{ maxHeight }}>
              <table className="min-w-full text-xs table-fixed">
                <tbody className="divide-y divide-gray-100">
                  {filtered.map((r) =>
                    editable && editingName === r.name ? (
                      <AttributeEditRow
                        key={r.name}
                        jobID={jobID}
                        row={r}
                        onCancel={() => setEditingName(null)}
                        onSaved={onSaved}
                      />
                    ) : (
                      <AttributeViewRow
                        key={r.name}
                        row={r}
                        expanded={expanded.has(r.name)}
                        onToggle={() => toggle(r.name)}
                        onEdit={editable ? () => setEditingName(r.name) : undefined}
                      />
                    ),
                  )}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// AttributeViewRow is the read-only display for one attribute. The
// whole row is a click target — double-clicking enters edit mode
// (handy on laptops where the inline icon button is fiddly), and
// the explicit "edit" button at the right covers the discoverability
// case. The hover background highlights the row the cursor is on,
// which is the difference between "I'll click this" and "I think
// I'm clicking this".
function AttributeViewRow({
  row,
  expanded,
  onToggle,
  onEdit,
}: {
  row: AttributeRow;
  expanded: boolean;
  onToggle: () => void;
  // onEdit=undefined puts the row into pure read-only mode (no edit
  // button, no double-click handler, no "double-click to edit"
  // tooltip). Archive detail page passes undefined since history
  // records are immutable.
  onEdit?: () => void;
}) {
  return (
    <tr
      className="hover:bg-gray-50 cursor-default"
      onDoubleClick={onEdit}
      title={onEdit ? 'Double-click to edit' : undefined}
    >
      <td className="px-3 py-1.5 w-56 font-mono text-gray-700 align-top break-all">
        {row.name}
      </td>
      <td className="px-3 py-1.5 w-20 text-gray-500 align-top">
        {row.type}
      </td>
      <td className="px-3 py-1.5 font-mono text-gray-900 align-top">
        <AttributeValue name={row.name} value={row.value} expanded={expanded} onToggle={onToggle} />
      </td>
      {onEdit && (
        <td className="px-3 py-1.5 w-16 text-right align-top">
          <button
            type="button"
            onClick={onEdit}
            className="text-[11px] rounded-sm border border-gray-300 bg-white px-2 py-0.5 text-gray-700 hover:bg-gray-50"
          >
            edit
          </button>
        </td>
      )}
    </tr>
  );
}

// AttributeCard is AttributeViewRow on a phone: the name, small and
// muted, over the value at the full width of the card.
function AttributeCard({
  row,
  expanded,
  onToggle,
  onEdit,
}: {
  row: AttributeRow;
  expanded: boolean;
  onToggle: () => void;
  onEdit?: () => void;
}) {
  return (
    <li className="px-3 py-2" data-testid="attribute-card">
      <div className="flex items-start justify-between gap-2">
        <span className="min-w-0 font-mono text-[11px] text-gray-500 break-all">
          {row.name}
        </span>
        <span className="flex shrink-0 items-center gap-2">
          <span className="text-[10px] text-gray-400">{row.type}</span>
          {onEdit && (
            <button
              type="button"
              onClick={onEdit}
              aria-label={`Edit ${row.name}`}
              className="rounded-sm border border-gray-300 bg-white px-2.5 py-1 text-[11px] text-gray-700 hover:bg-gray-50"
            >
              edit
            </button>
          )}
        </span>
      </div>
      <div className="mt-0.5 font-mono text-xs text-gray-900">
        <AttributeValue name={row.name} value={row.value} expanded={expanded} onToggle={onToggle} />
      </div>
    </li>
  );
}

// useAttributeEditor is the state behind both edit forms, the table
// row and the card. Submission goes through api.jobs.edit; the parent
// invalidates the job query on success so the row re-renders with the
// persisted value (which may differ from what we sent — e.g. integer
// truncated, expression evaluated server-side).
function useAttributeEditor(jobID: string, row: AttributeRow, onSaved: () => void) {
  const [type, setType] = useState<AttributeType>(row.type);
  // Initial text mirrors the displayed value. Strings come out
  // un-quoted (the user types raw text — server quotes via
  // classad.Quote); booleans default to the lowercase string form so
  // the dropdown lands on the right option.
  const [text, setText] = useState(() => {
    if (row.type === 'boolean') {
      const v = row.value.trim().toLowerCase();
      return v === 'true' || v === 'false' ? v : 'true';
    }
    return formatAttributeForEdit(row.value);
  });
  const [error, setError] = useState<string | null>(null);

  // When the user changes the type dropdown, keep the value field
  // sane: switching INTO boolean snaps to "true" so the dropdown has
  // a valid selection; switching OUT preserves what they typed.
  const changeType = (next: AttributeType) => {
    setType(next);
    setError(null);
    if (next === 'boolean') {
      const v = text.trim().toLowerCase();
      if (v !== 'true' && v !== 'false') setText('true');
    }
  };

  const editMut = useMutation({
    mutationFn: async () => {
      // Send the typed shape — server does the encoding via
      // classad.Quote so we don't have to mirror Go's full string
      // escape table on the SPA side.
      return api.jobs.edit(jobID, {
        [row.name]: { type, value: text },
      });
    },
    onSuccess: () => onSaved(),
    onError: (e) =>
      setError(e instanceof Error ? e.message : String(e)),
  });

  const submit = () => {
    setError(null);
    const validation = validateAttributeInput(type, text);
    if (validation) {
      setError(validation);
      return;
    }
    editMut.mutate();
  };

  return { type, changeType, text, setText, error, submit, pending: editMut.isPending };
}

type AttributeEditor = ReturnType<typeof useAttributeEditor>;

function AttributeTypeSelect({ ed, className }: { ed: AttributeEditor; className: string }) {
  return (
    <select
      value={ed.type}
      onChange={(e) => ed.changeType(e.target.value as AttributeType)}
      className={`rounded-sm border border-gray-300 bg-white px-1 py-0.5 ${className}`}
      aria-label="Attribute type"
    >
      <option value="string">string</option>
      <option value="integer">integer</option>
      <option value="real">real</option>
      <option value="boolean">boolean</option>
      <option value="raw">raw</option>
    </select>
  );
}

function AttributeValueInput({
  ed,
  onCancel,
  className,
}: {
  ed: AttributeEditor;
  onCancel: () => void;
  className: string;
}) {
  const cls = `w-full rounded-sm border border-gray-300 bg-white px-2 py-0.5 font-mono ${className}`;
  return (
    <>
      {ed.type === 'boolean' ? (
        // Booleans get a dropdown: free text just invites typos
        // ("True"/"yes"/"1") that fail validation, and there are
        // only two valid values anyway.
        <select
          value={ed.text === 'false' ? 'false' : 'true'}
          onChange={(e) => ed.setText(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter') ed.submit();
            if (e.key === 'Escape') onCancel();
          }}
          autoFocus
          className={cls}
          aria-label="Boolean value"
        >
          <option value="true">true</option>
          <option value="false">false</option>
        </select>
      ) : (
        <input
          type="text"
          value={ed.text}
          onChange={(e) => ed.setText(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter') ed.submit();
            if (e.key === 'Escape') onCancel();
          }}
          autoFocus
          spellCheck={false}
          className={cls}
          placeholder={
            ed.type === 'string'
              ? 'value (typed verbatim, no quotes)'
              : ed.type === 'raw'
                ? 'classad expression (e.g. Memory * 2)'
                : `${ed.type} value`
          }
        />
      )}
      {ed.error && (
        <p className="mt-1 text-[11px] text-red-700">{ed.error}</p>
      )}
    </>
  );
}

function AttributeEditButtons({ ed, onCancel }: { ed: AttributeEditor; onCancel: () => void }) {
  return (
    <div className="inline-flex items-center gap-1">
      <button
        type="button"
        onClick={ed.submit}
        disabled={ed.pending}
        className="text-[11px] rounded-sm border border-brand-600 bg-brand-600 px-2 py-0.5 font-medium text-white hover:bg-brand-700 disabled:opacity-50"
      >
        {ed.pending ? '…' : 'save'}
      </button>
      <button
        type="button"
        onClick={onCancel}
        disabled={ed.pending}
        className="text-[11px] rounded-sm border border-gray-300 bg-white px-2 py-0.5 text-gray-700 hover:bg-gray-50 disabled:opacity-50"
      >
        cancel
      </button>
    </div>
  );
}

// AttributeEditRow swaps the value cell for a (type, value) pair of
// inputs and turns the trailing button into a Save / Cancel pair.
function AttributeEditRow({
  jobID,
  row,
  onCancel,
  onSaved,
}: {
  jobID: string;
  row: AttributeRow;
  onCancel: () => void;
  onSaved: () => void;
}) {
  const ed = useAttributeEditor(jobID, row, onSaved);
  return (
    <tr className="bg-amber-50/50">
      <td className="px-3 py-1.5 w-56 font-mono text-gray-700 align-top break-all">
        {row.name}
      </td>
      <td className="px-3 py-1.5 w-20 align-top">
        <AttributeTypeSelect ed={ed} className="w-full text-[11px]" />
      </td>
      <td className="px-3 py-1.5 align-top">
        <AttributeValueInput ed={ed} onCancel={onCancel} className="text-xs" />
      </td>
      <td className="px-3 py-1.5 w-16 text-right align-top whitespace-nowrap">
        <AttributeEditButtons ed={ed} onCancel={onCancel} />
      </td>
    </tr>
  );
}

// AttributeEditCard is AttributeEditRow on a phone, its controls
// stacked under the name.
function AttributeEditCard({
  jobID,
  row,
  onCancel,
  onSaved,
}: {
  jobID: string;
  row: AttributeRow;
  onCancel: () => void;
  onSaved: () => void;
}) {
  const ed = useAttributeEditor(jobID, row, onSaved);
  return (
    <li className="space-y-1.5 bg-amber-50/50 px-3 py-2">
      <div className="font-mono text-[11px] text-gray-500 break-all">{row.name}</div>
      <div className="flex items-start gap-2">
        {/* 16px text so iOS does not zoom in on focus. */}
        <AttributeTypeSelect ed={ed} className="w-24 shrink-0 text-base" />
        <div className="min-w-0 flex-1">
          <AttributeValueInput ed={ed} onCancel={onCancel} className="text-base" />
        </div>
      </div>
      <div className="flex justify-end">
        <AttributeEditButtons ed={ed} onCancel={onCancel} />
      </div>
    </li>
  );
}

// stringifyAdValue collapses any JSON-shaped attribute value to a
// short readable string. For nested objects / arrays we fall back to
// JSON.stringify so the user can still see the structure inline; the
// Raw ClassAd panel below has the pretty-printed version when they
// need it.
function stringifyAdValue(v: unknown): string {
  if (v === null || v === undefined) return '';
  if (typeof v === 'string') return v;
  if (typeof v === 'number' || typeof v === 'boolean') return String(v);
  try {
    return JSON.stringify(v);
  } catch {
    return String(v);
  }
}
