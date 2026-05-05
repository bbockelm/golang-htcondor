// Lightweight helpers for poking at HTCondor submit-file text from the
// SPA's "quick fields" and batch-mode UI. The textarea remains the
// canonical state at submit time; these helpers just keep it in sync as
// the user moves sliders / edits the table.
//
// Design choices:
//   - Match attribute names case-insensitively (HTCondor is case-insensitive)
//     but preserve the casing the user already wrote.
//   - When a key isn't present, insert it just before the first `queue`
//     statement so the file's structure (attributes then queue) is
//     maintained.
//   - We never touch lines inside multi-line values (rare in submit
//     files; we accept the limitation).

const QUEUE_RE = /^\s*queue(\s|$)/i;

function attrLineRE(key: string): RegExp {
  // ^[whitespace] key [whitespace] = ...   (case-insensitive)
  // Matches the whole line so we can replace it as a unit.
  const escaped = key.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return new RegExp(`^(\\s*)${escaped}(\\s*=).*$`, 'im');
}

/**
 * Set or update an attribute = value line. If `value` is empty, the
 * attribute is removed entirely.
 *
 * Insertion point when the key is not yet present: immediately before
 * the first line beginning with `queue`. If no `queue` line exists,
 * append at the end (with a trailing newline).
 */
export function setAttribute(text: string, key: string, value: string): string {
  if (value === '' || value == null) {
    return removeAttribute(text, key);
  }
  const re = attrLineRE(key);
  if (re.test(text)) {
    return text.replace(re, (_match, leading, eq) => `${leading}${key}${eq} ${value}`);
  }
  return insertBeforeQueue(text, `${key} = ${value}`);
}

/** Remove a key=value line if present. */
export function removeAttribute(text: string, key: string): string {
  const re = attrLineRE(key);
  if (!re.test(text)) return text;
  // Drop the line and the trailing newline cleanly.
  const lines = text.split('\n');
  const out: string[] = [];
  let dropped = false;
  for (const line of lines) {
    if (!dropped && re.test(line)) {
      dropped = true;
      continue;
    }
    out.push(line);
  }
  return out.join('\n');
}

/** Get the current value of an attribute, or undefined if not present. */
export function getAttribute(text: string, key: string): string | undefined {
  const re = new RegExp(`^\\s*${key.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\s*=\\s*(.*?)\\s*$`, 'im');
  const m = re.exec(text);
  return m ? m[1] : undefined;
}

/**
 * Replace the trailing `queue ...` statement (or insert one at end if
 * none exists) with the supplied text. Only the LAST queue line is
 * touched — earlier `queue` statements (if the user wrote a multi-stage
 * submit file) are left alone.
 */
export function setQueueStatement(text: string, queueLine: string): string {
  const lines = text.split('\n');
  let lastQueueIdx = -1;
  for (let i = lines.length - 1; i >= 0; i--) {
    if (QUEUE_RE.test(lines[i])) {
      lastQueueIdx = i;
      break;
    }
  }
  if (lastQueueIdx >= 0) {
    lines[lastQueueIdx] = queueLine;
    return lines.join('\n');
  }
  // No existing queue; ensure a trailing blank line then the new statement.
  const trimmed = text.replace(/\s+$/, '');
  return `${trimmed}\n\n${queueLine}\n`;
}

function insertBeforeQueue(text: string, line: string): string {
  const lines = text.split('\n');
  let firstQueueIdx = -1;
  for (let i = 0; i < lines.length; i++) {
    if (QUEUE_RE.test(lines[i])) {
      firstQueueIdx = i;
      break;
    }
  }
  if (firstQueueIdx >= 0) {
    lines.splice(firstQueueIdx, 0, line);
    return lines.join('\n');
  }
  // No queue line — append at end with a separating blank line.
  const trimmed = text.replace(/\s+$/, '');
  return `${trimmed}\n${line}\n`;
}

// --- Batch mode helpers ----------------------------------------------------

/** Build a `queue N` statement. */
export function buildCountQueue(n: number): string {
  if (!Number.isFinite(n) || n < 1) n = 1;
  return `queue ${Math.floor(n)}`;
}

/**
 * Build a `queue var1, var2, ... in (...)` statement from a 2D table.
 * Each row becomes one item; cells are joined by a single space, so
 * cells must not contain whitespace (HTCondor splits items on whitespace).
 *
 * Throws if columns are empty, headers aren't valid identifiers, or any
 * cell contains whitespace.
 */
export function buildTableQueue(
  columns: string[],
  rows: string[][],
): string {
  if (columns.length === 0) {
    throw new Error('Add at least one column.');
  }
  for (const c of columns) {
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(c)) {
      throw new Error(
        `Column header "${c}" is not a valid HTCondor variable name (letters, digits, underscore; must not start with a digit).`,
      );
    }
  }
  if (rows.length === 0) {
    throw new Error('Add at least one row.');
  }
  const items: string[] = [];
  for (let r = 0; r < rows.length; r++) {
    const cells = rows[r].slice(0, columns.length);
    while (cells.length < columns.length) cells.push('');
    for (let c = 0; c < cells.length; c++) {
      const v = cells[c];
      if (v === '') {
        throw new Error(
          `Row ${r + 1}, column "${columns[c]}" is empty.`,
        );
      }
      if (/\s/.test(v)) {
        throw new Error(
          `Row ${r + 1}, column "${columns[c]}" contains whitespace; HTCondor would split it.`,
        );
      }
    }
    items.push(cells.join(' '));
  }
  // Multi-line form is more readable when there are many rows.
  if (items.length <= 3) {
    return `queue ${columns.join(', ')} in (${items.join(', ')})`;
  }
  const indented = items.map((it) => '    ' + it).join('\n');
  return `queue ${columns.join(', ')} in (\n${indented}\n)`;
}

// --- Environment encoding -------------------------------------------------

export interface EnvVar {
  name: string;
  value: string;
}

/**
 * Encode a list of environment variables in HTCondor's "new" environment
 * syntax. Per the condor_submit manpage:
 *   - The whole value is wrapped in double quotes.
 *   - Embedded literal double quotes are doubled ("").
 *   - Entries are separated by whitespace.
 *   - Entries whose value contains whitespace or a single quote are
 *     wrapped in single quotes, with embedded single quotes doubled ('').
 *
 * Returns null if the list is empty (or every entry has an empty name) —
 * callers should then `removeAttribute(text, 'environment')` to drop the
 * line entirely.
 */
export function encodeEnvironment(vars: EnvVar[]): string | null {
  const filtered = vars.filter((v) => v.name.trim() !== '');
  if (filtered.length === 0) return null;
  const entries = filtered.map((v) => {
    // Step 1: escape any embedded double quotes (which must survive the
    // outer "..." wrapping at the very end).
    const dq = v.value.replace(/"/g, '""');
    // Step 2: if the value has whitespace or a single quote, wrap with
    // single quotes and double any embedded single quotes.
    let encoded: string;
    if (/[\s']/.test(dq)) {
      encoded = "'" + dq.replace(/'/g, "''") + "'";
    } else {
      encoded = dq;
    }
    return `${v.name.trim()}=${encoded}`;
  });
  return `"${entries.join(' ')}"`;
}

/**
 * Decode an `environment = "..."` value back to a list. Best-effort: if
 * the value isn't in the new-syntax (no enclosing quotes), returns null
 * and the caller can fall back to leaving the textarea alone.
 */
export function decodeEnvironment(raw: string | undefined): EnvVar[] | null {
  if (raw === undefined) return null;
  const trimmed = raw.trim();
  if (!trimmed.startsWith('"') || !trimmed.endsWith('"')) return null;
  const inner = trimmed.slice(1, -1).replace(/""/g, '"'); // un-double quotes

  // Tokenize on whitespace, but keep single-quoted segments intact and
  // un-double internal single quotes ('' -> ').
  const tokens: string[] = [];
  let buf = '';
  let inSingle = false;
  for (let i = 0; i < inner.length; i++) {
    const ch = inner[i];
    if (ch === "'") {
      if (inSingle && inner[i + 1] === "'") {
        // doubled '' inside a single-quoted segment -> literal '
        buf += "'";
        i++;
        continue;
      }
      inSingle = !inSingle;
      continue;
    }
    if (!inSingle && /\s/.test(ch)) {
      if (buf !== '') {
        tokens.push(buf);
        buf = '';
      }
      continue;
    }
    buf += ch;
  }
  if (buf !== '') tokens.push(buf);

  const out: EnvVar[] = [];
  for (const t of tokens) {
    const eq = t.indexOf('=');
    if (eq <= 0) continue;
    out.push({ name: t.slice(0, eq), value: t.slice(eq + 1) });
  }
  return out;
}

// --- Resource request helpers --------------------------------------------
//
// Map ResourceRequest <-> submit-file body so the same widget can drive
// both a structured-state form (interactive page) and a freeform body
// editor (submit page step 4 + template authoring).

import {
  DEFAULT_RESOURCE_REQUEST,
  type ResourceRequest,
} from '@/components/ResourceRequest';

const RESOURCE_KEYS = [
  'request_cpus',
  'request_memory',
  'request_disk',
  'request_gpus',
  'gpus_minimum_memory',
  'gpus_minimum_capability',
  'gpus_minimum_runtime',
  'cuda_version',
  'require_gpus',
] as const;

/** Returns true when the body sets *any* of the structured resource keys. */
export function bodyHasResourceRequests(text: string): boolean {
  return RESOURCE_KEYS.some((k) => getAttribute(text, k) !== undefined);
}

/** Returns true when the body sets the core CPU/memory/disk triple. */
export function bodyHasCoreResourceRequests(text: string): boolean {
  return (
    getAttribute(text, 'request_cpus') !== undefined &&
    getAttribute(text, 'request_memory') !== undefined &&
    getAttribute(text, 'request_disk') !== undefined
  );
}

/**
 * Read whatever resource-request lines are present in the body. Missing
 * fields fall back to DEFAULT_RESOURCE_REQUEST. Memory/disk values are
 * accepted as bare integers — HTCondor's units suffix syntax (`4G` etc.)
 * is left as-is in the body and ignored here; consumers that want
 * structured editing should use bare integers.
 */
export function readResourcesFromBody(text: string): ResourceRequest {
  return {
    cpus: parseIntOr(getAttribute(text, 'request_cpus'), DEFAULT_RESOURCE_REQUEST.cpus),
    memoryMB: parseIntOr(
      getAttribute(text, 'request_memory'),
      DEFAULT_RESOURCE_REQUEST.memoryMB,
    ),
    diskMB: parseIntOr(
      getAttribute(text, 'request_disk'),
      DEFAULT_RESOURCE_REQUEST.diskMB,
    ),
    gpus: parseIntOr(getAttribute(text, 'request_gpus'), DEFAULT_RESOURCE_REQUEST.gpus),
    gpuMinCapability:
      getAttribute(text, 'gpus_minimum_capability') ??
      DEFAULT_RESOURCE_REQUEST.gpuMinCapability,
    gpuMinMemoryMB: parseIntOr(
      getAttribute(text, 'gpus_minimum_memory'),
      DEFAULT_RESOURCE_REQUEST.gpuMinMemoryMB,
    ),
    gpuMinRuntime:
      getAttribute(text, 'gpus_minimum_runtime') ??
      DEFAULT_RESOURCE_REQUEST.gpuMinRuntime,
    cudaVersion:
      getAttribute(text, 'cuda_version') ?? DEFAULT_RESOURCE_REQUEST.cudaVersion,
    requireGpus:
      getAttribute(text, 'require_gpus') ?? DEFAULT_RESOURCE_REQUEST.requireGpus,
  };
}

/**
 * Apply a ResourceRequest to the body, replacing existing resource lines
 * and inserting missing ones. Setting `gpus = 0` removes every GPU
 * subfield so the body doesn't accumulate dead lines as the user toggles
 * the GPU section.
 */
export function applyResourcesToBody(
  text: string,
  r: ResourceRequest,
): string {
  let next = text;
  next = setAttribute(next, 'request_cpus', String(r.cpus));
  next = setAttribute(next, 'request_memory', String(r.memoryMB));
  next = setAttribute(next, 'request_disk', String(r.diskMB));

  if (r.gpus > 0) {
    next = setAttribute(next, 'request_gpus', String(r.gpus));
    next = applyOrRemove(next, 'gpus_minimum_capability', r.gpuMinCapability);
    next = applyOrRemove(
      next,
      'gpus_minimum_memory',
      r.gpuMinMemoryMB > 0 ? String(r.gpuMinMemoryMB) : '',
    );
    next = applyOrRemove(next, 'gpus_minimum_runtime', r.gpuMinRuntime);
    next = applyOrRemove(next, 'cuda_version', r.cudaVersion);
    next = applyOrRemove(next, 'require_gpus', r.requireGpus);
  } else {
    for (const k of [
      'request_gpus',
      'gpus_minimum_memory',
      'gpus_minimum_capability',
      'gpus_minimum_runtime',
      'cuda_version',
      'require_gpus',
    ]) {
      next = removeAttribute(next, k);
    }
  }
  return next;
}

function applyOrRemove(text: string, key: string, value: string): string {
  if (value.trim() === '') return removeAttribute(text, key);
  return setAttribute(text, key, value);
}

function parseIntOr(raw: string | undefined, fallback: number): number {
  if (raw === undefined) return fallback;
  const n = parseInt(raw, 10);
  return Number.isNaN(n) ? fallback : n;
}

/**
 * Parse a CSV string. First non-empty row is treated as the header.
 * Returns null if the file is empty / only blanks.
 *
 * Intentionally minimal: handles plain comma-separated values and
 * surrounding whitespace. Quoted fields are NOT supported — callers
 * should reject such inputs since HTCondor wouldn't tolerate the
 * resulting whitespace anyway.
 */
export function parseCSV(text: string): { columns: string[]; rows: string[][] } | null {
  const lines = text.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
  if (lines.length === 0) return null;
  const split = (l: string) => l.split(',').map((c) => c.trim());
  const header = split(lines[0]);
  const rows = lines.slice(1).map(split);
  return { columns: header, rows };
}
