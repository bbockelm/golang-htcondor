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
