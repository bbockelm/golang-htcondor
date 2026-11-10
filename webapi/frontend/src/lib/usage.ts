import type { UsageRow } from "@/lib/api";

// Display helpers for the admin usage page.

// Column headings for every outcome either kind can report. Which of
// them a table shows is the server's call -- the summary carries its
// own vocabulary in display order -- so this is a lookup, not a list:
// adding an outcome server-side without touching this file gives a
// column headed with the raw value rather than no column at all.
const OUTCOME_LABELS: Record<string, string> = {
  ok: "OK",
  // MCP.
  error: "Error",
  refused: "Refused",
  unknown_tool: "Unknown tool",
  // REST.
  denied: "Denied",
  not_found: "Not found",
  rate_limited: "Rate limited",
  client_error: "Bad request",
};

/** outcomeLabel is the column heading for an outcome. */
export function outcomeLabel(outcome: string): string {
  return OUTCOME_LABELS[outcome] ?? outcome;
}

/**
 * outcomeTone says whether an outcome should read as trouble.
 *
 * "ok" is plain and everything else is amber -- including the ones
 * that are policy working rather than anything breaking. They are
 * still the rows an operator is scanning for, and colouring "denied"
 * like a success would bury the one number that explains a support
 * ticket.
 */
export function outcomeTone(outcome: string): string {
  return outcome === "ok" ? "" : "text-amber-700";
}

/** outcomeCount reads one outcome off a row, tolerating an absent key. */
export function outcomeCount(row: UsageRow, outcome: string): number {
  return row.outcomes?.[outcome] ?? 0;
}

/** formatSeconds renders a duration at a precision a reader can use. */
export function formatSeconds(s: number): string {
  if (!Number.isFinite(s) || s < 0) return "—";
  if (s < 1) return `${Math.round(s * 1000)} ms`;
  if (s < 60) return `${trim(s < 10 ? s.toFixed(1) : s.toFixed(0))} s`;
  if (s < 3600 - 0.5) {
    const total = Math.round(s);
    const m = Math.floor(total / 60);
    const rem = total - m * 60;
    return rem ? `${m} min ${rem} s` : `${m} min`;
  }
  // Round to the minute first, so 2 h 59 min 40 s reads "3 h", not
  // "2 h 60 min".
  const total = Math.round(s / 60);
  const h = Math.floor(total / 60);
  const m = total - h * 60;
  return m ? `${h} h ${m} min` : `${h} h`;
}

function trim(n: string): string {
  return n.endsWith(".0") ? n.slice(0, -2) : n;
}

/**
 * formatP95 renders the percentile as the bound it is: the 95th
 * percentile is at most the bucket's upper edge, or longer than the
 * last edge.
 */
export function formatP95(row: Pick<UsageRow, "p95_seconds" | "p95_over_seconds">): string {
  if (row.p95_seconds !== null && row.p95_seconds !== undefined) {
    return `≤ ${formatSeconds(row.p95_seconds)}`;
  }
  if (row.p95_over_seconds !== undefined) {
    return `> ${formatSeconds(row.p95_over_seconds)}`;
  }
  return "—";
}

/** p95SortValue orders "longer than the last edge" after every bound. */
export function p95SortValue(row: UsageRow): number | undefined {
  if (row.p95_seconds !== null && row.p95_seconds !== undefined) return row.p95_seconds;
  if (row.p95_over_seconds !== undefined) return row.p95_over_seconds + 1;
  return undefined;
}

/** timeAgo renders an ISO timestamp relative to now. */
export function timeAgo(iso: string | null | undefined, now: number = Date.now()): string {
  if (!iso) return "—";
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return "—";
  const secs = Math.max(0, Math.floor((now - t) / 1000));
  if (secs < 10) return "just now";
  if (secs < 60) return `${secs}s ago`;
  if (secs < 3600) return `${Math.floor(secs / 60)}m ago`;
  if (secs < 86400) return `${Math.floor(secs / 3600)}h ago`;
  return `${Math.floor(secs / 86400)}d ago`;
}

/** formatCount groups digits so 12345 reads as 12,345. */
export function formatCount(n: number): string {
  return n.toLocaleString("en-US");
}
