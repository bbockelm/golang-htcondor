import type { UsageRow } from "@/lib/api";

// Display helpers for the admin usage page.

export const OUTCOME_LABELS = {
  ok: "OK",
  error: "Error",
  refused: "Refused",
  unknown_tool: "Unknown tool",
} as const;

export type Outcome = keyof typeof OUTCOME_LABELS;

export const OUTCOMES = Object.keys(OUTCOME_LABELS) as Outcome[];

/** formatSeconds renders a duration at a precision a reader can use. */
export function formatSeconds(s: number): string {
  if (!Number.isFinite(s) || s < 0) return "—";
  if (s < 1) return `${Math.round(s * 1000)} ms`;
  if (s < 60) return `${trim(s < 10 ? s.toFixed(1) : s.toFixed(0))} s`;
  if (s < 3600) {
    const m = Math.floor(s / 60);
    const rem = Math.round(s - m * 60);
    return rem ? `${m} min ${rem} s` : `${m} min`;
  }
  const h = Math.floor(s / 3600);
  const m = Math.round((s - h * 3600) / 60);
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
