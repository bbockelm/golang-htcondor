"use client";

import { useMemo, useState } from "react";

// Sortable, separately-scrolling tables for the admin pages.
//
// Both exist because these two tables grow without bound. The tokens page
// lists every live grant and the clients page every registered client, so on
// a busy access point the page becomes long enough that what sits below it --
// the log-out control, on the admin shell -- is several screens away. A table
// that scrolls inside a fixed box keeps the page the same height whatever the
// pool is doing.

export type SortDirection = "asc" | "desc";

export type SortState<K extends string> = {
  key: K;
  direction: SortDirection;
};

/**
 * useSortedRows sorts rows by a caller-supplied accessor.
 *
 * The accessor returns a string, number or Date rather than the cell's
 * rendered markup: sorting the rendered form would order "Last used" by the
 * text of a formatted date, which puts April before January.
 */
export function useSortedRows<T, K extends string>(
  rows: T[],
  sort: SortState<K>,
  valueOf: (row: T, key: K) => string | number | Date | undefined,
): T[] {
  return useMemo(() => {
    const factor = sort.direction === "asc" ? 1 : -1;
    return [...rows].sort((a, b) => {
      const av = valueOf(a, sort.key);
      const bv = valueOf(b, sort.key);

      // Missing values sort last in BOTH directions. Treating them as
      // empty strings would put every never-used client at the top of an
      // ascending sort, which reads as "these are the oldest" rather than
      // "these have no value here".
      const aMissing = av === undefined || av === "" || av === null;
      const bMissing = bv === undefined || bv === "" || bv === null;
      if (aMissing && bMissing) return 0;
      if (aMissing) return 1;
      if (bMissing) return -1;

      if (av instanceof Date || bv instanceof Date) {
        return (Number(av) - Number(bv)) * factor;
      }
      if (typeof av === "number" && typeof bv === "number") {
        return (av - bv) * factor;
      }
      return String(av).localeCompare(String(bv), undefined, { numeric: true }) * factor;
    });
  }, [rows, sort, valueOf]);
}

/** SortableHeader renders one <th> that toggles the sort when clicked. */
export function SortableHeader<K extends string>({
  label,
  sortKey,
  sort,
  onSort,
  className = "",
}: {
  label: string;
  sortKey: K;
  sort: SortState<K>;
  onSort: (next: SortState<K>) => void;
  className?: string;
}) {
  const active = sort.key === sortKey;
  return (
    <th className={`px-3 py-2 ${className}`} aria-sort={active ? (sort.direction === "asc" ? "ascending" : "descending") : "none"}>
      <button
        type="button"
        className="inline-flex items-center gap-1 uppercase tracking-wide hover:text-gray-900"
        onClick={() =>
          onSort({
            key: sortKey,
            // Clicking the column already sorted reverses it; clicking a
            // different one starts ascending, rather than inheriting a
            // direction chosen for some other column's values.
            direction: active && sort.direction === "asc" ? "desc" : "asc",
          })
        }
      >
        {label}
        <span aria-hidden className={active ? "text-gray-900" : "text-gray-300"}>
          {active && sort.direction === "desc" ? "▾" : "▴"}
        </span>
      </button>
    </th>
  );
}

/** useSortState is the usual pairing of a sort and its setter. */
export function useSortState<K extends string>(key: K, direction: SortDirection = "desc") {
  return useState<SortState<K>>({ key, direction });
}

/**
 * ScrollableTable wraps a table so it scrolls inside a fixed box.
 *
 * The header stays put while the body moves: a table long enough to need
 * this is one where the column you are reading has left the screen.
 */
export function ScrollableTable({ children }: { children: React.ReactNode }) {
  return (
    <div className="max-h-[60vh] overflow-auto rounded-lg border border-gray-200 bg-white [&_thead]:sticky [&_thead]:top-0 [&_thead]:z-10">
      {children}
    </div>
  );
}
