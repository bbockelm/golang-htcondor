"use client";

// MCP tool-call statistics: who calls which tools, from which client,
// with what outcome and how long they take.
//
// Aggregation, including the filtered view, happens server-side; this
// page only picks the filter and renders the rows it gets back.

import { useState } from "react";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { api, type UsageFilter, type UsageRow } from "@/lib/api";
import {
  ScrollableTable,
  SortableHeader,
  useSortState,
  useSortedRows,
} from "@/components/SortableTable";
import {
  OUTCOME_LABELS,
  OUTCOMES,
  formatCount,
  formatP95,
  formatSeconds,
  p95SortValue,
  timeAgo,
} from "@/lib/usage";

type Dimension = "tool" | "user" | "client";

export default function AdminUsagePage() {
  const [filter, setFilter] = useState<UsageFilter>({});
  const { data, isLoading, error } = useQuery({
    queryKey: ["admin", "usage", filter],
    queryFn: () => api.admin.usage(filter),
    refetchInterval: 30_000,
    // Keep the old figures on screen while a new filter loads, rather
    // than flashing the page empty on every click.
    placeholderData: keepPreviousData,
  });

  const pick = (dim: Dimension, value: string) =>
    setFilter((prev) => ({ ...prev, [dim]: value || undefined }));
  const filtered = Boolean(filter.tool || filter.user || filter.client);

  return (
    <div className="space-y-4 max-w-6xl">
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Usage</h1>
        <p className="text-sm text-gray-500">MCP tool calls on this server.</p>
      </div>

      {isLoading && <p className="text-gray-400">Loading…</p>}
      {error && <p className="text-red-600 text-sm">{(error as Error).message}</p>}

      {data && !data.enabled && (
        <p className="text-sm text-gray-600">Usage is not being recorded on this server.</p>
      )}

      {data?.enabled && data.totals && (
        <>
          <div className="flex flex-wrap items-end gap-3">
            <FilterSelect label="Tool" value={filter.tool} options={data.options?.tools ?? []} onChange={(v) => pick("tool", v)} />
            <FilterSelect label="User" value={filter.user} options={data.options?.users ?? []} onChange={(v) => pick("user", v)} />
            <FilterSelect label="Client" value={filter.client} options={data.options?.clients ?? []} onChange={(v) => pick("client", v)} />
            {filtered && (
              <button
                type="button"
                onClick={() => setFilter({})}
                className="rounded-sm border border-gray-300 bg-white px-2 py-1 text-sm text-gray-700 hover:bg-gray-50"
              >
                Clear filter
              </button>
            )}
          </div>

          <Figures totals={data.totals} />

          {data.totals.calls === 0 ? (
            <p className="text-sm text-gray-500">
              {filtered ? "No tool calls match this filter." : "No tool calls yet."}
            </p>
          ) : (
            <>
              <UsageTable
                title="Tools"
                dimension="tool"
                rows={data.by_tool ?? []}
                selected={filter.tool}
                onPick={pick}
                countColumn="users"
              />
              <UsageTable
                title="Users"
                dimension="user"
                rows={data.by_user ?? []}
                selected={filter.user}
                onPick={pick}
                countColumn="clients"
              />
              <UsageTable
                title="Clients"
                dimension="client"
                rows={data.by_client ?? []}
                selected={filter.client}
                onPick={pick}
                countColumn="users"
              />
            </>
          )}
        </>
      )}
    </div>
  );
}

function FilterSelect({
  label,
  value,
  options,
  onChange,
}: {
  label: string;
  value?: string;
  options: string[];
  onChange: (v: string) => void;
}) {
  return (
    <label className="block text-xs">
      <span className="block text-gray-700">{label}</span>
      <select
        value={value ?? ""}
        onChange={(e) => onChange(e.target.value)}
        className="mt-1 max-w-[16rem] rounded-sm border border-gray-300 px-2 py-1 text-sm focus:border-brand-400 focus:outline-hidden focus:ring-1 focus:ring-brand-400"
      >
        <option value="">All</option>
        {options.map((o) => (
          <option key={o} value={o}>
            {o}
          </option>
        ))}
      </select>
    </label>
  );
}

function Figures({ totals }: { totals: UsageRow }) {
  const figures: { label: string; value: string; title?: string }[] = [
    { label: "Calls", value: formatCount(totals.calls) },
    ...OUTCOMES.map((o) => ({ label: OUTCOME_LABELS[o], value: formatCount(totals[o]) })),
    { label: "Users", value: formatCount(totals.users) },
    { label: "Clients", value: formatCount(totals.clients) },
    {
      label: "Last call",
      value: timeAgo(totals.last_call),
      title: totals.last_call ? new Date(totals.last_call).toLocaleString() : undefined,
    },
  ];
  return (
    <div className="grid grid-cols-2 gap-3 sm:grid-cols-4 lg:grid-cols-8">
      {figures.map((f) => (
        <div key={f.label} className="rounded-lg border border-gray-200 bg-white p-3" title={f.title}>
          <div className="text-xs uppercase tracking-wide text-gray-500">{f.label}</div>
          <div className="mt-1 text-xl font-semibold text-gray-900" data-testid={`figure-${f.label}`}>
            {f.value}
          </div>
        </div>
      ))}
    </div>
  );
}

type SortKey =
  | "name"
  | "calls"
  | "ok"
  | "error"
  | "refused"
  | "unknown_tool"
  | "users"
  | "clients"
  | "avg"
  | "p95"
  | "last";

function sortValue(row: UsageRow, key: SortKey): string | number | Date | undefined {
  switch (key) {
    case "name":
      return row.name;
    case "avg":
      return row.avg_seconds;
    case "p95":
      return p95SortValue(row);
    case "last":
      return row.last_call ? new Date(row.last_call) : undefined;
    default:
      return row[key];
  }
}

const DIMENSION_LABEL: Record<Dimension, string> = { tool: "Tool", user: "User", client: "Client" };

function UsageTable({
  title,
  dimension,
  rows,
  selected,
  onPick,
  countColumn,
}: {
  title: string;
  dimension: Dimension;
  rows: UsageRow[];
  selected?: string;
  onPick: (dim: Dimension, value: string) => void;
  countColumn: "users" | "clients";
}) {
  const [sort, setSort] = useSortState<SortKey>("calls");
  const sorted = useSortedRows(rows, sort, sortValue);
  const header = (label: string, key: SortKey, right = true) => (
    <SortableHeader label={label} sortKey={key} sort={sort} onSort={setSort} className={right ? "text-right" : ""} />
  );

  return (
    <section className="space-y-2" aria-label={title}>
      <h2 className="text-sm font-semibold text-gray-900">{title}</h2>
      <ScrollableTable>
        <table className="min-w-full text-sm">
          <thead className="bg-gray-50 text-left text-xs text-gray-500">
            <tr>
              {header(DIMENSION_LABEL[dimension], "name", false)}
              {header("Calls", "calls")}
              {OUTCOMES.map((o) => (
                <SortableHeader
                  key={o}
                  label={OUTCOME_LABELS[o]}
                  sortKey={o}
                  sort={sort}
                  onSort={setSort}
                  className="text-right"
                />
              ))}
              {header(countColumn === "users" ? "Users" : "Clients", countColumn)}
              {header("Avg", "avg")}
              {header("p95", "p95")}
              {header("Last call", "last")}
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-100">
            {sorted.map((r) => {
              const name = r.name ?? "";
              const active = selected === name;
              return (
                <tr key={name} className={active ? "bg-brand-50" : undefined}>
                  <td className="px-3 py-2 font-mono text-xs">
                    <button
                      type="button"
                      onClick={() => onPick(dimension, active ? "" : name)}
                      className="text-left text-brand-700 hover:underline"
                      title={active ? "Show all" : `Show only ${name}`}
                    >
                      {name}
                    </button>
                  </td>
                  <td className="px-3 py-2 text-right tabular-nums">{formatCount(r.calls)}</td>
                  {OUTCOMES.map((o) => (
                    <td
                      key={o}
                      className={`px-3 py-2 text-right tabular-nums ${
                        r[o] === 0 ? "text-gray-300" : o === "ok" ? "" : "text-amber-700"
                      }`}
                    >
                      {formatCount(r[o])}
                    </td>
                  ))}
                  <td className="px-3 py-2 text-right tabular-nums">{formatCount(r[countColumn])}</td>
                  <td className="px-3 py-2 text-right tabular-nums">{formatSeconds(r.avg_seconds)}</td>
                  <td className="px-3 py-2 text-right tabular-nums">{formatP95(r)}</td>
                  <td
                    className="px-3 py-2 text-right text-xs text-gray-600"
                    title={r.last_call ? new Date(r.last_call).toLocaleString() : undefined}
                  >
                    {timeAgo(r.last_call)}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </ScrollableTable>
    </section>
  );
}
