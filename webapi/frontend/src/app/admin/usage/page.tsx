"use client";

// Call statistics: who calls what, from which client, with what
// outcome and how long it takes.
//
// Two kinds, on two tabs: MCP tool calls and REST API requests. They
// are the same page because they are the same question asked of two
// doors into the same server, and the server reports them in one
// shape -- the summary carries its own vocabulary (what the first
// column is called, which outcome columns exist), so nothing below
// knows which kind it is rendering.
//
// Aggregation, including the filtered view, happens server-side; this
// page only picks the kind and the filter and renders what comes back.

import { useState } from "react";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import {
  api,
  type AdminUsageKind,
  type UsageFilter,
  type UsageKind,
  type UsageRow,
} from "@/lib/api";
import {
  ScrollableTable,
  SortableHeader,
  useSortState,
  useSortedRows,
} from "@/components/SortableTable";
import {
  formatCount,
  formatP95,
  formatSeconds,
  outcomeCount,
  outcomeLabel,
  outcomeTone,
  p95SortValue,
  timeAgo,
} from "@/lib/usage";

type Dimension = "name" | "user" | "client";

// The tabs to draw before the server has answered. Replaced by the
// server's own list on the first response; here so the tab bar does
// not appear a frame late or jump when it arrives.
const FALLBACK_KINDS: AdminUsageKind[] = [
  { kind: "mcp", label: "MCP tools", enabled: true },
  { kind: "rest", label: "REST API", enabled: true },
];

export default function AdminUsagePage() {
  const [kind, setKind] = useState<UsageKind>("mcp");
  // Filters are per kind: a tool name means nothing on the REST tab,
  // and carrying one across would show an empty table with no
  // obvious reason why.
  const [filters, setFilters] = useState<Record<string, UsageFilter>>({});
  const filter = filters[kind] ?? {};

  const { data, isLoading, error } = useQuery({
    queryKey: ["admin", "usage", kind, filter],
    queryFn: () => api.admin.usage(kind, filter),
    refetchInterval: 30_000,
    // Keep the old figures on screen while a new filter loads, rather
    // than flashing the page empty on every click.
    placeholderData: keepPreviousData,
  });

  const pick = (dim: Dimension, value: string) =>
    setFilters((prev) => ({
      ...prev,
      [kind]: { ...(prev[kind] ?? {}), [dim]: value || undefined },
    }));
  const clearFilter = () => setFilters((prev) => ({ ...prev, [kind]: {} }));
  const filtered = Boolean(filter.name || filter.user || filter.client);

  const kinds = data?.kinds ?? FALLBACK_KINDS;
  const title = data?.title ?? "Name";
  const outcomes = data?.outcomes ?? [];

  return (
    <div className="space-y-4 max-w-6xl">
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Usage</h1>
        <p className="text-sm text-gray-500">Calls served by this access point.</p>
      </div>

      <KindTabs kinds={kinds} selected={kind} onSelect={(k) => setKind(k as UsageKind)} />

      {isLoading && <p className="text-gray-400">Loading…</p>}
      {error && <p className="text-red-600 text-sm">{(error as Error).message}</p>}

      {data && !data.enabled && (
        <p className="text-sm text-gray-600">
          {kind === "rest"
            ? "REST API usage is not being recorded on this server."
            : "MCP usage is not being recorded on this server."}
        </p>
      )}

      {data?.enabled && data.totals && (
        <>
          <div className="flex flex-wrap items-end gap-3">
            <FilterSelect
              label={title}
              value={filter.name}
              options={data.options?.names ?? []}
              onChange={(v) => pick("name", v)}
            />
            <FilterSelect
              label="User"
              value={filter.user}
              options={data.options?.users ?? []}
              onChange={(v) => pick("user", v)}
            />
            <FilterSelect
              label="Client"
              value={filter.client}
              options={data.options?.clients ?? []}
              labels={data.client_labels}
              onChange={(v) => pick("client", v)}
            />
            {filtered && (
              <button
                type="button"
                onClick={clearFilter}
                className="rounded-sm border border-gray-300 bg-white px-2 py-1 text-sm text-gray-700 hover:bg-gray-50"
              >
                Clear filter
              </button>
            )}
          </div>

          <Figures totals={data.totals} outcomes={outcomes} />

          {data.totals.calls === 0 ? (
            <p className="text-sm text-gray-500">
              {filtered ? "No calls match this filter." : "No calls yet."}
            </p>
          ) : (
            <>
              <UsageTable
                title={`${title}s`}
                dimension="name"
                heading={title}
                outcomes={outcomes}
                rows={data.by_name ?? []}
                selected={filter.name}
                onPick={pick}
                countColumn="users"
              />
              <UsageTable
                title="Users"
                dimension="user"
                heading="User"
                outcomes={outcomes}
                rows={data.by_user ?? []}
                selected={filter.user}
                onPick={pick}
                countColumn="clients"
              />
              <UsageTable
                title="Clients"
                dimension="client"
                heading="Client"
                outcomes={outcomes}
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

function KindTabs({
  kinds,
  selected,
  onSelect,
}: {
  kinds: AdminUsageKind[];
  selected: string;
  onSelect: (kind: string) => void;
}) {
  return (
    <div className="flex gap-1 border-b border-gray-200" role="tablist" aria-label="Usage kind">
      {kinds.map((k) => {
        const active = k.kind === selected;
        return (
          <button
            key={k.kind}
            type="button"
            role="tab"
            aria-selected={active}
            onClick={() => onSelect(k.kind)}
            className={`-mb-px border-b-2 px-3 py-2 text-sm ${
              active
                ? "border-brand-600 font-semibold text-brand-700"
                : "border-transparent text-gray-600 hover:text-gray-900"
            }`}
            // A kind this server is not counting still gets a tab, so
            // the page says the feature exists and is off rather than
            // leaving an admin wondering where it went.
            title={k.enabled ? undefined : "Not being recorded on this server"}
          >
            {k.label}
            {!k.enabled && <span className="ml-1 text-xs text-gray-400">(off)</span>}
          </button>
        );
      })}
    </div>
  );
}

function FilterSelect({
  label,
  value,
  options,
  labels,
  onChange,
}: {
  label: string;
  value?: string;
  options: string[];
  // Display names for options whose recorded value is an identifier.
  // The option's VALUE stays the recorded string, which is what the
  // server filters on.
  labels?: Record<string, string>;
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
            {labels?.[o] ?? o}
          </option>
        ))}
      </select>
    </label>
  );
}

function Figures({ totals, outcomes }: { totals: UsageRow; outcomes: string[] }) {
  const figures: { label: string; value: string; title?: string }[] = [
    { label: "Calls", value: formatCount(totals.calls) },
    ...outcomes.map((o) => ({
      label: outcomeLabel(o),
      value: formatCount(outcomeCount(totals, o)),
    })),
    { label: "Users", value: formatCount(totals.users) },
    { label: "Clients", value: formatCount(totals.clients) },
    {
      label: "Last call",
      value: timeAgo(totals.last_call),
      title: totals.last_call ? new Date(totals.last_call).toLocaleString() : undefined,
    },
  ];
  return (
    <div className="grid grid-cols-2 gap-3 sm:grid-cols-4 lg:grid-cols-5 xl:grid-cols-10">
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

// A sort key is either one of the fixed columns or an outcome, which
// the server names. The prefix keeps an outcome called "calls" or
// "users" from colliding with a column of that name.
type SortKey = "name" | "calls" | "users" | "clients" | "avg" | "p95" | "last" | `outcome:${string}`;

function sortValue(row: UsageRow, key: SortKey): string | number | Date | undefined {
  if (key.startsWith("outcome:")) return outcomeCount(row, key.slice("outcome:".length));
  switch (key) {
    case "name":
      return row.label ?? row.name;
    case "avg":
      return row.avg_seconds;
    case "p95":
      return p95SortValue(row);
    case "last":
      return row.last_call ? new Date(row.last_call) : undefined;
    default:
      return row[key as "calls" | "users" | "clients"];
  }
}

function UsageTable({
  title,
  dimension,
  heading,
  outcomes,
  rows,
  selected,
  onPick,
  countColumn,
}: {
  title: string;
  dimension: Dimension;
  heading: string;
  outcomes: string[];
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
              {header(heading, "name", false)}
              {header("Calls", "calls")}
              {outcomes.map((o) => (
                <SortableHeader
                  key={o}
                  label={outcomeLabel(o)}
                  sortKey={`outcome:${o}` as SortKey}
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
              const shown = r.label ?? name;
              return (
                <tr key={name} className={active ? "bg-brand-50" : undefined}>
                  <td className="px-3 py-2 font-mono text-xs">
                    <button
                      type="button"
                      onClick={() => onPick(dimension, active ? "" : name)}
                      className="text-left text-brand-700 hover:underline"
                      title={active ? "Show all" : `Show only ${shown}`}
                    >
                      {shown}
                    </button>
                  </td>
                  <td className="px-3 py-2 text-right tabular-nums">{formatCount(r.calls)}</td>
                  {outcomes.map((o) => {
                    const n = outcomeCount(r, o);
                    return (
                      <td
                        key={o}
                        className={`px-3 py-2 text-right tabular-nums ${
                          n === 0 ? "text-gray-300" : outcomeTone(o)
                        }`}
                      >
                        {formatCount(n)}
                      </td>
                    );
                  })}
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
