'use client';

// /pool is the pool overview: a capacity/usage summary across every
// execute node, a table with one row per node that expands to reveal its
// slots (the same disclosure pattern the jobs page uses for batches),
// click-through to a per-slot page, and a filter that runs either as a
// free-text substring match (client-side) or as a raw ClassAd expression
// (sent to the collector query).

import { useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useRouter } from 'next/navigation';
import { api, ApiError } from '@/lib/api';
import {
  parseSlot,
  groupByMachine,
  summarize,
  slotStateStyle,
  gib,
  textHaystack,
  SLOT_PROJECTION,
  type Slot,
  type NodeGroup,
  type ResourceUsage,
} from '@/lib/pool';

type FilterMode = 'text' | 'expr';

export default function PoolPage() {
  const router = useRouter();
  const [mode, setMode] = useState<FilterMode>('text');
  const [input, setInput] = useState('');
  // In expression mode the constraint is only sent when applied (Enter /
  // Apply), so we neither hammer the collector on every keystroke nor ship
  // half-typed, unparseable expressions.
  const [appliedExpr, setAppliedExpr] = useState('');
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  const constraint = mode === 'expr' ? appliedExpr : '';

  // Always exclude per-job (dynamic) slots from the query. On a busy pool
  // they outnumber the machines by orders of magnitude, and fetching them
  // all made the streamed response so large it was truncated mid-array
  // ("Expected ',' or ']'"). Usage is derived from each machine's free
  // capacity instead (see usageFor), so the totals stay correct without
  // them. A user expression is ANDed on top.
  const excludeDynamic = 'SlotType =!= "Dynamic"';
  const effectiveConstraint = constraint
    ? `(${excludeDynamic}) && (${constraint})`
    : excludeDynamic;

  const { data, isLoading, error, isFetching, refetch } = useQuery({
    queryKey: ['pool-slots', effectiveConstraint],
    queryFn: () =>
      api.collector.list({
        adType: 'startd',
        projection: SLOT_PROJECTION,
        limit: '*',
        constraint: effectiveConstraint,
      }),
    refetchInterval: 30_000,
    retry: false,
  });

  const slots = useMemo(() => (data?.ads ?? []).map(parseSlot), [data]);

  const textFilter = mode === 'text' ? input.trim().toLowerCase() : '';
  const filtered = useMemo(() => {
    if (!textFilter) return slots;
    const tokens = textFilter.split(/\s+/);
    return slots.filter((s) => {
      const h = textHaystack(s);
      return tokens.every((t) => h.includes(t));
    });
  }, [slots, textFilter]);

  const summary = useMemo(() => summarize(filtered), [filtered]);
  const nodes = useMemo(() => groupByMachine(filtered), [filtered]);

  const toggle = (machine: string) =>
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(machine)) next.delete(machine);
      else next.add(machine);
      return next;
    });

  const notConfigured = error instanceof ApiError && error.status === 501;
  const exprError =
    mode === 'expr' && !notConfigured && error instanceof ApiError
      ? error.message
      : null;

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <h1 className="text-2xl font-bold text-gray-900">Pool</h1>
        <span className="text-sm text-gray-500">
          Execute nodes and their slots, as reported to the collector.
        </span>
        {isFetching && !isLoading && (
          <span className="text-xs text-gray-400">refreshing…</span>
        )}
      </div>

      {notConfigured ? (
        <p className="rounded-lg border border-gray-200 bg-white p-4 text-sm text-gray-600">
          This API server has no collector configured, so there is no pool to
          show.
        </p>
      ) : (
        <>
          <FilterControls
            mode={mode}
            input={input}
            onMode={(m) => {
              setMode(m);
              setInput('');
              setAppliedExpr('');
            }}
            onInput={setInput}
            onApplyExpr={() => setAppliedExpr(input.trim())}
          />
          {exprError && (
            <p className="rounded-sm border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">
              {exprError}
            </p>
          )}

          <p className="text-xs text-gray-400">
            Per-job (dynamic) slots are excluded; usage reflects each
            machine&apos;s allocated capacity.
          </p>

          {data?.error && (
            <p className="rounded-sm border border-amber-200 bg-amber-50 px-3 py-2 text-sm text-amber-800">
              The collector query returned only partial results: {data.error}
            </p>
          )}

          {isLoading ? (
            <p className="text-sm text-gray-400">Loading pool…</p>
          ) : error && !exprError ? (
            <p className="text-sm text-red-600">
              Could not load the pool: {(error as Error).message}
            </p>
          ) : (
            <>
              <SummaryCards
                machines={summary.machines}
                slots={summary.slots}
                usage={summary.usage}
                stateCounts={summary.stateCounts}
              />
              {nodes.length === 0 ? (
                <p className="text-sm text-gray-500">
                  No slots match this {mode === 'expr' ? 'expression' : 'filter'}.
                </p>
              ) : (
                <NodeTable
                  nodes={nodes}
                  expanded={expanded}
                  onToggle={toggle}
                  onSlot={(name) =>
                    router.push(`/pool/slots/${encodeURIComponent(name)}`)
                  }
                />
              )}
            </>
          )}
        </>
      )}
    </div>
  );
}

function FilterControls({
  mode,
  input,
  onMode,
  onInput,
  onApplyExpr,
}: {
  mode: FilterMode;
  input: string;
  onMode: (m: FilterMode) => void;
  onInput: (v: string) => void;
  onApplyExpr: () => void;
}) {
  return (
    <div className="flex flex-wrap items-center gap-2">
      <div className="inline-flex overflow-hidden rounded-sm border border-gray-300">
        {(['text', 'expr'] as const).map((m) => (
          <button
            key={m}
            type="button"
            onClick={() => onMode(m)}
            className={`px-3 py-1.5 text-sm ${
              mode === m
                ? 'bg-brand-600 text-white'
                : 'bg-white text-gray-600 hover:bg-gray-50'
            }`}
          >
            {m === 'text' ? 'Text' : 'ClassAd expression'}
          </button>
        ))}
      </div>
      {mode === 'text' ? (
        <input
          type="text"
          value={input}
          onChange={(e) => onInput(e.target.value)}
          placeholder="Filter slots (host, state, owner, arch…)"
          className="min-w-[20rem] flex-1 rounded-sm border border-gray-300 px-3 py-1.5 text-sm"
        />
      ) : (
        <form
          className="flex flex-1 items-center gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            onApplyExpr();
          }}
        >
          <input
            type="text"
            value={input}
            onChange={(e) => onInput(e.target.value)}
            placeholder={'ClassAd, e.g. GPUs > 0 && State == "Unclaimed"'}
            spellCheck={false}
            className="min-w-[20rem] flex-1 rounded-sm border border-gray-300 px-3 py-1.5 font-mono text-sm"
          />
          <button
            type="submit"
            className="rounded-sm bg-brand-600 px-4 py-1.5 text-sm font-medium text-white hover:bg-brand-700"
          >
            Apply
          </button>
        </form>
      )}
    </div>
  );
}

function SummaryCards({
  machines,
  slots,
  usage,
  stateCounts,
}: {
  machines: number;
  slots: number;
  usage: ResourceUsage;
  stateCounts: Record<string, number>;
}) {
  return (
    <div className="space-y-3">
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
        <StatCard label="Execute nodes" value={machines.toLocaleString()} />
        <StatCard label="Slots" value={slots.toLocaleString()} />
        <StatCard
          label="CPUs (in use / total)"
          value={`${usage.usedCpus.toLocaleString()} / ${usage.totalCpus.toLocaleString()}`}
          sub={pct(usage.usedCpus, usage.totalCpus)}
        />
        <StatCard
          label="Memory (in use / total)"
          value={`${gib(usage.usedMemoryMB)} / ${gib(usage.totalMemoryMB)}`}
          sub={pct(usage.usedMemoryMB, usage.totalMemoryMB)}
        />
        <StatCard
          label="GPUs (in use / total)"
          value={`${usage.usedGpus.toLocaleString()} / ${usage.totalGpus.toLocaleString()}`}
          sub={usage.totalGpus > 0 ? pct(usage.usedGpus, usage.totalGpus) : undefined}
        />
      </div>
      <StatePills counts={stateCounts} />
    </div>
  );
}

function StatCard({
  label,
  value,
  sub,
}: {
  label: string;
  value: string;
  sub?: string;
}) {
  return (
    <div className="rounded-lg border border-gray-200 bg-white p-3">
      <div className="text-xs uppercase tracking-wide text-gray-500">
        {label}
      </div>
      <div className="mt-1 text-lg font-semibold text-gray-900">{value}</div>
      {sub && <div className="text-xs text-gray-400">{sub}</div>}
    </div>
  );
}

function StatePills({ counts }: { counts: Record<string, number> }) {
  const entries = Object.entries(counts).sort((a, b) => b[1] - a[1]);
  if (entries.length === 0) return null;
  return (
    <div className="flex flex-wrap gap-2">
      {entries.map(([state, n]) => (
        <span
          key={state}
          className={`inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 text-xs font-medium ${slotStateStyle(
            state,
          )}`}
        >
          {state}
          <span className="font-normal opacity-70">{n}</span>
        </span>
      ))}
    </div>
  );
}

function pct(used: number, total: number): string {
  if (!total) return '0%';
  return `${Math.round((used / total) * 100)}% in use`;
}

function Caret({ open }: { open: boolean }) {
  return (
    <span
      className={`inline-block text-gray-400 transition-transform ${
        open ? 'rotate-90' : ''
      }`}
      aria-hidden
    >
      ▶
    </span>
  );
}

function NodeTable({
  nodes,
  expanded,
  onToggle,
  onSlot,
}: {
  nodes: NodeGroup[];
  expanded: Set<string>;
  onToggle: (machine: string) => void;
  onSlot: (name: string) => void;
}) {
  return (
    <div className="overflow-x-auto rounded-lg border border-gray-200 bg-white">
      <table className="min-w-full text-sm">
        <thead className="bg-gray-50 text-xs uppercase tracking-wide text-gray-500">
          <tr>
            <th className="w-6 px-3 py-2" />
            <th className="px-3 py-2 text-left">Execute node</th>
            <th className="px-3 py-2 text-left">Slots</th>
            <th className="px-3 py-2 text-left">State</th>
            <th className="px-3 py-2 text-left">CPUs</th>
            <th className="px-3 py-2 text-left">Memory</th>
            <th className="px-3 py-2 text-left">GPUs</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-gray-100">
          {nodes.map((node) => (
            <NodeRow
              key={node.machine}
              node={node}
              open={expanded.has(node.machine)}
              onToggle={() => onToggle(node.machine)}
              onSlot={onSlot}
            />
          ))}
        </tbody>
      </table>
    </div>
  );
}

function NodeRow({
  node,
  open,
  onToggle,
  onSlot,
}: {
  node: NodeGroup;
  open: boolean;
  onToggle: () => void;
  onSlot: (name: string) => void;
}) {
  const u = node.usage;
  return (
    <>
      <tr
        className="cursor-pointer hover:bg-gray-50"
        onClick={onToggle}
        aria-expanded={open}
      >
        <td className="px-3 py-2">
          <Caret open={open} />
        </td>
        <td className="px-3 py-2 font-medium text-gray-900">{node.machine}</td>
        <td className="px-3 py-2 text-gray-600">{node.slots.length}</td>
        <td className="px-3 py-2">
          <StatePills counts={node.stateCounts} />
        </td>
        <td className="px-3 py-2 text-gray-600">
          {u.usedCpus} / {u.totalCpus}
        </td>
        <td className="px-3 py-2 text-gray-600">
          {gib(u.usedMemoryMB)} / {gib(u.totalMemoryMB)}
        </td>
        <td className="px-3 py-2 text-gray-600">
          {u.totalGpus > 0 ? `${u.usedGpus} / ${u.totalGpus}` : '—'}
        </td>
      </tr>
      {open && (
        <tr>
          <td colSpan={7} className="bg-gray-50 px-3 py-2">
            <SlotSubTable slots={node.slots} onSlot={onSlot} />
          </td>
        </tr>
      )}
    </>
  );
}

function SlotSubTable({
  slots,
  onSlot,
}: {
  slots: Slot[];
  onSlot: (name: string) => void;
}) {
  const ordered = [...slots].sort((a, b) => a.name.localeCompare(b.name));
  return (
    <table className="min-w-full text-xs">
      <thead className="text-gray-500">
        <tr>
          <th className="px-2 py-1 text-left">Slot</th>
          <th className="px-2 py-1 text-left">Type</th>
          <th className="px-2 py-1 text-left">State / Activity</th>
          <th className="px-2 py-1 text-left">CPUs</th>
          <th className="px-2 py-1 text-left">Memory</th>
          <th className="px-2 py-1 text-left">GPUs</th>
          <th className="px-2 py-1 text-left">Owner</th>
        </tr>
      </thead>
      <tbody>
        {ordered.map((s) => (
          <tr
            key={s.name}
            className="cursor-pointer border-t border-gray-200 hover:bg-white"
            onClick={() => onSlot(s.name)}
          >
            <td className="px-2 py-1 font-mono text-brand-700">{s.name}</td>
            <td className="px-2 py-1">{s.slotType || '—'}</td>
            <td className="px-2 py-1">
              <span
                className={`inline-flex rounded-full px-2 py-0.5 font-medium ${slotStateStyle(
                  s.state,
                )}`}
              >
                {s.state ?? '?'}
              </span>
              {s.activity && (
                <span className="ml-1 text-gray-400">/ {s.activity}</span>
              )}
            </td>
            <td className="px-2 py-1">{s.cpus ?? '—'}</td>
            <td className="px-2 py-1">{gib(s.memoryMB)}</td>
            <td className="px-2 py-1">{s.gpus ?? '—'}</td>
            <td className="px-2 py-1 text-gray-600">{s.remoteOwner ?? '—'}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
