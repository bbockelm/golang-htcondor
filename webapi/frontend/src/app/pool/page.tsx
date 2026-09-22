'use client';

// /pool is the pool overview: a capacity/usage summary across every
// execute node, a table with one row per node that expands to reveal its
// slots (the disclosure pattern the jobs page uses for batches),
// click-through to a per-slot page, and a filter that runs either as a
// free-text substring match (client-side) or a raw ClassAd expression
// (sent to the collector query).

import { useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useRouter } from 'next/navigation';
import { api, ApiError } from '@/lib/api';
import { FilterControls, type FilterMode } from '@/components/FilterControls';
import {
  parseSlot,
  groupByMachine,
  summarize,
  slotStateStyle,
  gib,
  gibNum,
  pct,
  textHaystack,
  SLOT_PROJECTION,
  type Slot,
  type NodeGroup,
  type PoolSummary,
} from '@/lib/pool';

export default function PoolPage() {
  const router = useRouter();
  const [mode, setMode] = useState<FilterMode>('text');
  const [input, setInput] = useState('');
  const [appliedExpr, setAppliedExpr] = useState('');
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  const constraint = mode === 'expr' ? appliedExpr : '';

  // Exclude per-job (dynamic) slots from the query. On a busy pool they
  // outnumber the machines by orders of magnitude and blew the streamed
  // response past the point it was truncated. Running-job counts come from
  // the partitionable slot's NumDynamicSlots instead. A user expression is
  // ANDed on top. Backfill slots ARE fetched (we surface them separately).
  const excludeDynamic = 'SlotType =!= "Dynamic"';
  const effectiveConstraint = constraint
    ? `(${excludeDynamic}) && (${constraint})`
    : excludeDynamic;

  const { data, isLoading, error, isFetching } = useQuery({
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
            textPlaceholder="Filter slots (host, state, owner, arch…)"
            exprPlaceholder={'ClassAd, e.g. GPUs > 0 && State == "Unclaimed"'}
          />
          {exprError && (
            <p className="rounded-sm border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">
              {exprError}
            </p>
          )}
          <p className="text-xs text-gray-400">
            Usage reflects each machine&apos;s allocated capacity; expand a
            node to see its individual slots, including the per-job (dynamic)
            slots. Backfill slots are counted separately.
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
              <SummaryPanel summary={summary} />
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

function SummaryPanel({ summary }: { summary: PoolSummary }) {
  const u = summary.usage;
  const rows: {
    label: string;
    used: string;
    total: string;
    ratio: string;
  }[] = [
    {
      label: 'CPUs',
      used: u.usedCpus.toLocaleString(),
      total: u.totalCpus.toLocaleString(),
      ratio: pct(u.usedCpus, u.totalCpus),
    },
    {
      label: 'Memory (GiB)',
      used: gibNum(u.usedMemoryMB),
      total: gibNum(u.totalMemoryMB),
      ratio: pct(u.usedMemoryMB, u.totalMemoryMB),
    },
  ];
  if (u.totalGpus > 0) {
    rows.push({
      label: 'GPUs',
      used: u.usedGpus.toLocaleString(),
      total: u.totalGpus.toLocaleString(),
      ratio: pct(u.usedGpus, u.totalGpus),
    });
  }

  return (
    <div className="grid gap-3 lg:grid-cols-3">
      {/* Vertically-aligned usage table: one resource per row, columns
          line up so used/total/% are scannable at a glance. */}
      <div className="overflow-x-auto rounded-lg border border-gray-200 bg-white lg:col-span-2">
        <table className="min-w-full text-sm tabular-nums">
          <thead className="bg-gray-50 text-xs uppercase tracking-wide text-gray-500">
            <tr>
              <th className="px-3 py-2 text-left">Resource</th>
              <th className="px-3 py-2 text-right">In use</th>
              <th className="px-3 py-2 text-right">Total</th>
              <th className="px-3 py-2 text-right">%</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-100">
            {rows.map((r) => (
              <tr key={r.label}>
                <td className="px-3 py-2 font-medium text-gray-700">{r.label}</td>
                <td className="px-3 py-2 text-right text-gray-900">{r.used}</td>
                <td className="px-3 py-2 text-right text-gray-500">{r.total}</td>
                <td className="px-3 py-2 text-right text-gray-500">{r.ratio}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="grid grid-cols-2 gap-3">
        <StatCard label="Execute nodes" value={summary.machines.toLocaleString()} />
        <StatCard label="Running jobs" value={summary.runningJobs.toLocaleString()} />
        <StatCard
          label="Owner (unavailable)"
          value={summary.ownerNodes.toLocaleString()}
        />
        {summary.backfillCpus > 0 && (
          <StatCard
            label="Backfill CPUs"
            value={summary.backfillCpus.toLocaleString()}
          />
        )}
      </div>
    </div>
  );
}

function StatCard({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-lg border border-gray-200 bg-white p-3">
      <div className="text-xs uppercase tracking-wide text-gray-500">{label}</div>
      <div className="mt-1 text-lg font-semibold text-gray-900">{value}</div>
    </div>
  );
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

function OwnerBadge() {
  return (
    <span className="inline-flex rounded-full bg-orange-100 px-2 py-0.5 text-xs font-medium text-orange-800">
      Owner
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
      <table className="min-w-full text-sm tabular-nums">
        <thead className="bg-gray-50 text-xs uppercase tracking-wide text-gray-500">
          <tr>
            <th className="w-6 px-3 py-2" />
            <th className="px-3 py-2 text-left">Execute node</th>
            <th className="px-3 py-2 text-right">Running</th>
            <th className="px-3 py-2 text-right">CPUs</th>
            <th className="px-3 py-2 text-right">Memory (GiB)</th>
            <th className="px-3 py-2 text-right">GPUs</th>
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

// UsagePair renders "used / total" so the used figures line up vertically
// down a column: the used value is right-aligned against the slash and the
// total is a fixed-width, left-aligned muted suffix, so the slashes (and
// therefore the used values' right edges) sit at the same x on every row.
function UsagePair({ used, total }: { used: string; total: string }) {
  if (total === '—' || total === '0') {
    return <span className="text-gray-400">—</span>;
  }
  return (
    <span className="inline-flex items-baseline justify-end tabular-nums">
      <span className="min-w-[4ch] text-right text-gray-800">{used}</span>
      <span className="px-1 text-gray-300">/</span>
      <span className="min-w-[4ch] text-left text-gray-500">{total}</span>
    </span>
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

  // The overview query excludes per-job (dynamic) slots to keep the payload
  // small, so node.slots has none. When a node is expanded, fetch its full
  // slot list — dynamic slots included — for just that machine. This is a
  // narrow query and only runs while the row is open.
  const { data: detail, isFetching: detailFetching } = useQuery({
    queryKey: ['pool-node-slots', node.machine],
    queryFn: () =>
      api.collector.list({
        adType: 'startd',
        projection: SLOT_PROJECTION,
        limit: '*',
        constraint: `Machine == ${JSON.stringify(node.machine)}`,
      }),
    enabled: open,
    refetchInterval: open ? 30_000 : false,
    retry: false,
  });
  const detailSlots = useMemo(
    () => (detail?.ads ? detail.ads.map(parseSlot) : node.slots),
    [detail, node.slots],
  );

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
        <td className="px-3 py-2 font-medium text-gray-900">
          <span className="inline-flex items-center gap-2">
            {node.machine}
            {node.owner && <OwnerBadge />}
          </span>
        </td>
        <td className="px-3 py-2 text-right text-gray-600">{node.runningJobs}</td>
        <td className="px-3 py-2 text-right">
          <UsagePair used={String(u.usedCpus)} total={String(u.totalCpus)} />
        </td>
        <td className="px-3 py-2 text-right">
          <UsagePair used={gibNum(u.usedMemoryMB)} total={gibNum(u.totalMemoryMB)} />
        </td>
        <td className="px-3 py-2 text-right">
          <UsagePair used={String(u.usedGpus)} total={String(u.totalGpus)} />
        </td>
      </tr>
      {open && (
        <tr>
          <td colSpan={6} className="bg-gray-50 px-3 py-2">
            <SlotSubTable
              slots={detailSlots}
              loading={detailFetching && !detail}
              onSlot={onSlot}
            />
          </td>
        </tr>
      )}
    </>
  );
}

function SlotSubTable({
  slots,
  loading,
  onSlot,
}: {
  slots: Slot[];
  loading?: boolean;
  onSlot: (name: string) => void;
}) {
  const ordered = [...slots].sort((a, b) => a.name.localeCompare(b.name));
  return (
    <table className="min-w-full text-xs tabular-nums">
      <thead className="text-gray-500">
        <tr>
          <th className="px-2 py-1 text-left">
            Slot{loading && <span className="ml-2 text-gray-400">loading…</span>}
          </th>
          <th className="px-2 py-1 text-left">Type</th>
          <th className="px-2 py-1 text-left">State / Activity</th>
          <th className="px-2 py-1 text-right">CPUs</th>
          <th className="px-2 py-1 text-right">Memory</th>
          <th className="px-2 py-1 text-right">GPUs</th>
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
            <td className="px-2 py-1">
              {s.backfill ? (
                <span className="rounded-full bg-purple-100 px-2 py-0.5 font-medium text-purple-800">
                  backfill
                </span>
              ) : (
                s.slotType || '—'
              )}
            </td>
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
            <td className="px-2 py-1 text-right">{s.cpus ?? '—'}</td>
            <td className="px-2 py-1 text-right">{gib(s.memoryMB)}</td>
            <td className="px-2 py-1 text-right">{s.gpus ?? '—'}</td>
            <td className="px-2 py-1 text-gray-600">{s.remoteOwner ?? '—'}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
