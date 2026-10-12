'use client';

// DagGraphPanel draws a DAG workflow's structure from
// GET /api/v1/jobs/{id}/dag, for the DAGMan manager job it is given: on
// that job's page, and on the workflow's batch page.
//
// Props: jobId is the DAGMan manager job, "cluster.proc"; schedd names
// its access point in multi-AP mode (the id becomes "cluster.proc@schedd",
// the form every per-job endpoint takes there). The caller decides whether
// the job has a graph to draw -- a DAGMan manager whose files are in the
// spool -- and renders the panel only then; on a job without one the
// endpoint answers with the reason, which the panel shows.

import { useCallback, useMemo, useState } from 'react';
import Link from 'next/link';
import {
  api,
  ApiError,
  type DagGraphGroup,
  type DagGraphResponse,
} from '@/lib/api';
import { humanDuration } from '@/lib/duration';
import { statusPillCls } from '@/lib/statusPill';
import { useNowTick } from '@/lib/useNowTick';

// --- Workflow graph -------------------------------------------------
//
// The panel below draws GET /api/v1/jobs/{id}/dag: the workflow's
// structure, collapsed so that nodes doing the same job in the same
// place are one shape. The collapse is what makes it drawable at all --
// a 50,000-way fan-out is two boxes and one line here -- and it is also
// the one thing a reader has to be told about, which is why the
// some-to-some note below is rendered rather than left in a comment.
//
// Everything here is explicit-load. There is no single-file protocol
// between this server and the schedd, so a cache miss re-transfers the
// workflow's whole spool; a poll loop would be a poll loop over every
// file the workflow has written.

// Box geometry for the drawing. Fixed rather than measured: the
// collapsed graph is small by construction, and measuring would buy a
// layout pass for a picture that is usually five boxes.
const DAG_BOX_W = 176;
const DAG_BOX_H = 58;
const DAG_H_GAP = 26;
const DAG_V_GAP = 72;
const DAG_PAD = 16;

// Past these the drawing stops being a drawing. A layer wider than
// DAG_MAX_LAYER is a wall of boxes nobody can trace an edge through,
// and a graph with more than DAG_MAX_GROUPS shapes is not a summary of
// anything. Rather than shrink the text to nothing (or attempt a real
// layout, which is a graph library's job and not this panel's), the
// panel says so and falls back to the group list.
const DAG_MAX_LAYER = 40;
const DAG_MAX_GROUPS = 150;

// dagLayers assigns every group a layer and returns the layers in
// drawing order, top to bottom. layer(g) is the longest path to g from
// any root, which is the assignment that makes every edge point
// strictly downwards -- the property that makes the picture readable.
//
// O(V+E): one pass to build the forward/reverse indexes, then a Kahn
// sweep that relaxes each child's layer as its parents settle. Within a
// layer the order is first appearance in `groups`, so the same response
// always draws the same picture; keying off Map/Set iteration order
// instead would reshuffle the row whenever the server reordered its
// array.
//
// Two inputs must not break it, because both arrive from real (torn or
// spliced) DAG files:
//   - a parent_ids entry naming a group that is not in the list. It is
//     dropped: treating a dangling reference as a real parent leaves
//     its child permanently unsettled, i.e. invisible.
//   - a cycle. The server flags that as approximate_layering; here the
//     members Kahn could not settle are placed just under the deepest
//     parent that did settle, rather than dropped.
export function dagLayers(
  groups: readonly { id: string; parent_ids?: string[] | null }[],
): string[][] {
  // Insertion order is first appearance, and every ordering below reads
  // it back out of this Map.
  const order = new Map<string, number>();
  groups.forEach((g, i) => {
    if (!order.has(g.id)) order.set(g.id, i);
  });
  if (order.size === 0) return [];

  const parents = new Map<string, string[]>();
  const children = new Map<string, string[]>();
  const indegree = new Map<string, number>();
  for (const id of order.keys()) {
    parents.set(id, []);
    children.set(id, []);
    indegree.set(id, 0);
  }
  for (const g of groups) {
    const seen = new Set<string>();
    for (const p of g.parent_ids ?? []) {
      // Self-edges and duplicates would each leave a permanent +1 on
      // the indegree, which is the same failure as a dangling parent.
      if (p === g.id || !order.has(p) || seen.has(p)) continue;
      seen.add(p);
      parents.get(g.id)!.push(p);
      children.get(p)!.push(g.id);
      indegree.set(g.id, indegree.get(g.id)! + 1);
    }
  }

  const layer = new Map<string, number>();
  const queue: string[] = [];
  for (const id of order.keys()) {
    if (indegree.get(id) === 0) {
      layer.set(id, 0);
      queue.push(id);
    }
  }
  for (let i = 0; i < queue.length; i++) {
    const id = queue[i];
    const at = layer.get(id)!;
    for (const c of children.get(id)!) {
      // Longest path, not shortest: a node with parents at depth 1 and
      // depth 3 belongs under the depth-3 one, or its edge points up.
      layer.set(c, Math.max(layer.get(c) ?? 0, at + 1));
      const left = indegree.get(c)! - 1;
      indegree.set(c, left);
      if (left === 0) queue.push(c);
    }
  }

  // Anything Kahn left unsettled is in a cycle. Place it below whatever
  // parent did settle, in input order so the result stays deterministic.
  for (const id of order.keys()) {
    if (layer.has(id)) continue;
    let deepest = -1;
    for (const p of parents.get(id)!) {
      const pl = layer.get(p);
      if (pl !== undefined) deepest = Math.max(deepest, pl);
    }
    layer.set(id, deepest + 1);
  }

  let depth = 0;
  for (const l of layer.values()) depth = Math.max(depth, l);
  const layers: string[][] = Array.from({ length: depth + 1 }, () => []);
  for (const id of order.keys()) layers[layer.get(id)!].push(id);
  return layers;
}

// DAG_STATE_STYLES is the one place a node state's urgency and its
// colour are decided, MOST URGENT FIRST.
//
// The order is the answer to "where is my workflow stuck", which is the
// question the panel exists for. A group holding one failed node among
// ninety-nine done ones is a red box, because the ninety-nine are not
// what the reader came to find; `done` sorts last for the same reason.
//
// Colours are the app's own job-status tokens (statusPillCls) rather
// than a palette of this panel's, so red here means what red means in
// the status pill at the top of the page. DAGMan has states JobStatus
// does not -- failed, futile, ready, unready, prerun/postrun -- so this
// is a superset, and those borrow the nearest token deliberately.
//
// `shape` is the SVG twin of `pill`: Tailwind's bg-/text- utilities do
// nothing to a <rect>, so a drawn box needs fill-/stroke- equivalents
// of the same colours.
const DAG_STATE_STYLES: readonly {
  state: string;
  pill: string;
  shape: string;
}[] = [
  // Stopped, and not on purpose. These two are why anyone opens this.
  { state: 'failed', pill: statusPillCls('held'), shape: 'fill-red-100 stroke-red-400' },
  { state: 'held', pill: statusPillCls('held'), shape: 'fill-red-100 stroke-red-400' },
  // Futile: an ancestor failed, so this node can never run. Not itself
  // broken, but it is the blast radius of the thing that is.
  { state: 'futile', pill: 'bg-orange-100 text-orange-800', shape: 'fill-orange-100 stroke-orange-400' },
  { state: 'removed', pill: statusPillCls('removed'), shape: 'fill-amber-100 stroke-amber-400' },
  { state: 'suspended', pill: statusPillCls('suspended'), shape: 'fill-amber-100 stroke-amber-400' },
  { state: 'running', pill: statusPillCls('running'), shape: 'fill-green-100 stroke-green-500' },
  // PRE and POST scripts run on the access point, not in the pool; they
  // are progress, so they share the "in flight" amber.
  { state: 'prerun', pill: statusPillCls('transferring'), shape: 'fill-amber-100 stroke-amber-400' },
  { state: 'postrun', pill: statusPillCls('transferring'), shape: 'fill-amber-100 stroke-amber-400' },
  { state: 'transferring', pill: statusPillCls('transferring'), shape: 'fill-amber-100 stroke-amber-400' },
  { state: 'submitted', pill: statusPillCls('idle'), shape: 'fill-blue-100 stroke-blue-400' },
  { state: 'idle', pill: statusPillCls('idle'), shape: 'fill-blue-100 stroke-blue-400' },
  { state: 'ready', pill: statusPillCls('idle'), shape: 'fill-blue-50 stroke-blue-300' },
  { state: 'unready', pill: statusPillCls('unknown'), shape: 'fill-white stroke-gray-300' },
  { state: 'done', pill: statusPillCls('completed'), shape: 'fill-gray-200 stroke-gray-400' },
];

const DAG_STATE_INDEX = new Map(DAG_STATE_STYLES.map((s, i) => [s.state, i]));

// dagStateRank orders node states by urgency, lowest number first.
//
// An unrecognised state ranks LAST -- below `done`. A state name this
// UI has not seen is not evidence of trouble, and ranking the unknown
// above `failed` would let a server-side rename silently recolour every
// group in every workflow red.
export function dagStateRank(state: string): number {
  const i = DAG_STATE_INDEX.get(state);
  return i === undefined ? DAG_STATE_STYLES.length : i;
}

// dagStatePill / dagStateShape: the badge and the drawn-box classes for
// a node state. Unknown states fall back to the app's "unknown" grey
// rather than to nothing, so an unrecognised state still renders.
export function dagStatePill(state: string): string {
  const i = DAG_STATE_INDEX.get(state);
  return i === undefined ? statusPillCls('unknown') : DAG_STATE_STYLES[i].pill;
}

export function dagStateShape(state: string): string {
  const i = DAG_STATE_INDEX.get(state);
  return i === undefined ? 'fill-gray-100 stroke-gray-400' : DAG_STATE_STYLES[i].shape;
}

// dagStatusEntries turns a group's histogram into a most-urgent-first
// list. Zero counts are dropped -- a server that emits every state with
// a count would otherwise fill the box with "0 held, 0 failed" -- and
// ties break on the name so the row is stable.
export function dagStatusEntries(
  status: Record<string, number> | null | undefined,
): { state: string; count: number }[] {
  return Object.entries(status ?? {})
    .filter(([, n]) => typeof n === 'number' && n > 0)
    .map(([state, count]) => ({ state, count }))
    .sort(
      (a, b) =>
        dagStateRank(a.state) - dagStateRank(b.state) ||
        a.state.localeCompare(b.state),
    );
}

// dominantDagState is the state a group's box is coloured by: the most
// URGENT state present, not the most numerous. One failed node among a
// thousand done ones is the fact the picture has to carry; averaging it
// away would make the panel answer a question nobody asked.
export function dominantDagState(
  status: Record<string, number> | null | undefined,
): string | undefined {
  return dagStatusEntries(status)[0]?.state;
}

// DagGraphPanel is the panel: explicit load, one Refresh button, no timer
// (see the block comment above for why). batchHref, when given, links the
// heading row to the workflow's batch page -- for the DAGMan job's own
// page, not for the batch page itself.
export function DagGraphPanel({
  jobId,
  schedd,
  batchHref,
}: {
  jobId: string;
  schedd?: string;
  batchHref?: string;
}) {
  const id = schedd && !jobId.includes('@') ? `${jobId}@${schedd}` : jobId;
  const [data, setData] = useState<DagGraphResponse | null>(null);
  // notice vs error: a 409 is the server telling us this workflow has
  // nothing to show and why, in a sentence already written for a human.
  // It is prose, not a failure.
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [selected, setSelected] = useState<string | null>(null);

  const load = useCallback(
    (refresh: boolean) => {
      setLoading(true);
      setError(null);
      setNotice(null);
      api.jobs
        .dagGraph(id, refresh ? { refresh: true } : undefined)
        .then((res) => {
          setData(res);
          // Keep the open group open across a refresh, but only if it
          // still exists -- a vanished group would leave the detail box
          // showing an empty member list with no explanation.
          setSelected((prev) =>
            prev && (res.groups ?? []).some((g) => g.id === prev) ? prev : null,
          );
        })
        .catch((e: unknown) => {
          if (e instanceof ApiError && e.status === 409) {
            setNotice(e.message);
            setData(null);
            setSelected(null);
            return;
          }
          setError(e instanceof Error ? e.message : String(e));
        })
        .finally(() => setLoading(false));
    },
    [id],
  );

  const loaded = data !== null || notice !== null;
  return (
    // The test id is load-bearing: a smoke test asserts that NOTHING in
    // this panel explains how the server works, and "the innermost div
    // holding the heading" is the button row, not the panel.
    <div
      data-testid="workflow-graph-panel"
      className="rounded-sm border border-gray-200 bg-white p-4 space-y-3"
    >
      <div className="flex items-center justify-between gap-3">
        <h2 className="text-sm font-medium text-gray-900">Workflow graph</h2>
        <div className="flex items-center gap-3">
          {batchHref && (
            <Link href={batchHref} className="text-xs text-brand-700 hover:underline">
              Open batch page
            </Link>
          )}
          <button
            type="button"
            onClick={() => load(loaded)}
            disabled={loading}
            // A hint, not body text: the panel is explicit-load, and the
            // only thing worth saying about Refresh is that it is the
            // slow one.
            title={loaded ? 'Re-read this workflow (slow)' : undefined}
            className="rounded-sm border border-gray-300 bg-white px-3 py-1.5 text-xs font-medium text-gray-700 hover:bg-gray-50 disabled:opacity-50"
          >
            {loading
              ? loaded
                ? 'Refreshing…'
                : 'Loading…'
              : loaded
                ? 'Refresh'
                : 'Load graph'}
          </button>
        </div>
      </div>

      <p className="text-xs text-gray-500">
        The workflow&apos;s structure, with nodes that run the same thing
        in the same place drawn as one box.
      </p>

      {error && (
        <div className="rounded-sm border border-red-200 bg-red-50 p-3 text-xs text-red-700">
          Could not load the workflow graph: {error}
        </div>
      )}
      {notice && <p className="text-xs text-gray-600">{notice}</p>}
      {loading && !data && <p className="text-xs text-gray-500">Loading…</p>}

      {data && (
        <WorkflowGraphBody
          data={data}
          selected={selected}
          onSelect={setSelected}
          onRefresh={() => load(true)}
          refreshing={loading}
        />
      )}
    </div>
  );
}

// WorkflowGraphBody is everything below the Load button once there is a
// response: the honesty banners, the drawing, the caveat the drawing
// cannot state for itself, and the per-group detail.
function WorkflowGraphBody({
  data,
  selected,
  onSelect,
  onRefresh,
  refreshing,
}: {
  data: DagGraphResponse;
  selected: string | null;
  onSelect: (id: string | null) => void;
  onRefresh: () => void;
  refreshing: boolean;
}) {
  const groups = useMemo(() => data.groups ?? [], [data]);
  const layers = useMemo(() => dagLayers(groups), [groups]);
  const widest = layers.reduce((m, l) => Math.max(m, l.length), 0);
  const drawable =
    groups.length > 0 &&
    groups.length <= DAG_MAX_GROUPS &&
    widest <= DAG_MAX_LAYER;
  const open = selected ? groups.find((g) => g.id === selected) : undefined;

  return (
    <div className="space-y-3">
      <DagBanners data={data} onRefresh={onRefresh} refreshing={refreshing} />

      <p className="text-xs text-gray-500">
        <span className="tabular-nums">{data.node_count.toLocaleString()}</span>{' '}
        nodes and{' '}
        <span className="tabular-nums">{data.edge_count.toLocaleString()}</span>{' '}
        dependencies, collapsed into{' '}
        <span className="tabular-nums">{groups.length.toLocaleString()}</span>{' '}
        groups
        {/* link_count is one of the fields not every server version
            copies into the response; show it only when it is there. */}
        {data.link_count !== undefined && (
          <>
            {' '}
            joined by{' '}
            <span className="tabular-nums">
              {data.link_count.toLocaleString()}
            </span>{' '}
            links
          </>
        )}
        .
      </p>

      {groups.length === 0 ? (
        <p className="text-xs text-gray-600">
          This workflow has no nodes to draw.
        </p>
      ) : drawable ? (
        <DagDrawing
          groups={groups}
          layers={layers}
          selected={selected}
          onSelect={onSelect}
        />
      ) : (
        <DagTooWide groups={groups} widest={widest} />
      )}

      {/* The one piece of explanation that earns its place: it is how to
          READ the drawing, not how the server made it. A reader who takes
          a group link for "every node in A feeds every node in B" will
          misread a fan-out of independent chains as a synchronisation
          point, which is the opposite of what it is. One sentence. */}
      <p className="rounded-sm border border-gray-200 bg-gray-50 px-3 py-2 text-xs text-gray-600">
        <strong className="font-medium text-gray-800">
          A line means &ldquo;some&rdquo;, not &ldquo;every&rdquo;.
        </strong>{' '}
        An arrow says that <em>some</em> node in the first is a parent of{' '}
        <em>some</em> node in the second.
      </p>

      {groups.length > 0 && !drawable && (
        <DagGroupList groups={groups} selected={selected} onSelect={onSelect} />
      )}

      {open && <DagGroupDetail data={data} group={open} />}

      <DagProvenance data={data} />
    </div>
  );
}

// DagNote is the shared shell for the banners below. amber for "this
// picture may be wrong", grey for "here is where it came from".
function DagNote({
  tone = 'amber',
  children,
}: {
  tone?: 'amber' | 'gray';
  children: React.ReactNode;
}) {
  const cls =
    tone === 'amber'
      ? 'border-amber-200 bg-amber-50 text-amber-900'
      : 'border-gray-200 bg-gray-50 text-gray-600';
  return (
    <div className={`rounded-sm border px-3 py-2 text-xs ${cls}`}>{children}</div>
  );
}

// DagBanners renders, for each way this picture can be wrong, a
// sentence saying so -- and nothing at all when the field is absent.
//
// Absent matters: truncated / incomplete / dangling_edges are defined by
// dagman.Grouping but not copied into the HTTP response by every server
// version, so `undefined` here means "this server does not say", NOT
// "no". Rendering a reassuring "not truncated" would be a claim the
// response never made.
function DagBanners({
  data,
  onRefresh,
  refreshing,
}: {
  data: DagGraphResponse;
  onRefresh: () => void;
  refreshing: boolean;
}) {
  const dangling = data.dangling_edges ?? 0;
  return (
    <>
      {data.truncated && (
        <DagNote>
          This drawing may be missing dependencies.{' '}
          <button
            type="button"
            onClick={onRefresh}
            disabled={refreshing}
            className="underline underline-offset-2 disabled:opacity-50"
          >
            {refreshing ? 'Refreshing…' : 'Refresh to re-read it'}
          </button>
          .
        </DagNote>
      )}

      {data.incomplete && (
        <DagNote>Part of this workflow is missing from this drawing.</DagNote>
      )}

      {dangling > 0 && (
        <DagNote>
          <span className="tabular-nums">{dangling.toLocaleString()}</span>{' '}
          {dangling === 1 ? 'dependency is' : 'dependencies are'} missing from
          this drawing.
        </DagNote>
      )}

      {data.approximate_layering && (
        <DagNote>
          This grouping is coarser than the workflow&apos;s real structure, so
          boxes may sit at a depth the dependencies do not justify.
          {data.approximate_reason === 'cycle' && (
            <> This workflow has a cycle.</>
          )}
          {data.approximate_reason === 'refinement-bound' && (
            <> Distinct nodes are sharing a box.</>
          )}
        </DagNote>
      )}

      {(data.warnings ?? []).map((w, i) => (
        // Verbatim: these say what could NOT be consulted, and a missing
        // archive has to read as "not available" rather than as "nothing
        // ran". Paraphrasing is how that flips.
        <DagNote key={i}>{w}</DagNote>
      ))}
    </>
  );
}

// dagStateAsOf is the unix time the state in this response is good as
// of: the older of when the workflow's spool was read and when DAGMan
// last wrote its node states, because the answer is only as fresh as
// whichever of those is further behind.
//
// An unparseable or absent fetched_at falls back to the status file's
// own time, and a response carrying neither returns 0, which the caller
// renders as nothing rather than as 1970.
export function dagStateAsOf(data: {
  fetched_at?: string;
  status_file_time?: number;
}): number {
  const parsed = data.fetched_at ? Date.parse(data.fetched_at) : NaN;
  const fetched = Number.isFinite(parsed) ? Math.floor(parsed / 1000) : 0;
  const status =
    typeof data.status_file_time === 'number' && data.status_file_time > 0
      ? data.status_file_time
      : 0;
  if (fetched && status) return Math.min(fetched, status);
  return fetched || status;
}

// formatTookMs renders a server-reported duration the way a reader reads
// one: sub-second in milliseconds, past that in seconds with one
// decimal. It is the number the panel shows beside the state's age.
export function formatTookMs(ms: number): string {
  if (!Number.isFinite(ms) || ms < 0) return '';
  return ms < 1000 ? `${Math.round(ms)}ms` : `${(ms / 1000).toFixed(1)}s`;
}

// DagProvenance is one line: how old the state is, and how long the load
// took.
//
// It used to be three paragraphs naming the .dot and .status files, the
// spool, the queue and DAGMan's write cycle. None of that is a fact
// about the reader's workflow -- it is a description of this server --
// and the project owner asked for it gone. What a reader needs is
// whether they are looking at something current, which is the age, and
// whether the panel is slow, which is the duration.
function DagProvenance({ data }: { data: DagGraphResponse }) {
  // The same minute-resolution clock the rest of the page ages its
  // timestamps against: the age has to keep growing while the panel sits
  // open, which a value frozen at render would not.
  const now = useNowTick(60_000);
  const at = dagStateAsOf(data);
  const took =
    typeof data.took_ms === 'number' ? formatTookMs(data.took_ms) : '';
  if (!at && !took) return null;
  return (
    <p className="text-xs text-gray-500">
      {at > 0 && (
        <>
          State as of {new Date(at * 1000).toLocaleTimeString()} (
          {humanDuration(Math.max(0, now - at))} ago)
        </>
      )}
      {at > 0 && took && ' · '}
      {took && <>loaded in {took}</>}
    </p>
  );
}

// truncateLabel keeps a label inside its box. The full text is in the
// box's <title> and in the detail panel, so nothing is lost -- only
// shortened.
function truncateLabel(s: string, max: number): string {
  return s.length <= max ? s : `${s.slice(0, max - 1)}…`;
}

// dagStatusSummary renders a histogram as "9 done · 1 failed", most
// urgent first.
function dagStatusSummary(
  status: Record<string, number> | null | undefined,
): string {
  return dagStatusEntries(status)
    .map((e) => `${e.count} ${e.state}`)
    .join(' · ');
}

// DagDrawing is the layered picture: one row per layer, one box per
// group, one line per parent_ids entry.
//
// It deliberately does NOT try to be a layout engine -- no crossing
// minimisation, no edge routing, no port assignment. Groups sit in
// first-appearance order within their row and edges are drawn straight
// through. On the graphs this endpoint produces (small by construction,
// which is the whole point of collapsing) that reads fine; on one where
// it would not, DagTooWide takes over rather than this degrading.
//
// The SVG is drawn at its natural size inside a scrolling box. Scaling
// it to fit would shrink an 11px label to unreadable exactly on the
// wide graphs that most need reading.
function DagDrawing({
  groups,
  layers,
  selected,
  onSelect,
}: {
  groups: DagGraphGroup[];
  layers: string[][];
  selected: string | null;
  onSelect: (id: string | null) => void;
}) {
  const widest = layers.reduce((m, l) => Math.max(m, l.length), 0);
  const contentW = widest * (DAG_BOX_W + DAG_H_GAP) - DAG_H_GAP;
  const width = contentW + DAG_PAD * 2;
  const height =
    layers.length * (DAG_BOX_H + DAG_V_GAP) - DAG_V_GAP + DAG_PAD * 2;

  const pos = new Map<string, { x: number; y: number }>();
  layers.forEach((ids, li) => {
    const rowW = ids.length * (DAG_BOX_W + DAG_H_GAP) - DAG_H_GAP;
    const x0 = DAG_PAD + (contentW - rowW) / 2;
    ids.forEach((id, i) => {
      pos.set(id, {
        x: x0 + i * (DAG_BOX_W + DAG_H_GAP),
        y: DAG_PAD + li * (DAG_BOX_H + DAG_V_GAP),
      });
    });
  });

  return (
    <div
      className="overflow-auto rounded-sm border border-gray-200 bg-white"
      style={{ maxHeight: 520 }}
    >
      <svg
        width={width}
        height={height}
        viewBox={`0 0 ${width} ${height}`}
        role="img"
        aria-label={`Workflow graph: ${groups.length} groups in ${layers.length} layers`}
        className="block"
      >
        <defs>
          <marker
            id="dag-arrow"
            viewBox="0 0 8 8"
            refX="7"
            refY="4"
            markerWidth="7"
            markerHeight="7"
            orient="auto-start-reverse"
          >
            <path d="M0,1 L7,4 L0,7 z" className="fill-gray-400" />
          </marker>
        </defs>

        {groups.flatMap((g) =>
          (g.parent_ids ?? []).map((p) => {
            const from = pos.get(p);
            const to = pos.get(g.id);
            // A dangling or self parent has no box to start from; the
            // banner above already counts those.
            if (!from || !to || p === g.id) return null;
            const x1 = from.x + DAG_BOX_W / 2;
            const y1 = from.y + DAG_BOX_H;
            const x2 = to.x + DAG_BOX_W / 2;
            const y2 = to.y;
            // Bow the curve out far enough that a line between adjacent
            // rows still reads as a direction. Clamped, because a cycle
            // can put the child ABOVE the parent.
            const dy = Math.max(18, (y2 - y1) / 2);
            return (
              <path
                key={`${p}->${g.id}`}
                d={`M${x1},${y1} C${x1},${y1 + dy} ${x2},${y2 - dy} ${x2},${y2}`}
                className="fill-none stroke-gray-400"
                strokeWidth={1.25}
                markerEnd="url(#dag-arrow)"
              />
            );
          }),
        )}

        {groups.map((g) => {
          const p = pos.get(g.id);
          if (!p) return null;
          const entries = dagStatusEntries(g.status);
          const dominant = entries[0]?.state;
          const total = entries.reduce((s, e) => s + e.count, 0);
          const summary = dagStatusSummary(g.status);
          const isSelected = selected === g.id;
          const toggle = () => onSelect(isSelected ? null : g.id);
          let barX = p.x + 10;
          let barLeft = DAG_BOX_W - 20;
          return (
            <g
              key={g.id}
              data-group-id={g.id}
              role="button"
              tabIndex={0}
              aria-pressed={isSelected}
              aria-label={`${g.label}${g.count > 1 ? `, ${g.count} nodes` : ''}${summary ? `: ${summary}` : ''}`}
              className="cursor-pointer"
              onClick={toggle}
              onKeyDown={(e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                  e.preventDefault();
                  toggle();
                }
              }}
            >
              <title>
                {g.label}
                {g.count > 1 ? ` (${g.count} nodes)` : ''}
                {g.description ? ` — ${g.description}` : ''}
                {summary ? `\n${summary}` : ''}
              </title>
              <rect
                x={p.x}
                y={p.y}
                width={DAG_BOX_W}
                height={DAG_BOX_H}
                rx={4}
                strokeWidth={isSelected ? 2.5 : 1}
                className={
                  dominant ? dagStateShape(dominant) : 'fill-white stroke-gray-300'
                }
              />
              <text
                x={p.x + 10}
                y={p.y + 19}
                className="fill-gray-900 text-[11px] font-medium"
              >
                {truncateLabel(g.label, 20)}
              </text>
              {g.count > 1 && (
                <text
                  x={p.x + DAG_BOX_W - 10}
                  y={p.y + 19}
                  textAnchor="end"
                  className="fill-gray-600 text-[11px] tabular-nums"
                >
                  ×{g.count}
                </text>
              )}
              <text
                x={p.x + 10}
                y={p.y + 34}
                className="fill-gray-600 text-[10px]"
              >
                {truncateLabel(summary, 28)}
              </text>
              {total > 0 &&
                entries.map((e) => {
                  // Clamp each slice to a visible minimum so a single
                  // failed node among a thousand does not round away,
                  // and to whatever width is left so the clamping
                  // cannot push the bar out of its box.
                  const w = Math.min(
                    barLeft,
                    Math.max(2, (e.count / total) * (DAG_BOX_W - 20)),
                  );
                  const x = barX;
                  barX += w;
                  barLeft -= w;
                  if (w <= 0) return null;
                  return (
                    <rect
                      key={e.state}
                      x={x}
                      y={p.y + 42}
                      width={w}
                      height={5}
                      rx={1}
                      strokeWidth={0.5}
                      className={dagStateShape(e.state)}
                    />
                  );
                })}
            </g>
          );
        })}
      </svg>
    </div>
  );
}

// DagTooWide is what happens instead of a drawing nobody could read.
// Saying "too wide" and handing over the list is more useful than a
// picture scaled until its labels are grey smears -- and a general
// layout that would fix it is a graph library, which this panel
// deliberately is not.
function DagTooWide({
  groups,
  widest,
}: {
  groups: DagGraphGroup[];
  widest: number;
}) {
  return (
    <DagNote>
      This workflow collapsed to{' '}
      <span className="tabular-nums">{groups.length.toLocaleString()}</span>{' '}
      groups, {widest > DAG_MAX_LAYER ? 'with ' : ''}
      {widest > DAG_MAX_LAYER && (
        <>
          <span className="tabular-nums">{widest.toLocaleString()}</span> of them
          side by side in one layer,{' '}
        </>
      )}
      which is wider than a readable drawing. The group list is below
      instead.
    </DagNote>
  );
}

// DagGroupList is the drawing's fallback: the same groups, same colours,
// same click target, no geometry.
function DagGroupList({
  groups,
  selected,
  onSelect,
}: {
  groups: DagGraphGroup[];
  selected: string | null;
  onSelect: (id: string | null) => void;
}) {
  return (
    <ul className="max-h-96 space-y-1 overflow-auto rounded-sm border border-gray-200 bg-white p-2">
      {groups.map((g) => {
        const dominant = dominantDagState(g.status);
        const isSelected = selected === g.id;
        return (
          <li key={g.id}>
            <button
              type="button"
              onClick={() => onSelect(isSelected ? null : g.id)}
              className={`flex w-full items-center gap-2 rounded-sm px-2 py-1 text-left text-xs hover:bg-gray-50 ${
                isSelected ? 'bg-gray-100' : ''
              }`}
            >
              <span
                className={`inline-flex rounded-full px-2 py-0.5 text-[10px] font-medium ${dagStatePill(dominant ?? 'unready')}`}
              >
                {dominant ?? '—'}
              </span>
              <span className="font-mono text-gray-900">{g.label}</span>
              {g.count > 1 && (
                <span className="tabular-nums text-gray-500">×{g.count}</span>
              )}
              <span className="ml-auto text-gray-500">
                {dagStatusSummary(g.status)}
              </span>
            </button>
          </li>
        );
      })}
    </ul>
  );
}

// How many members to list before we stop. The server already caps what
// it sends (nodes_omitted / nodes_omitted_reason); this is the second
// cap, for a group that is under the server's limit but still far past
// what anyone scrolls.
const DAG_MAX_MEMBERS_SHOWN = 300;

// DagGroupDetail shows what a group actually contains. This is where
// the some-to-some collapse is undone: the box says "10 nodes, 1
// failed", and the answer to "which one" is only here.
function DagGroupDetail({
  data,
  group,
}: {
  data: DagGraphResponse;
  group: DagGraphGroup;
}) {
  const members = useMemo(
    () =>
      (data.nodes ?? [])
        .filter((n) => n.group_id === group.id)
        .sort(
          (a, b) =>
            dagStateRank(a.state) - dagStateRank(b.state) ||
            a.name.localeCompare(b.name),
        ),
    [data, group.id],
  );
  const shown = members.slice(0, DAG_MAX_MEMBERS_SHOWN);

  return (
    <div className="space-y-2 rounded-sm border border-gray-300 bg-gray-50 p-3">
      <div className="flex flex-wrap items-center gap-2">
        <h3 className="font-mono text-sm font-medium text-gray-900">
          {group.label}
        </h3>
        {group.count > 1 && (
          <span className="tabular-nums text-xs text-gray-500">
            {group.count.toLocaleString()} nodes
          </span>
        )}
        <span className="ml-auto flex flex-wrap gap-1">
          {dagStatusEntries(group.status).map((e) => (
            <span
              key={e.state}
              className={`inline-flex rounded-full px-2 py-0.5 text-[10px] font-medium ${dagStatePill(e.state)}`}
            >
              {e.count} {e.state}
            </span>
          ))}
        </span>
      </div>

      {group.description && (
        <p className="font-mono text-xs break-all text-gray-600">
          {group.description}
        </p>
      )}

      {data.nodes_omitted ? (
        // The server dropped the per-node overlay for size. Say its
        // reason rather than rendering an empty list, which would read
        // as "this group has no members".
        <p className="text-xs text-gray-600">
          {data.nodes_omitted_reason ??
            'This workflow is too large to list node by node.'}
        </p>
      ) : members.length === 0 ? (
        <p className="text-xs text-gray-600">
          No individual nodes are listed for this group.
        </p>
      ) : (
        <>
          <ul className="max-h-96 space-y-1 overflow-auto">
            {shown.map((n) => (
              <li
                key={n.name}
                className="space-y-1 rounded-sm border border-gray-200 bg-white p-2 text-xs"
              >
                <div className="flex flex-wrap items-center gap-2">
                  <span
                    className={`inline-flex rounded-full px-2 py-0.5 text-[10px] font-medium ${dagStatePill(n.state)}`}
                  >
                    {n.state}
                  </span>
                  <span className="font-mono break-all text-gray-900">
                    {n.name}
                  </span>
                  {n.job_id && (
                    <Link
                      href={`/jobs/${n.job_id}`}
                      className="text-brand-700 hover:underline"
                    >
                      job {n.job_id}
                    </Link>
                  )}
                  {n.exit_code !== undefined && (
                    <span className="tabular-nums text-gray-600">
                      exit {n.exit_code}
                    </span>
                  )}
                </div>
                {n.detail && <p className="text-gray-600">{n.detail}</p>}
                {n.hold_reason && (
                  <p className="text-red-700">{n.hold_reason}</p>
                )}
              </li>
            ))}
          </ul>
          {members.length > shown.length && (
            <p className="text-xs text-gray-500">
              Showing{' '}
              <span className="tabular-nums">{shown.length.toLocaleString()}</span>{' '}
              of{' '}
              <span className="tabular-nums">
                {members.length.toLocaleString()}
              </span>{' '}
              members.
            </p>
          )}
        </>
      )}

      <DagNodeConstraint cluster={data.cluster} />
    </div>
  );
}

// DagNodeConstraint hands over the ClassAd constraint that finds the
// workflow's node jobs in the queue. It is the answer to "where are
// these in the jobs list", and it is not guessable: DAGMan stamps
// DAGManJobId on every node job it submits, and nothing on this page
// spells that attribute out otherwise.
function DagNodeConstraint({ cluster }: { cluster: number }) {
  const constraint = `DAGManJobId == ${cluster}`;
  const [copied, setCopied] = useState(false);
  return (
    <div className="flex flex-wrap items-center gap-2 border-t border-gray-200 pt-2 text-xs">
      <span className="text-gray-500">Node jobs in the queue:</span>
      <code className="rounded-sm border border-gray-300 bg-white px-2 py-0.5 font-mono text-gray-800">
        {constraint}
      </code>
      <button
        type="button"
        onClick={() => {
          navigator.clipboard?.writeText(constraint);
          setCopied(true);
          setTimeout(() => setCopied(false), 2000);
        }}
        className="rounded-sm border border-gray-300 bg-white px-2 py-0.5 text-gray-700 hover:bg-gray-50"
      >
        {copied ? 'Copied' : 'Copy'}
      </button>
      <Link
        href={`/jobs?constraint=${encodeURIComponent(constraint)}`}
        className="text-brand-700 hover:underline"
      >
        Open in jobs
      </Link>
    </div>
  );
}
