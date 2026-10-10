'use client';

// The Utilization page's charts. Inline SVG with no chart dependency, the
// same approach as MetricChart and Sparkline: each one draws into a fixed
// viewBox and scales with its container, so a chart is as wide as its
// card at any screen width.
//
// Every chart has its figures somewhere other than the hover tooltip --
// direct labels for the few numbers the chart is about, and a table view
// for the rest -- because a tooltip is unreachable from a keyboard and
// from a screen reader.

import { useId, useMemo, useState, type PointerEvent, type ReactNode } from 'react';
import {
  formatMiB,
  formatNumber,
  formatPercent,
  stripGeometry,
  type UtilBatchPoint,
  type UtilDistribution,
  type UtilMemoryCurvePoint,
  type UtilRequest,
  type UtilSample,
} from '@/lib/utilization';
import { formatSeconds } from '@/lib/usage';

// Colours. The data hues are the dataviz palette's, the same ones the job
// page's metric charts use (lib/metrics.ts RUN_COLORS), validated for
// colour-blind separation as the sets each chart actually puts side by
// side. References -- what was requested, what to request -- are not data
// and use ink and the brand colour, always with a text label.
export const UTIL_COLOR = {
  used: '#2a78d6', // palette blue: what jobs used
  usedSoft: '#86b6ef', // blue 250: the middle half of jobs on a range strip
  track: '#cde2fb', // blue 100: reserved but unused, the meter's track
  request: '#5d5d5d', // ink-600: the current request
  recommended: '#b61f24', // brand-600: the suggested request
  retry: '#eda100', // palette yellow: jobs that would rerun
  retryLine: '#c98500', // a step darker so the line shows over its own bars
  over: '#d03b3b', // status critical: a job above its request
  grid: '#e7e7e7', // ink-100
  axis: '#888888', // ink-400
  failed: '#4a3aa7', // palette violet
  memoryExceeded: '#eb6834', // palette orange
  removed: '#b0b0b0', // ink-300
} as const;

// --- Shared chart plumbing ---

interface TipRow {
  label: string;
  value: string;
  color?: string;
}

interface Tip {
  x: number; // viewBox coordinates
  y: number;
  title: string;
  rows: TipRow[];
}

/**
 * ChartFrame is the card every chart sits in: a title, the plot with its
 * tooltip layer, an optional legend and note, and the table view.
 */
function ChartFrame({
  title,
  subtitle,
  width,
  height,
  tip,
  children,
  legend,
  note,
  table,
}: {
  title: string;
  subtitle?: ReactNode;
  width: number;
  height: number;
  tip: Tip | null;
  children: ReactNode;
  legend?: ReactNode;
  note?: ReactNode;
  table?: ReactNode;
}) {
  return (
    <figure className="min-w-0 rounded-lg border border-gray-200 bg-white p-3">
      <figcaption className="mb-2">
        <div className="text-sm font-semibold text-gray-900">{title}</div>
        {subtitle && <div className="text-xs text-gray-500">{subtitle}</div>}
      </figcaption>
      <div className="relative">
        {children}
        {tip && <Tooltip tip={tip} width={width} height={height} />}
      </div>
      {legend && <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs text-gray-600">{legend}</div>}
      {note && <p className="mt-1 text-xs text-gray-500">{note}</p>}
      {table && (
        <details className="mt-2 text-xs text-gray-600">
          <summary className="cursor-pointer select-none text-gray-500 hover:text-gray-800">
            Show as table
          </summary>
          <div className="mt-1 max-h-64 overflow-auto">{table}</div>
        </details>
      )}
    </figure>
  );
}

function Tooltip({ tip, width, height }: { tip: Tip; width: number; height: number }) {
  // Positioned in percentages of the viewBox, which is the same as
  // percentages of the rendered plot because the SVG keeps its aspect
  // ratio. Near either edge the box hangs inward so it is never clipped.
  const fx = tip.x / width;
  const shift = fx > 0.7 ? '-100%' : fx < 0.3 ? '0%' : '-50%';
  return (
    <div
      role="status"
      className="pointer-events-none absolute z-10 min-w-32 rounded-md border border-gray-200 bg-white px-2.5 py-1.5 text-xs shadow-md"
      style={{
        left: `${fx * 100}%`,
        top: `${(tip.y / height) * 100}%`,
        transform: `translate(${shift}, calc(-100% - 10px))`,
      }}
    >
      <div className="mb-0.5 text-gray-500">{tip.title}</div>
      {tip.rows.map((r) => (
        <div key={r.label} className="flex items-center gap-1.5 whitespace-nowrap">
          {r.color && (
            <span aria-hidden className="inline-block h-0.5 w-3 rounded" style={{ backgroundColor: r.color }} />
          )}
          <span className="font-semibold tabular-nums text-gray-900">{r.value}</span>
          <span className="text-gray-500">{r.label}</span>
        </div>
      ))}
    </div>
  );
}

// LegendKey is a legend entry: a mark beside ink-coloured text. The mark
// mirrors the chart's (a bar is a block, a line is a stroke).
export function LegendKey({
  color,
  shape = 'block',
  children,
  dashed,
}: {
  color: string;
  shape?: 'block' | 'line' | 'dot' | 'triangle' | 'square' | 'ring';
  children: ReactNode;
  dashed?: boolean;
}) {
  let mark: ReactNode;
  switch (shape) {
    case 'line':
      mark = (
        <svg width="16" height="8" aria-hidden>
          <line x1="1" x2="15" y1="4" y2="4" stroke={color} strokeWidth="2" strokeDasharray={dashed ? '3 2' : undefined} />
        </svg>
      );
      break;
    case 'dot':
    case 'ring':
    case 'triangle':
    case 'square':
      mark = (
        <svg width="10" height="10" aria-hidden>
          <Glyph shape={shape} cx={5} cy={5} r={4} color={color} />
        </svg>
      );
      break;
    default:
      mark = <span aria-hidden className="inline-block h-2.5 w-2.5 rounded-sm" style={{ backgroundColor: color }} />;
  }
  return (
    <span className="inline-flex items-center gap-1.5">
      {mark}
      {children}
    </span>
  );
}

function Glyph({
  shape,
  cx,
  cy,
  r,
  color,
  ring,
}: {
  shape: 'dot' | 'ring' | 'triangle' | 'square';
  cx: number;
  cy: number;
  r: number;
  color: string;
  ring?: boolean;
}) {
  const stroke = ring ? { stroke: '#ffffff', strokeWidth: 1 } : {};
  switch (shape) {
    case 'triangle': {
      const h = r * 1.9;
      return (
        <path
          d={`M${cx},${cy - h / 2 - 0.5} L${cx + r},${cy + h / 2 - 0.5} L${cx - r},${cy + h / 2 - 0.5} Z`}
          fill={color}
          {...stroke}
        />
      );
    }
    case 'square':
      return <rect x={cx - r * 0.85} y={cy - r * 0.85} width={r * 1.7} height={r * 1.7} rx={1} fill={color} {...stroke} />;
    case 'ring':
      return <circle cx={cx} cy={cy} r={r - 0.75} fill="none" stroke={color} strokeWidth={1.5} />;
    default:
      return <circle cx={cx} cy={cy} r={r} fill={color} {...stroke} />;
  }
}

// --- Scales ---

export type AxisUnit = 'mib' | 'kib' | 'plain' | 'hours' | 'minutes' | 'fraction';

/**
 * niceTicks picks round axis ticks from zero to at least `max`. Memory and
 * disk are ticked in whole GB once they reach a GB, so the axis reads
 * "2 GB, 4 GB" rather than "2,000 MB, 4,000 MB".
 */
export function niceTicks(max: number, unit: AxisUnit, count = 4): number[] {
  let scale = 1;
  if (unit === 'mib' && max >= 1024) scale = 1024;
  if (unit === 'kib') scale = max >= 1024 * 1024 ? 1024 * 1024 : 1024;
  const m = max / scale;
  if (!(m > 0)) return [0, scale];
  // A share of something tops out at all of it.
  if (unit === 'fraction' && m <= 1.05) return [0, 0.25, 0.5, 0.75, 1];
  const raw = m / count;
  const mag = Math.pow(10, Math.floor(Math.log10(raw)));
  const n = raw / mag;
  const step = (n <= 1 ? 1 : n <= 2 ? 2 : n <= 2.5 ? 2.5 : n <= 5 ? 5 : 10) * mag;
  const top = Math.ceil(m / step - 1e-9) * step;
  const out: number[] = [];
  for (let v = 0; v <= top + step / 2; v += step) out.push(v * scale);
  return out;
}

// axisNumber renders a tick value exactly enough to tell neighbours
// apart: a 2.5 GB step must not round to "3 GB", and zero is just "0".
function axisNumber(v: number): string {
  return v.toLocaleString('en-US', { maximumFractionDigits: 2 });
}

export function formatAxis(v: number, unit: AxisUnit): string {
  if (v === 0) return '0';
  switch (unit) {
    case 'mib':
      return v >= 1024 ? `${axisNumber(v / 1024)} GB` : `${axisNumber(v)} MB`;
    case 'kib':
      return formatAxis(v / 1024, 'mib');
    case 'hours':
      return `${axisNumber(v)} h`;
    case 'minutes':
      return `${axisNumber(v)} min`;
    case 'fraction':
      return formatPercent(v);
    default:
      return axisNumber(v);
  }
}

// barPath draws a column with a rounded data end and a square base.
function barPath(x: number, y: number, w: number, h: number, r = 4): string {
  if (h <= 0 || w <= 0) return '';
  const rr = Math.min(r, w / 2, h);
  return `M${x},${y + h} V${y + rr} Q${x},${y} ${x + rr},${y} H${x + w - rr} Q${x + w},${y} ${x + w},${y + rr} V${y + h} Z`;
}

// svgPoint converts a pointer event to viewBox coordinates.
function svgPoint(e: PointerEvent<SVGElement>, width: number, height: number): { x: number; y: number } {
  const svg = (e.currentTarget as SVGElement).ownerSVGElement ?? (e.currentTarget as SVGSVGElement);
  const r = svg.getBoundingClientRect();
  return {
    x: r.width > 0 ? ((e.clientX - r.left) / r.width) * width : 0,
    y: r.height > 0 ? ((e.clientY - r.top) / r.height) * height : 0,
  };
}

// --- Histogram ---

export interface ChartMarker {
  value: number;
  label: string;
  kind: 'request' | 'recommended' | 'retry';
}

const MARKER_STYLE: Record<ChartMarker['kind'], { color: string; dash?: string; width: number }> = {
  request: { color: UTIL_COLOR.request, dash: '4 3', width: 1.5 },
  recommended: { color: UTIL_COLOR.recommended, width: 2 },
  retry: { color: UTIL_COLOR.retryLine, width: 2 },
};

// layoutMarkerLabels puts each marker's label in the first row where it
// does not collide with a label already placed, so two requests a few
// pixels apart get two rows rather than one smear of overlapping text.
function layoutMarkerLabels(xs: { x: number; text: string }[], maxX: number): { row: number; anchor: 'start' | 'end' }[] {
  // Each row holds the spans already taken in it: label text in its own
  // row, and the marker's line in every row below it on the way down to
  // the plot. A label must not land on another's line, and a line must
  // not run through another's label.
  const rows: [number, number][][] = Array.from({ length: 6 }, () => []);
  const free = (row: number, span: [number, number]) =>
    rows[row].every(([a, b]) => span[1] < a || span[0] > b);
  return xs.map(({ x, text }) => {
    const w = text.length * 6.8 + 6;
    const anchor: 'start' | 'end' = x + w > maxX ? 'end' : 'start';
    const span: [number, number] = anchor === 'start' ? [x - 2, x + w] : [x - w, x + 2];
    const stem: [number, number] = [x - 2, x + 2];
    let row = 0;
    for (; row < rows.length - 1; row++) {
      let ok = free(row, span);
      for (let r = row + 1; ok && r < rows.length; r++) ok = free(r, stem);
      if (ok) break;
    }
    rows[row].push(span);
    for (let r = row + 1; r < rows.length; r++) rows[r].push(stem);
    return { row, anchor };
  });
}

const HW = 560;
const HPAD = { right: 18, bottom: 30, left: 44 };

/**
 * Histogram draws a distribution of per-job values with vertical
 * references for the request. Bins to the right of `shadeFrom` are drawn
 * in the retry colour: those are the jobs that would outgrow a request at
 * that value and run again.
 */
export function Histogram({
  title,
  subtitle,
  dist,
  unit,
  markers = [],
  shadeFrom,
  shadeLabel,
  barLabel = 'jobs',
  note,
}: {
  title: string;
  subtitle?: ReactNode;
  dist: UtilDistribution;
  unit: AxisUnit;
  markers?: ChartMarker[];
  shadeFrom?: number;
  shadeLabel?: string;
  barLabel?: string;
  note?: ReactNode;
}) {
  const titleId = useId();
  const [tip, setTip] = useState<Tip | null>(null);
  const bins = dist.histogram;
  const lastHi = bins.length ? bins[bins.length - 1].hi : dist.max;
  const xTicks = niceTicks(Math.max(lastHi, ...markers.map((m) => m.value)) * 1.02, unit, 5);
  const xMax = xTicks[xTicks.length - 1];
  const maxCount = Math.max(1, ...bins.map((b) => b.count));
  const yTicks = niceTicks(maxCount, 'plain', 3);
  const yMax = yTicks[yTicks.length - 1];

  const sorted = [...markers].sort((a, b) => a.value - b.value);
  const plotRight = HW - HPAD.right;
  const xs0 = (v: number) => HPAD.left + (v / xMax) * (plotRight - HPAD.left);
  const labels = layoutMarkerLabels(
    sorted.map((m) => ({ x: xs0(m.value), text: m.label })),
    plotRight,
  );
  const labelRows = Math.max(0, ...labels.map((l) => l.row + 1));
  const top = 10 + labelRows * 15;
  const H = top + 150 + HPAD.bottom;
  const plotBottom = H - HPAD.bottom;
  const ys = (c: number) => plotBottom - (c / yMax) * (plotBottom - top);

  const shaded = (b: { lo: number; hi: number }) => shadeFrom !== undefined && (b.lo + b.hi) / 2 > shadeFrom;
  const shadedCount = bins.reduce((a, b) => a + (shaded(b) ? b.count : 0), 0);

  const describe =
    `${title}: ${dist.n.toLocaleString()} ${barLabel}; middle half between ${formatAxis(dist.p25, unit)} and ` +
    `${formatAxis(dist.p75, unit)}, largest ${formatAxis(dist.max, unit)}` +
    (sorted.length ? `; ${sorted.map((m) => m.label).join(', ')}` : '') +
    '.';

  return (
    <ChartFrame
      title={title}
      subtitle={subtitle}
      width={HW}
      height={H}
      tip={tip}
      note={note}
      legend={
        shadeFrom !== undefined && shadedCount > 0 ? (
          <>
            <LegendKey color={UTIL_COLOR.used}>{barLabel}</LegendKey>
            <LegendKey color={UTIL_COLOR.retry}>{shadeLabel ?? 'would rerun'}</LegendKey>
          </>
        ) : undefined
      }
      table={
        <table className="w-full tabular-nums">
          <thead>
            <tr className="text-left text-gray-500">
              <th className="py-0.5 pr-3 font-normal">Range</th>
              <th className="py-0.5 text-right font-normal">{barLabel}</th>
            </tr>
          </thead>
          <tbody>
            {bins.map((b, i) => (
              <tr key={i}>
                <td className="py-0.5 pr-3">
                  {formatAxis(b.lo, unit)} – {formatAxis(b.hi, unit)}
                </td>
                <td className="py-0.5 text-right">{b.count.toLocaleString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      }
    >
      <svg viewBox={`0 0 ${HW} ${H}`} width="100%" role="img" aria-labelledby={titleId} onPointerLeave={() => setTip(null)}>
        <title id={titleId}>{describe}</title>
        {yTicks.map((v) => (
          <g key={v}>
            <line x1={HPAD.left} x2={plotRight} y1={ys(v)} y2={ys(v)} stroke={UTIL_COLOR.grid} strokeWidth={1} />
            <text x={HPAD.left - 6} y={ys(v)} textAnchor="end" dominantBaseline="middle" className="fill-gray-500 text-[12px] tabular-nums">
              {v.toLocaleString()}
            </text>
          </g>
        ))}
        {xTicks.map((v) => (
          <text key={v} x={xs0(v)} y={plotBottom + 18} textAnchor="middle" className="fill-gray-500 text-[12px] tabular-nums">
            {formatAxis(v, unit)}
          </text>
        ))}
        {bins.map((b, i) => {
          const x0 = xs0(b.lo);
          const x1 = xs0(b.hi);
          // The 2px surface gap between neighbours, and the 24px cap on
          // a bar's width so a sparse histogram does not turn into slabs.
          const w = Math.min(24, Math.max(1, x1 - x0 - 2));
          const x = (x0 + x1) / 2 - w / 2;
          const y = ys(b.count);
          const fill = shaded(b) ? UTIL_COLOR.retry : UTIL_COLOR.used;
          return (
            <g key={i}>
              <path d={barPath(x, y, w, plotBottom - y)} fill={fill} opacity={tip && tip.x === (x0 + x1) / 2 ? 0.8 : 1} />
              <rect
                x={x0}
                y={top}
                width={Math.max(1, x1 - x0)}
                height={plotBottom - top}
                fill="transparent"
                onPointerEnter={() =>
                  setTip({
                    x: (x0 + x1) / 2,
                    y: Math.min(y, plotBottom - 8),
                    title: `${formatAxis(b.lo, unit)} – ${formatAxis(b.hi, unit)}`,
                    rows: [{ label: barLabel, value: b.count.toLocaleString() }],
                  })
                }
              />
            </g>
          );
        })}
        <line x1={HPAD.left} x2={plotRight} y1={plotBottom} y2={plotBottom} stroke={UTIL_COLOR.axis} strokeWidth={1} />
        {sorted.map((m, i) => {
          const s = MARKER_STYLE[m.kind];
          const x = xs0(m.value);
          const l = labels[i];
          const ly = 10 + l.row * 15;
          return (
            <g key={`${m.kind}-${m.value}`} pointerEvents="none">
              <line x1={x} x2={x} y1={ly + 2} y2={plotBottom} stroke="#ffffff" strokeWidth={s.width + 2} />
              <line x1={x} x2={x} y1={ly + 2} y2={plotBottom} stroke={s.color} strokeWidth={s.width} strokeDasharray={s.dash} />
              <text
                x={l.anchor === 'start' ? x + 4 : x - 4}
                y={ly + 8}
                textAnchor={l.anchor}
                className={`text-[12px] ${m.kind === 'request' ? 'fill-gray-700' : 'fill-gray-900 font-semibold'}`}
              >
                {m.label}
              </text>
            </g>
          );
        })}
      </svg>
    </ChartFrame>
  );
}

// --- The memory request curve ---

const CW = 560;
const CH = 280;
const CPAD = { top: 34, right: 24, bottom: 36, left: 60 };

/**
 * MemoryCurve plots, for each request_memory a workflow could have used,
 * the memory it would have reserved over the same work -- retries
 * included. Too low and the reruns cost more than they save; too high
 * and the reservation sits unused. The lowest point is the suggestion.
 */
export function MemoryCurve({ points }: { points: UtilMemoryCurvePoint[] }) {
  const titleId = useId();
  const [active, setActive] = useState<number | null>(null);
  const pts = useMemo(() => [...points].sort((a, b) => a.request_mib - b.request_mib), [points]);
  if (pts.length === 0) return null;
  const current = pts.find((p) => p.is_current);
  const recommended = pts.find((p) => p.is_recommended);

  const gib = (p: UtilMemoryCurvePoint) => p.reserved_mib_hours / 1024;
  const xMin = pts[0].request_mib;
  const xMaxRaw = pts[pts.length - 1].request_mib;
  const xSpan = xMaxRaw > xMin ? xMaxRaw - xMin : 1;
  const yTicks = niceTicks(Math.max(...pts.map(gib)), 'plain', 4);
  const yMax = yTicks[yTicks.length - 1];
  const xs = (v: number) => CPAD.left + ((v - xMin) / xSpan) * (CW - CPAD.left - CPAD.right);
  const ys = (v: number) => CH - CPAD.bottom - (v / yMax) * (CH - CPAD.top - CPAD.bottom);
  const xTicks = niceTicks(xMaxRaw, 'mib', 6).filter((v) => v >= xMin - 1e-6);

  // Where reruns start: every request below the first one no job
  // outgrows. Shading it shows which side of the curve retries cost.
  const firstClean = pts.find((p) => p.retry_fraction === 0);
  const retryEdge = firstClean ? xs(firstClean.request_mib) : xs(xMaxRaw);

  const line = pts.map((p) => `${xs(p.request_mib)},${ys(gib(p))}`).join(' ');
  const tip: Tip | null =
    active === null
      ? null
      : (() => {
          const p = pts[active];
          return {
            x: xs(p.request_mib),
            y: ys(gib(p)),
            title: `request_memory = ${formatMiB(p.request_mib)}`,
            rows: [
              { label: 'GB-hours reserved', value: formatNumber(gib(p)), color: UTIL_COLOR.used },
              { label: 'of jobs rerun', value: formatPercent(p.retry_fraction) },
              ...(p.retry_mib !== null ? [{ label: 'retry request', value: formatMiB(p.retry_mib) }] : []),
            ],
          };
        })();

  const nearest = (x: number) => {
    let best = 0;
    for (let i = 1; i < pts.length; i++) {
      if (Math.abs(xs(pts[i].request_mib) - x) < Math.abs(xs(pts[best].request_mib) - x)) best = i;
    }
    return best;
  };

  const saving =
    current && recommended && current !== recommended && gib(current) > 0
      ? 1 - gib(recommended) / gib(current)
      : null;

  const describe =
    `Memory reserved for each possible request.` +
    (current ? ` Current request ${formatMiB(current.request_mib)}: ${formatNumber(gib(current))} GB-hours.` : '') +
    (recommended
      ? ` Suggested ${formatMiB(recommended.request_mib)}: ${formatNumber(gib(recommended))} GB-hours, ${formatPercent(recommended.retry_fraction)} of jobs rerun.`
      : '');

  const callout = (p: UtilMemoryCurvePoint, kind: 'current' | 'recommended', i: number) => {
    const x = xs(p.request_mib);
    const y = ys(gib(p));
    const right = x > CW * 0.6;
    const color = kind === 'current' ? UTIL_COLOR.request : UTIL_COLOR.recommended;
    // The suggestion is the curve's lowest point, so the space under it
    // is free and its label goes there; the current request's goes above.
    const below = kind === 'recommended' && y + 38 < CH - CPAD.bottom;
    const ty = below ? y + 20 : y - 22;
    return (
      <g key={`${kind}-${i}`} pointerEvents="none">
        <circle cx={x} cy={y} r={6} fill={color} stroke="#ffffff" strokeWidth={2} />
        <text x={right ? x - 8 : x + 8} y={ty} textAnchor={right ? 'end' : 'start'} className="fill-gray-900 text-[13px] font-semibold">
          {kind === 'current' ? (p.is_recommended ? 'now, and the lowest' : 'now') : 'suggested'}{' '}
          {formatMiB(p.request_mib)}
        </text>
        <text x={right ? x - 8 : x + 8} y={ty + 14} textAnchor={right ? 'end' : 'start'} className="fill-gray-500 text-[12px] tabular-nums">
          {formatNumber(gib(p))} GB-h{p.retry_fraction > 0 ? `, ${formatPercent(p.retry_fraction)} rerun` : ''}
        </text>
      </g>
    );
  };

  return (
    <ChartFrame
      title="What each memory request would have reserved"
      subtitle="Reserved memory over the same work, including the reruns of jobs that outgrow the request."
      width={CW}
      height={CH}
      tip={tip}
      legend={
        <>
          <LegendKey color={UTIL_COLOR.used} shape="line">GB-hours reserved</LegendKey>
          {current && <LegendKey color={UTIL_COLOR.request} shape="dot">current request</LegendKey>}
          {recommended && recommended !== current && (
            <LegendKey color={UTIL_COLOR.recommended} shape="dot">suggested request</LegendKey>
          )}
          {firstClean !== pts[0] && <LegendKey color="#fdf0d0">some jobs rerun</LegendKey>}
        </>
      }
      note={
        saving !== null && saving > 0 && recommended && current
          ? `Requesting ${formatMiB(recommended.request_mib)} instead of ${formatMiB(current.request_mib)} would have reserved ${formatPercent(saving)} less memory.`
          : undefined
      }
      table={
        <table className="w-full tabular-nums">
          <thead>
            <tr className="text-left text-gray-500">
              <th className="py-0.5 pr-3 font-normal">request_memory</th>
              <th className="py-0.5 pr-3 font-normal">retry at</th>
              <th className="py-0.5 pr-3 text-right font-normal">rerun</th>
              <th className="py-0.5 text-right font-normal">GB-hours</th>
            </tr>
          </thead>
          <tbody>
            {pts.map((p) => (
              <tr key={p.request_mib} className={p.is_recommended ? 'font-semibold text-gray-900' : ''}>
                <td className="py-0.5 pr-3">
                  {formatMiB(p.request_mib)}
                  {p.is_current ? ' (now)' : ''}
                  {p.is_recommended ? ' (suggested)' : ''}
                </td>
                <td className="py-0.5 pr-3">{p.retry_mib !== null ? formatMiB(p.retry_mib) : '—'}</td>
                <td className="py-0.5 pr-3 text-right">{formatPercent(p.retry_fraction)}</td>
                <td className="py-0.5 text-right">{formatNumber(gib(p))}</td>
              </tr>
            ))}
          </tbody>
        </table>
      }
    >
      <svg
        viewBox={`0 0 ${CW} ${CH}`}
        width="100%"
        role="img"
        aria-labelledby={titleId}
        onPointerLeave={() => setActive(null)}
      >
        <title id={titleId}>{describe}</title>
        {retryEdge > CPAD.left && (
          <rect
            x={CPAD.left}
            y={CPAD.top - 6}
            width={retryEdge - CPAD.left}
            height={CH - CPAD.bottom - CPAD.top + 6}
            fill="#fdf0d0"
            opacity={0.7}
          />
        )}
        {yTicks.map((v) => (
          <g key={v}>
            <line x1={CPAD.left} x2={CW - CPAD.right} y1={ys(v)} y2={ys(v)} stroke={UTIL_COLOR.grid} strokeWidth={1} />
            <text x={CPAD.left - 6} y={ys(v)} textAnchor="end" dominantBaseline="middle" className="fill-gray-500 text-[12px] tabular-nums">
              {formatNumber(v)}
            </text>
          </g>
        ))}
        <text x={14} y={CPAD.top - 14} className="fill-gray-500 text-[12px]">
          GB-hours
        </text>
        {xTicks.map((v) => (
          <text key={v} x={xs(v)} y={CH - CPAD.bottom + 16} textAnchor="middle" className="fill-gray-500 text-[12px] tabular-nums">
            {formatAxis(v, 'mib')}
          </text>
        ))}
        <text x={CW - CPAD.right} y={CH - 4} textAnchor="end" className="fill-gray-500 text-[12px]">
          request_memory
        </text>
        <line x1={CPAD.left} x2={CW - CPAD.right} y1={CH - CPAD.bottom} y2={CH - CPAD.bottom} stroke={UTIL_COLOR.axis} strokeWidth={1} />
        <polyline points={line} fill="none" stroke={UTIL_COLOR.used} strokeWidth={2} strokeLinejoin="round" strokeLinecap="round" />
        {active !== null && (
          <line
            x1={xs(pts[active].request_mib)}
            x2={xs(pts[active].request_mib)}
            y1={CPAD.top - 6}
            y2={CH - CPAD.bottom}
            stroke={UTIL_COLOR.axis}
            strokeWidth={1}
          />
        )}
        {pts.map((p, i) => (
          <circle
            key={p.request_mib}
            cx={xs(p.request_mib)}
            cy={ys(gib(p))}
            r={4}
            fill={UTIL_COLOR.used}
            stroke="#ffffff"
            strokeWidth={2}
            tabIndex={0}
            aria-label={`request_memory ${formatMiB(p.request_mib)}: ${formatNumber(gib(p))} GB-hours, ${formatPercent(p.retry_fraction)} rerun`}
            onFocus={() => setActive(i)}
            onBlur={() => setActive(null)}
            className="outline-none focus:stroke-gray-900"
          />
        ))}
        {current && callout(current, 'current', 0)}
        {recommended && recommended !== current && callout(recommended, 'recommended', 1)}
        {/* The hit layer: the pointer only has to be nearest a request,
            not on an 8px dot. */}
        <rect
          x={CPAD.left}
          y={CPAD.top - 6}
          width={CW - CPAD.left - CPAD.right}
          height={CH - CPAD.bottom - CPAD.top + 6}
          fill="transparent"
          onPointerMove={(e) => setActive(nearest(svgPoint(e, CW, CH).x))}
        />
      </svg>
    </ChartFrame>
  );
}

// --- Wall time vs peak memory ---

const OUTCOMES: {
  key: UtilSample['outcome'];
  label: string;
  color: string;
  shape: 'dot' | 'triangle' | 'square' | 'ring';
}[] = [
  { key: 'ok', label: 'succeeded', color: UTIL_COLOR.used, shape: 'dot' },
  { key: 'memory_exceeded', label: 'went over memory', color: UTIL_COLOR.memoryExceeded, shape: 'triangle' },
  { key: 'failed', label: 'failed', color: UTIL_COLOR.failed, shape: 'square' },
  { key: 'removed', label: 'removed', color: UTIL_COLOR.removed, shape: 'ring' },
];

const SW = 560;
const SH = 280;
const SPAD = { top: 14, right: 18, bottom: 36, left: 56 };

/**
 * OutcomeScatter answers "do the long jobs need more memory?": one dot
 * per job, run time across, peak memory up, shaped and coloured by how it
 * ended. Shape carries the outcome too, so it reads without colour.
 */
export function OutcomeScatter({ samples, request }: { samples: UtilSample[]; request: UtilRequest | null }) {
  const titleId = useId();
  const [active, setActive] = useState<number | null>(null);
  const pts = useMemo(
    () => samples.filter((s): s is UtilSample & { memory_mib: number } => s.memory_mib !== null),
    [samples],
  );
  if (pts.length === 0) return null;

  // Short jobs read in minutes; "0.04 h" makes the reader do the sum.
  const maxWall = Math.max(...pts.map((p) => p.wall));
  const tUnit: AxisUnit = maxWall < 2 * 3600 ? 'minutes' : 'hours';
  const tScale = tUnit === 'minutes' ? 60 : 3600;
  const xTicks = niceTicks(maxWall / tScale, 'plain', 5);
  const xMax = xTicks[xTicks.length - 1];
  const yTicks = niceTicks(Math.max(request?.typical ?? 0, ...pts.map((p) => p.memory_mib)), 'mib', 4);
  const yMax = yTicks[yTicks.length - 1];
  const xs = (h: number) => SPAD.left + (h / xMax) * (SW - SPAD.left - SPAD.right);
  const ys = (m: number) => SH - SPAD.bottom - (m / yMax) * (SH - SPAD.top - SPAD.bottom);

  const counts = new Map<string, number>();
  for (const p of pts) counts.set(p.outcome, (counts.get(p.outcome) ?? 0) + 1);
  const present = OUTCOMES.filter((o) => counts.has(o.key));

  // Draw the common outcome first so the rare ones -- the ones worth
  // seeing -- sit on top of it.
  const order = pts
    .map((p, i) => ({ p, i }))
    .sort((a, b) => (a.p.outcome === 'ok' ? 0 : 1) - (b.p.outcome === 'ok' ? 0 : 1));

  const tip: Tip | null =
    active === null
      ? null
      : (() => {
          const p = pts[active];
          const o = OUTCOMES.find((x) => x.key === p.outcome)!;
          return {
            x: xs(p.wall / tScale),
            y: ys(p.memory_mib),
            title: o.label,
            rows: [
              { label: 'peak memory', value: formatMiB(p.memory_mib) },
              { label: 'run time', value: formatSeconds(p.wall) },
            ],
          };
        })();

  const nearest = (x: number, y: number) => {
    let best = -1;
    let bestD = 24 * 24;
    pts.forEach((p, i) => {
      const dx = xs(p.wall / tScale) - x;
      const dy = ys(p.memory_mib) - y;
      const d = dx * dx + dy * dy;
      if (d < bestD) {
        bestD = d;
        best = i;
      }
    });
    return best < 0 ? null : best;
  };

  return (
    <ChartFrame
      title="Run time and peak memory"
      subtitle={`One mark per job${samples.length < 400 ? '' : ', for a sample of 400 jobs'}.`}
      width={SW}
      height={SH}
      tip={tip}
      legend={
        <>
          {present.map((o) => (
            <LegendKey key={o.key} color={o.color} shape={o.shape}>
              {o.label} <span className="tabular-nums text-gray-400">{counts.get(o.key)!.toLocaleString()}</span>
            </LegendKey>
          ))}
          {request && (
            <LegendKey color={UTIL_COLOR.request} shape="line" dashed>
              requested {formatMiB(request.typical)}
            </LegendKey>
          )}
        </>
      }
    >
      <svg viewBox={`0 0 ${SW} ${SH}`} width="100%" role="img" aria-labelledby={titleId} onPointerLeave={() => setActive(null)}>
        <title id={titleId}>
          {`Run time against peak memory for ${pts.length} jobs: ${present
            .map((o) => `${counts.get(o.key)} ${o.label}`)
            .join(', ')}.`}
        </title>
        {yTicks.map((v) => (
          <g key={v}>
            <line x1={SPAD.left} x2={SW - SPAD.right} y1={ys(v)} y2={ys(v)} stroke={UTIL_COLOR.grid} strokeWidth={1} />
            <text x={SPAD.left - 6} y={ys(v)} textAnchor="end" dominantBaseline="middle" className="fill-gray-500 text-[12px] tabular-nums">
              {formatAxis(v, 'mib')}
            </text>
          </g>
        ))}
        {xTicks.map((v) => (
          <text key={v} x={xs(v)} y={SH - SPAD.bottom + 16} textAnchor="middle" className="fill-gray-500 text-[12px] tabular-nums">
            {formatAxis(v, tUnit)}
          </text>
        ))}
        <line x1={SPAD.left} x2={SW - SPAD.right} y1={SH - SPAD.bottom} y2={SH - SPAD.bottom} stroke={UTIL_COLOR.axis} strokeWidth={1} />
        {request && (
          <line
            x1={SPAD.left}
            x2={SW - SPAD.right}
            y1={ys(request.typical)}
            y2={ys(request.typical)}
            stroke={UTIL_COLOR.request}
            strokeWidth={1.5}
            strokeDasharray="4 3"
          />
        )}
        {order.map(({ p, i }) => {
          const o = OUTCOMES.find((x) => x.key === p.outcome)!;
          return (
            <g key={i} opacity={active === null || active === i ? 0.85 : 0.35}>
              <Glyph shape={o.shape} cx={xs(p.wall / tScale)} cy={ys(p.memory_mib)} r={4} color={o.color} ring />
            </g>
          );
        })}
        {active !== null && (
          <circle cx={xs(pts[active].wall / tScale)} cy={ys(pts[active].memory_mib)} r={7} fill="none" stroke="#1a1a1a" strokeWidth={1.5} />
        )}
        <rect
          x={SPAD.left}
          y={SPAD.top}
          width={SW - SPAD.left - SPAD.right}
          height={SH - SPAD.top - SPAD.bottom}
          fill="transparent"
          onPointerMove={(e) => {
            const pt = svgPoint(e, SW, SH);
            setActive(nearest(pt.x, pt.y));
          }}
        />
      </svg>
    </ChartFrame>
  );
}

// --- Request against use, submission by submission ---

const TW = 560;
const TH = 230;
const TPAD = { top: 16, right: 92, bottom: 32, left: 56 };

/**
 * TrendChart follows one resource across a workflow's submissions: what
 * was requested next to what the jobs used. A change the user made shows
 * as a step in the request line, and whether it helped shows as how
 * close the two lines end up.
 */
export function TrendChart({
  title,
  batches,
  request,
  used,
  usedLabel,
  unit,
}: {
  title: string;
  batches: UtilBatchPoint[];
  request: (b: UtilBatchPoint) => number | null;
  used: (b: UtilBatchPoint) => number | null;
  usedLabel: string;
  unit: AxisUnit;
}) {
  const titleId = useId();
  const [active, setActive] = useState<number | null>(null);
  const reqs = batches.map(request);
  const uses = batches.map(used);
  const all = [...reqs, ...uses].filter((v): v is number => v !== null);
  if (all.length === 0 || batches.length < 2) return null;

  const yTicks = niceTicks(Math.max(...all), unit, 4);
  const yMax = yTicks[yTicks.length - 1];
  const n = batches.length;
  const xs = (i: number) => TPAD.left + (n === 1 ? 0.5 : i / (n - 1)) * (TW - TPAD.left - TPAD.right);
  const ys = (v: number) => TH - TPAD.bottom - (v / yMax) * (TH - TPAD.top - TPAD.bottom);
  const fmt = (v: number) => formatAxis(v, unit);

  // The request is a setting, so it steps rather than slopes between
  // submissions; usage is a measurement and joins point to point.
  const stepPath = (vals: (number | null)[]) => {
    let d = '';
    let prev: number | null = null;
    vals.forEach((v, i) => {
      if (v === null) {
        prev = null;
        return;
      }
      if (prev === null) d += `M${xs(i)},${ys(v)}`;
      else d += `H${xs(i)}V${ys(v)}`;
      prev = v;
    });
    return d;
  };
  const linePath = (vals: (number | null)[]) => {
    let d = '';
    let started = false;
    vals.forEach((v, i) => {
      if (v === null) {
        started = false;
        return;
      }
      d += `${started ? 'L' : 'M'}${xs(i)},${ys(v)}`;
      started = true;
    });
    return d;
  };

  const lastIdx = (vals: (number | null)[]) => {
    for (let i = vals.length - 1; i >= 0; i--) if (vals[i] !== null) return i;
    return -1;
  };
  const lr = lastIdx(reqs);
  const lu = lastIdx(uses);
  // End labels sit beside the last point of each line; when the two
  // lines end close together the labels part to either side of them.
  let ry = lr >= 0 ? ys(reqs[lr]!) : 0;
  let uy = lu >= 0 ? ys(uses[lu]!) : 0;
  if (lr >= 0 && lu >= 0 && Math.abs(ry - uy) < 12) {
    const mid = (ry + uy) / 2;
    const reqAbove = reqs[lr]! >= uses[lu]!;
    ry = reqAbove ? mid - 7 : mid + 7;
    uy = reqAbove ? mid + 7 : mid - 7;
  }

  const date = (t: number) => new Date(t * 1000).toLocaleDateString([], { month: 'short', day: 'numeric' });
  const tip: Tip | null =
    active === null
      ? null
      : {
          x: xs(active),
          y: Math.min(...[reqs[active], uses[active]].filter((v): v is number => v !== null).map(ys), TH - TPAD.bottom),
          title: `Cluster ${batches[active].id} · ${date(batches[active].submitted)} · ${batches[active].jobs.toLocaleString()} jobs`,
          rows: [
            ...(reqs[active] !== null ? [{ label: 'requested', value: fmt(reqs[active]!), color: UTIL_COLOR.request }] : []),
            ...(uses[active] !== null ? [{ label: usedLabel, value: fmt(uses[active]!), color: UTIL_COLOR.used }] : []),
          ],
        };

  return (
    <ChartFrame
      title={title}
      width={TW}
      height={TH}
      tip={tip}
      legend={
        <>
          <LegendKey color={UTIL_COLOR.request} shape="line">requested</LegendKey>
          <LegendKey color={UTIL_COLOR.used} shape="line">{usedLabel}</LegendKey>
        </>
      }
      table={
        <table className="w-full tabular-nums">
          <thead>
            <tr className="text-left text-gray-500">
              <th className="py-0.5 pr-3 font-normal">Cluster</th>
              <th className="py-0.5 pr-3 font-normal">Submitted</th>
              <th className="py-0.5 pr-3 text-right font-normal">Jobs</th>
              <th className="py-0.5 pr-3 text-right font-normal">Requested</th>
              <th className="py-0.5 text-right font-normal">{usedLabel}</th>
            </tr>
          </thead>
          <tbody>
            {batches.map((b, i) => (
              <tr key={b.id}>
                <td className="py-0.5 pr-3">{b.id}</td>
                <td className="py-0.5 pr-3">{date(b.submitted)}</td>
                <td className="py-0.5 pr-3 text-right">{b.jobs.toLocaleString()}</td>
                <td className="py-0.5 pr-3 text-right">{reqs[i] !== null ? fmt(reqs[i]!) : '—'}</td>
                <td className="py-0.5 text-right">{uses[i] !== null ? fmt(uses[i]!) : '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      }
    >
      <svg viewBox={`0 0 ${TW} ${TH}`} width="100%" role="img" aria-labelledby={titleId} onPointerLeave={() => setActive(null)}>
        <title id={titleId}>
          {`${title} across ${n} submissions` +
            (lr >= 0 ? `; latest request ${fmt(reqs[lr]!)}` : '') +
            (lu >= 0 ? `, ${usedLabel} ${fmt(uses[lu]!)}` : '') +
            '.'}
        </title>
        {yTicks.map((v) => (
          <g key={v}>
            <line x1={TPAD.left} x2={TW - TPAD.right} y1={ys(v)} y2={ys(v)} stroke={UTIL_COLOR.grid} strokeWidth={1} />
            <text x={TPAD.left - 6} y={ys(v)} textAnchor="end" dominantBaseline="middle" className="fill-gray-500 text-[12px] tabular-nums">
              {fmt(v)}
            </text>
          </g>
        ))}
        <text x={TPAD.left} y={TH - 8} className="fill-gray-500 text-[12px]">
          {date(batches[0].submitted)}
        </text>
        <text x={TW - TPAD.right} y={TH - 8} textAnchor="end" className="fill-gray-500 text-[12px]">
          {date(batches[n - 1].submitted)}
        </text>
        <line x1={TPAD.left} x2={TW - TPAD.right} y1={TH - TPAD.bottom} y2={TH - TPAD.bottom} stroke={UTIL_COLOR.axis} strokeWidth={1} />
        {active !== null && (
          <line x1={xs(active)} x2={xs(active)} y1={TPAD.top} y2={TH - TPAD.bottom} stroke={UTIL_COLOR.axis} strokeWidth={1} />
        )}
        <path d={stepPath(reqs)} fill="none" stroke={UTIL_COLOR.request} strokeWidth={2} strokeLinejoin="round" />
        <path d={linePath(uses)} fill="none" stroke={UTIL_COLOR.used} strokeWidth={2} strokeLinejoin="round" strokeLinecap="round" />
        {uses.map((v, i) =>
          v === null ? null : (
            <circle key={i} cx={xs(i)} cy={ys(v)} r={active === i ? 5 : 3} fill={UTIL_COLOR.used} stroke="#ffffff" strokeWidth={active === i ? 2 : 1} />
          ),
        )}
        {lr >= 0 && (
          <text x={xs(lr) + 8} y={ry} dominantBaseline="middle" className="fill-gray-700 text-[12px]">
            requested
          </text>
        )}
        {lu >= 0 && (
          <text x={xs(lu) + 8} y={uy} dominantBaseline="middle" className="fill-gray-700 text-[12px]">
            {usedLabel}
          </text>
        )}
        <rect
          x={TPAD.left - 8}
          y={TPAD.top}
          width={TW - TPAD.left - TPAD.right + 16}
          height={TH - TPAD.top - TPAD.bottom}
          fill="transparent"
          onPointerMove={(e) => {
            const { x } = svgPoint(e, TW, TH);
            const i = Math.round(((x - TPAD.left) / (TW - TPAD.left - TPAD.right)) * (n - 1));
            setActive(Math.max(0, Math.min(n - 1, i)));
          }}
        />
      </svg>
    </ChartFrame>
  );
}

// --- The range strip ---

const RW = 150;
const RH = 22;
const RPAD = 6;

/**
 * RangeStrip says at a glance whether a workflow's jobs fit their
 * request: the track runs from zero to the request or the largest job,
 * whichever is bigger; the tick is the request, the box the middle half
 * of jobs, the whisker the 10th to 90th percentile, and the dot the
 * largest job -- red when it went over the request.
 */
export function RangeStrip({
  request,
  dist,
  format,
  label,
}: {
  request: UtilRequest | null;
  dist: UtilDistribution | null;
  format: (v: number) => string;
  label: string;
}) {
  const g = stripGeometry(request, dist);
  if (!g || !dist) return <span className="text-xs text-gray-400">—</span>;
  const xs = (f: number) => RPAD + f * (RW - 2 * RPAD);
  const mid = RH / 2;
  const text =
    `${label}: ${request ? `requested ${format(request.typical)}; ` : ''}` +
    `middle half of jobs used ${format(dist.p25)}–${format(dist.p75)}; ` +
    `largest ${format(dist.max)}${g.over ? ', more than requested' : ''}.`;
  return (
    <svg
      viewBox={`0 0 ${RW} ${RH}`}
      width={RW}
      height={RH}
      role="img"
      aria-label={text}
      className="block max-w-full"
      data-over={g.over ? 'true' : 'false'}
    >
      <title>{text}</title>
      <line x1={xs(0)} x2={xs(1)} y1={mid} y2={mid} stroke={UTIL_COLOR.track} strokeWidth={4} strokeLinecap="round" />
      <line x1={xs(g.p10)} x2={xs(g.p90)} y1={mid} y2={mid} stroke={UTIL_COLOR.used} strokeWidth={1.5} />
      <rect
        x={xs(g.p25)}
        y={mid - 4}
        width={Math.max(2, xs(g.p75) - xs(g.p25))}
        height={8}
        rx={2}
        fill={UTIL_COLOR.used}
      />
      {g.request !== null && (
        <line
          x1={xs(g.request)}
          x2={xs(g.request)}
          y1={2}
          y2={RH - 2}
          stroke={UTIL_COLOR.request}
          strokeWidth={2}
          data-testid="strip-request"
        />
      )}
      <circle
        cx={xs(g.max)}
        cy={mid}
        r={4}
        fill={g.over ? UTIL_COLOR.over : UTIL_COLOR.used}
        stroke="#ffffff"
        strokeWidth={1.5}
        data-testid="strip-max"
      />
    </svg>
  );
}

/** RangeStripKey explains the strip once, under the table. */
export function RangeStripKey() {
  return (
    <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-gray-500">
      <span className="inline-flex items-center gap-1.5">
        <svg width="6" height="14" aria-hidden>
          <line x1="3" x2="3" y1="1" y2="13" stroke={UTIL_COLOR.request} strokeWidth="2" />
        </svg>
        typical request
      </span>
      <span className="inline-flex items-center gap-1.5">
        <svg width="30" height="10" aria-hidden>
          <line x1="1" x2="29" y1="5" y2="5" stroke={UTIL_COLOR.used} strokeWidth="1.5" />
          <rect x="8" y="1" width="14" height="8" rx="2" fill={UTIL_COLOR.used} />
        </svg>
        middle half of jobs, whiskers 10th–90th percentile
      </span>
      <LegendKey color={UTIL_COLOR.used} shape="dot">
        largest job
      </LegendKey>
      <LegendKey color={UTIL_COLOR.over} shape="dot">
        largest job, over its request
      </LegendKey>
    </div>
  );
}

// --- The headline meter ---

/**
 * UsageBar splits a reservation into the part jobs used and the part they
 * did not. The unused part is a light step of the same blue, so the bar
 * reads as one quantity divided rather than two things compared.
 */
export function UsageBar({ fraction, label }: { fraction: number; label: string }) {
  const used = Math.max(0, Math.min(1, fraction));
  return (
    <div
      role="img"
      aria-label={label}
      className="flex h-2.5 w-full gap-0.5 overflow-hidden rounded-full"
    >
      {used > 0 && (
        <div className="h-full rounded-l-full" style={{ width: `${used * 100}%`, backgroundColor: UTIL_COLOR.used }} />
      )}
      {used < 1 && (
        <div
          className={`h-full flex-1 rounded-r-full ${used === 0 ? 'rounded-l-full' : ''}`}
          style={{ backgroundColor: UTIL_COLOR.track }}
        />
      )}
    </div>
  );
}
