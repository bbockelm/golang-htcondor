'use client';

// A small time-series line chart for one job metric: one line per run
// attempt, a dashed reference line for the requested amount, and native
// per-point tooltips. Inline SVG, no chart dependency -- the same approach
// as Sparkline, one step up in fidelity because this one has axes.
//
// One metric per chart, one y-axis: memory, CPU, disk and GPU never share
// a plot (their units do not compare), which is also why the requested
// reference is a line only when it shares the value's unit.

import { useId } from 'react';
import { formatAxisTicks, niceTicks, type AxisUnit } from '@/lib/axis';
import {
  formatMetric,
  RUN_COLORS,
  runColor,
  type MetricSeries,
} from '@/lib/metrics';

const W = 640;
const H = 200;
const PAD = { top: 12, right: 16, bottom: 28, left: 60 };
const PLOT_W = W - PAD.left - PAD.right;
const PLOT_H = H - PAD.top - PAD.bottom;

export function MetricChart({ series }: { series: MetricSeries }) {
  const titleId = useId();
  const allValues: number[] = [];
  let tMin = Infinity;
  let tMax = -Infinity;
  for (const ex of series.executions) {
    for (const p of ex.points) {
      allValues.push(p.value);
      if (p.t < tMin) tMin = p.t;
      if (p.t > tMax) tMax = p.t;
    }
  }
  const dataMax = Math.max(0, ...allValues, series.requested ?? 0);
  // Ticks are round numbers in the unit the axis is labelled in, and the
  // whole axis is labelled in one unit (see formatAxisTicks).
  const axisUnit: AxisUnit = series.unit === 'MB' ? 'mib' : series.unit === 'KB' ? 'kib' : 'plain';
  const yTicks = niceTicks(dataMax, axisUnit, 4);
  const yMax = yTicks[yTicks.length - 1];
  const yLabels =
    axisUnit === 'plain'
      ? yTicks.map((v) => (v === 0 ? '0' : formatMetric(v, series.unit)))
      : formatAxisTicks(yTicks, axisUnit);
  const spanT = tMax > tMin ? tMax - tMin : 1;

  const xs = (t: number) => PAD.left + ((t - tMin) / spanT) * PLOT_W;
  const ys = (v: number) => PAD.top + PLOT_H - (yMax > 0 ? v / yMax : 0) * PLOT_H;

  const multi = series.executions.length > 1;

  return (
    <figure className="rounded-lg border border-gray-200 bg-white p-3">
      <figcaption className="mb-1 flex items-baseline justify-between gap-2">
        <span className="text-sm font-semibold text-gray-900">{series.label}</span>
        <span className="text-xs text-gray-400" title={series.requestedExpr}>
          {series.requestedNote ??
            (series.requested !== undefined
              ? `Requested ${formatMetric(series.requested, series.unit)}`
              : '')}
          {series.requestedExpr && (series.requestedNote || series.requested !== undefined) && (
            <> · from expression</>
          )}
        </span>
      </figcaption>

      <svg
        viewBox={`0 0 ${W} ${H}`}
        width="100%"
        role="img"
        aria-labelledby={titleId}
        className="overflow-visible"
        preserveAspectRatio="xMidYMid meet"
      >
        <title id={titleId}>
          {`${series.label} over time${multi ? `, ${series.executions.length} run attempts` : ''}`}
        </title>

        {/* y gridlines + labels */}
        {yTicks.map((v, i) => (
          <g key={i}>
            <line
              x1={PAD.left}
              x2={W - PAD.right}
              y1={ys(v)}
              y2={ys(v)}
              className="stroke-gray-100"
              strokeWidth={1}
            />
            <text
              x={PAD.left - 6}
              y={ys(v)}
              textAnchor="end"
              dominantBaseline="middle"
              className="fill-gray-400 text-[10px]"
            >
              {yLabels[i]}
            </text>
          </g>
        ))}

        {/* x endpoints */}
        <text x={PAD.left} y={H - 8} textAnchor="start" className="fill-gray-400 text-[10px]">
          {new Date(tMin * 1000).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })}
        </text>
        <text x={W - PAD.right} y={H - 8} textAnchor="end" className="fill-gray-400 text-[10px]">
          {new Date(tMax * 1000).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })}
        </text>

        {/* requested reference line (same-unit metrics only) */}
        {series.requested !== undefined && series.requested <= yMax && (
          <g>
            <line
              x1={PAD.left}
              x2={W - PAD.right}
              y1={ys(series.requested)}
              y2={ys(series.requested)}
              className="stroke-gray-400"
              strokeWidth={1.5}
              strokeDasharray="4 3"
            />
            <text
              x={W - PAD.right}
              y={ys(series.requested) - 3}
              textAnchor="end"
              className="fill-gray-500 text-[10px]"
            >
              requested
            </text>
          </g>
        )}

        {/* one polyline + dots per run */}
        {series.executions.map((ex, i) => {
          const color = runColor(i);
          const pts = ex.points.map((p) => `${xs(p.t)},${ys(p.value)}`).join(' ');
          return (
            <g key={ex.run}>
              <polyline
                points={pts}
                fill="none"
                stroke={color}
                strokeWidth={2}
                strokeLinejoin="round"
                strokeLinecap="round"
              >
                {multi && <title>{`Run ${ex.run}`}</title>}
              </polyline>
              {ex.points.map((p, j) => (
                <circle key={j} cx={xs(p.t)} cy={ys(p.value)} r={3} fill={color}>
                  <title>
                    {`${multi ? `Run ${ex.run} — ` : ''}${formatMetric(p.value, series.unit)} · ${new Date(
                      p.t * 1000,
                    ).toLocaleString()}`}
                  </title>
                </circle>
              ))}
            </g>
          );
        })}
      </svg>

      {/* legend, only when more than one run attempt. A swatch per run
          while each run has its own colour; past that, a swatch list would
          repeat colours and run to dozens of entries, so one line says how
          many runs there are and that the tooltips name them. */}
      {multi && series.executions.length > RUN_COLORS.length && (
        <p className="mt-1 text-xs text-gray-600">
          {`${series.executions.length} runs (Run ${series.executions[0].run} to Run ${
            series.executions[series.executions.length - 1].run
          }). Colors repeat every ${RUN_COLORS.length} runs; hover a point for its run.`}
        </p>
      )}
      {multi && series.executions.length <= RUN_COLORS.length && (
        <div className="mt-1 flex flex-wrap gap-3">
          {series.executions.map((ex, i) => (
            <span key={ex.run} className="inline-flex items-center gap-1 text-xs text-gray-600">
              <span
                className="inline-block h-2 w-2 rounded-full"
                style={{ backgroundColor: runColor(i) }}
              />
              Run {ex.run}
            </span>
          ))}
        </div>
      )}

      {series.note && <p className="mt-1 text-[11px] text-gray-400">{series.note}</p>}
    </figure>
  );
}
