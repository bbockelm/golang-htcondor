// Axis scales shared by the app's charts: the Utilization page's and the
// job page's usage graphs.
//
// Memory and disk are binary quantities (MiB and KiB on HTCondor's wire)
// labelled MB/GB, as formatMiB in lib/utilization labels them everywhere
// else, so an axis, a tooltip and a table cell read the same number the
// same way.

import { formatPercent } from './utilization';

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
  let step = (n <= 1 ? 1 : n <= 2 ? 2 : n <= 2.5 ? 2.5 : n <= 5 ? 5 : 10) * mag;
  // Below a GB, steps of a fifth make "409.6 MB"; quarters and halves
  // make "256 MB" and "512 MB", which are numbers people request.
  if (scale > 1 && step < 1) step = step <= 0.25 ? 0.25 : 0.5;
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

// formatAxisTicks labels a whole axis in one unit, chosen from its top
// tick: an axis reaching a GB reads "0, 5 GB, 10 GB, 15 GB", never
// "512 MB" beside "1 GB". The ticks should come from niceTicks, which
// already steps in that unit, so every label is a round number in it.
// Units without a scale fall through to formatAxis.
export function formatAxisTicks(ticks: number[], unit: AxisUnit): string[] {
  if (unit !== 'mib' && unit !== 'kib') return ticks.map((v) => formatAxis(v, unit));
  const mib = unit === 'kib' ? ticks.map((v) => v / 1024) : ticks;
  const top = Math.max(0, ...mib);
  const [div, label] = top >= 1024 * 1024 ? [1024 * 1024, 'TB'] : top >= 1024 ? [1024, 'GB'] : [1, 'MB'];
  return mib.map((v) => (v === 0 ? '0' : `${axisNumber(v / div)} ${label}`));
}
