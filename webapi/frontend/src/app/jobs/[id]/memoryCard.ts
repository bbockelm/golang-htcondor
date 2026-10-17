// What the job page's memory card says and draws: what similar jobs
// peaked at, this job's own peak, and how many similar jobs went past
// what it requested. Pure functions, like runtimeCard, so every state's
// wording and every bar position is tested without rendering.

import type { RuntimeMemory } from '@/lib/api';
import { formatMiB } from '@/lib/utilization';

import type { BarGeometry } from './runtimeCard';

// Round figures, in MiB, a memory axis can end on. Past the last, whole
// multiples of it.
const NICE_MIB = [
  128, 256, 512, 1024, 1536, 2048, 3072, 4096, 6144, 8192, 12288, 16384, 24576, 32768, 49152, 65536, 98304, 131072,
];

// niceMiB is the smallest round figure at or past mib.
export function niceMiB(mib: number): number {
  if (!Number.isFinite(mib) || mib <= NICE_MIB[0]) return NICE_MIB[0];
  for (const n of NICE_MIB) if (n >= mib) return n;
  const last = NICE_MIB[NICE_MIB.length - 1];
  return Math.ceil(mib / last) * last;
}

// How far past the usual range the axis stretches to reach the job's
// peak, as the run time card does for elapsed time: past this the peak's
// fill stops at the end of the axis and the text carries the figure.
const PEAK_REACH = 4;

// memoryAxisMax is where the bar's axis ends: comfortably past the
// usual range and the job's peak, on a round figure.
export function memoryAxisMax(m: Pick<RuntimeMemory, 'p50_mib' | 'p90_mib'>, peak?: number): number {
  const usual = Math.max(m.p50_mib, m.p90_mib);
  const reach = peak === undefined ? 0 : usual > 0 ? Math.min(peak, usual * PEAK_REACH) : peak;
  return niceMiB(Math.max(usual, reach) * 1.2);
}

// memoryRangeText is the usual range, or undefined when its ends read as
// one figure. A rough group's range says so.
export function memoryRangeText(m: Pick<RuntimeMemory, 'p10_mib' | 'p90_mib' | 'rough'>): string | undefined {
  const lo = formatMiB(m.p10_mib);
  const hi = formatMiB(m.p90_mib);
  if (lo === hi) return undefined;
  return m.rough ? `anywhere from ${lo} to ${hi}` : `usually ${lo} to ${hi}`;
}

// requestLine is how many similar jobs peaked above what this job
// requests, as a count; undefined without a request.
export function requestLine(m: RuntimeMemory): string | undefined {
  if (m.requested_mib === undefined || m.above_requested === undefined) return undefined;
  const req = formatMiB(m.requested_mib);
  const n = m.above_requested;
  const total = m.sample_count;
  if (total === 1) {
    return n === 0
      ? `The one similar job stayed under the ${req} requested.`
      : `The one similar job peaked above the ${req} requested.`;
  }
  if (n === 0) return `All ${total.toLocaleString()} similar jobs stayed under the ${req} requested.`;
  if (n === total) return `All ${total.toLocaleString()} similar jobs peaked above the ${req} requested.`;
  return `${n.toLocaleString()} of ${total.toLocaleString()} similar jobs peaked above the ${req} requested.`;
}

// MemoryCard is everything the card shows.
export interface MemoryCard {
  // A running job already past what nearly every similar job peaked at:
  // amber, with its own chip.
  above: boolean;
  rough: boolean;
  headline: string;
  bar: BarGeometry;
  axis: { left: string; middle?: string; right: string };
  // Sentences under the bar, in order.
  lines: string[];
}

const frac = (v: number, max: number) => Math.min(1, Math.max(0, v / max));

// memoryCard is what the job page shows for an estimate's memory, or
// null when there is none. status is the job's: waiting (1) and running
// (2) compare with the request, finished (3, 4) with what similar jobs
// peaked at; anything else shows nothing.
export function memoryCard(m: RuntimeMemory | undefined, status: number | undefined): MemoryCard | null {
  if (!m || m.sample_count <= 0) return null;
  const live = status === 1 || status === 2;
  if (!live && status !== 3 && status !== 4) return null;
  const rough = !!m.rough;
  const about = rough ? 'roughly' : 'about';
  const typical = formatMiB(m.p50_mib);
  // A waiting job has used nothing yet.
  const peak = status === 1 ? undefined : m.peak_mib;
  const max = memoryAxisMax(m, peak);
  const range = memoryRangeText(m);
  const bar: BarGeometry = { tick: frac(m.p50_mib, max) };
  if (range !== undefined) bar.band = { from: frac(m.p10_mib, max), to: frac(m.p90_mib, max) };
  if (peak !== undefined) {
    bar.elapsed = frac(peak, max);
    if (peak > max) bar.elapsedCapped = true;
  }
  const axis = {
    left: '0',
    middle: range,
    right: bar.elapsedCapped ? `peak ${formatMiB(peak!)}` : formatMiB(max),
  };
  const peers = `Similar jobs peaked at ${about} ${typical}; 9 in 10 stayed under ${formatMiB(m.p90_mib)}.`;
  const req = live ? requestLine(m) : undefined;
  const above = status === 2 && m.above_usual;

  if (peak === undefined) {
    return {
      above: false,
      rough,
      headline: `Similar jobs ${live ? 'peak' : 'peaked'} at ${about} ${typical}`,
      bar,
      axis,
      lines: req ? [req] : [],
    };
  }
  return {
    above,
    rough,
    headline: status === 2 ? `Peak so far ${formatMiB(peak)}` : `Peaked at ${formatMiB(peak)}`,
    bar,
    axis,
    lines: req ? [peers, req] : [peers],
  };
}
