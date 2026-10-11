// What the job page's run time card says and draws for a waiting or
// running job's estimate. Pure functions, so every state's wording and
// every bar position is tested without rendering.

import type { RuntimeEstimate, RuntimeEstimateLevel } from '@/lib/api';
import { approxDuration } from '@/lib/duration';

// What each basis compared the job with. [singular, plural]; null for a
// basis that carries no count worth printing.
const basisText: Record<RuntimeEstimateLevel, [string, string] | null> = {
  cluster: ['from 1 finished job in this cluster', 'from N finished jobs in this cluster'],
  exact: [
    'from 1 earlier job with the same command and arguments',
    'from N of your earlier jobs with the same command and arguments',
  ],
  template: [
    'from 1 earlier job with the same command and argument pattern',
    'from N of your earlier jobs with the same command and argument pattern',
  ],
  batch: ['from 1 earlier job in the same batch', 'from N of your earlier jobs in the same batch'],
  iwd: [
    'from 1 earlier job from the same submit directory',
    'from N of your earlier jobs from the same submit directory',
  ],
  cmd: [
    'from 1 earlier job running the same program',
    'from N of your earlier jobs running the same program',
  ],
  owner: null,
  global: null,
};

// basisLine says what the estimate was drawn from. The two broadest
// bases say why nothing closer answered when that is known: a rough
// guess should say what it is a guess from.
export function basisLine(basis: RuntimeEstimate['basis']): string | undefined {
  if (!basis) return undefined;
  if (basis.level === 'owner') {
    return basis.new_command
      ? 'This command has not run recently. Based on your recent jobs in general.'
      : 'Based on your recent jobs in general.';
  }
  if (basis.level === 'global') {
    return 'You have no recently finished jobs to compare with. Based on recent jobs on this access point.';
  }
  const text = basisText[basis.level];
  if (!text) return undefined;
  return basis.sample_count === 1
    ? text[0]
    : text[1].replace('N', String(basis.sample_count));
}

// rangeText is the likely range, or undefined when it would read as a
// single figure ("1h to 1h"). A rough guess's range is wide and says so.
export function rangeText(
  r: Pick<RuntimeEstimate, 'p10_seconds' | 'p90_seconds' | 'rough'>,
): string | undefined {
  if (r.p10_seconds === undefined || r.p90_seconds === undefined) return undefined;
  const lo = approxDuration(r.p10_seconds);
  const hi = approxDuration(r.p90_seconds);
  if (lo === hi) return undefined;
  return r.rough ? `anywhere from ${lo} to ${hi}` : `usually ${lo} to ${hi}`;
}

// sentence turns a basis fragment ("from 12 finished jobs in this
// cluster") into a sentence of its own.
export function sentence(s: string | undefined): string | undefined {
  if (!s) return undefined;
  const t = s.charAt(0).toUpperCase() + s.slice(1);
  return /[.!?]$/.test(t) ? t : `${t}.`;
}

// Round durations an axis can end on. Past the last, whole weeks.
const NICE_SECONDS = [
  60, 120, 300, 600, 900, 1200, 1800, 2700,
  3600, 5400, 7200, 10800, 14400, 18000, 21600, 28800, 36000, 43200, 57600,
  86400, 129600, 172800, 259200, 345600, 432000, 604800,
];

// niceDuration is the smallest round duration at or past s.
export function niceDuration(s: number): number {
  if (!Number.isFinite(s) || s <= 60) return 60;
  for (const n of NICE_SECONDS) if (n >= s) return n;
  return Math.ceil(s / 604800) * 604800;
}

// How far past the usual range the axis stretches to reach the elapsed
// time. A job ten times over would otherwise squash the usual range into
// a sliver at the left; past this the elapsed fill stops at the end of
// the axis and the text carries the real figure.
const ELAPSED_REACH = 4;

// axisMax is where the bar's axis ends: comfortably past the usual
// range and the time the job has run so far, on a round figure.
export function axisMax(r: Pick<RuntimeEstimate, 'estimate_seconds' | 'p90_seconds' | 'elapsed_seconds'>): number {
  const usual = Math.max(r.estimate_seconds ?? 0, r.p90_seconds ?? 0);
  const elapsed = r.elapsed_seconds ?? 0;
  const reach = usual > 0 ? Math.min(elapsed, usual * ELAPSED_REACH) : elapsed;
  return niceDuration(Math.max(usual, reach) * 1.2);
}

// BarGeometry is the range bar as fractions of its width, 0..1.
export interface BarGeometry {
  // The usual range; absent when there is none to draw.
  band?: { from: number; to: number };
  tick: number;
  // How long the job has run so far, for a running job.
  elapsed?: number;
  // The elapsed time ran past the end of the axis and was cut there.
  elapsedCapped?: boolean;
}

const frac = (s: number, max: number) => Math.min(1, Math.max(0, s / max));

// barGeometry places the band, tick and elapsed fill on an axis from 0
// to max seconds. A band whose ends round to the same figure is no
// range, so it is not drawn (the text does not print one either).
export function barGeometry(r: RuntimeEstimate, max: number, running: boolean): BarGeometry {
  const g: BarGeometry = { tick: frac(r.estimate_seconds ?? 0, max) };
  if (rangeText(r) !== undefined) {
    g.band = { from: frac(r.p10_seconds!, max), to: frac(r.p90_seconds!, max) };
  }
  if (running && r.elapsed_seconds !== undefined) {
    g.elapsed = frac(r.elapsed_seconds, max);
    if (r.elapsed_seconds > max) g.elapsedCapped = true;
  }
  return g;
}

// clockParts splits a time of day as people say it into its day ("" for
// today, "Tue" this week, "Oct 20," after that) and its time ("3:40 PM").
// More than an hour from now it is rounded to five minutes: the figure
// is approximate, and "4:37 PM" would claim otherwise.
export function clockParts(
  unix: number,
  now: number,
  locale?: string,
): { day: string; time: string } {
  const step = Math.abs(unix - now) > 3600 ? 300 : 60;
  const d = new Date(Math.round(unix / step) * step * 1000);
  const today = new Date(now * 1000);
  // Non-breaking, so a narrow label never strands the "PM".
  const time = d
    .toLocaleTimeString(locale, { hour: 'numeric', minute: '2-digit' })
    .replace(/\s/g, ' ');
  if (d.toDateString() === today.toDateString()) return { day: '', time };
  if (Math.abs(unix - now) < 6 * 86400) {
    return { day: d.toLocaleDateString(locale, { weekday: 'short' }), time };
  }
  return { day: `${d.toLocaleDateString(locale, { month: 'short', day: 'numeric' })},`, time };
}

const joinDay = (p: { day: string; time: string }) => (p.day ? `${p.day} ${p.time}` : p.time);

// clockTime is clockParts as one string: "3:40 PM", "Tue 3:40 PM".
export function clockTime(unix: number, now: number, locale?: string): string {
  return joinDay(clockParts(unix, now, locale));
}

// clockRange is two times as one span: "3:40 to 5:30 PM" when they share
// a day and a half of the day, else each in full.
export function clockRange(a: number, b: number, now: number, locale?: string): string {
  const lo = clockParts(a, now, locale);
  const hi = clockParts(b, now, locale);
  if (lo.day !== hi.day) return `${joinDay(lo)} to ${joinDay(hi)}`;
  let loTime = lo.time;
  const suffix = /[^\d]+$/.exec(hi.time)?.[0];
  if (suffix && loTime.endsWith(suffix)) loTime = loTime.slice(0, -suffix.length);
  const span = `${loTime} to ${hi.time}`;
  return lo.day ? `${lo.day} ${span}` : span;
}

// RuntimeCard is everything the card shows.
export interface RuntimeCard {
  // Running past what comparable jobs took: amber, with its own chip.
  longer: boolean;
  rough: boolean;
  headline: string;
  bar: BarGeometry;
  axis: { left: string; middle?: string; right: string };
  // Sentences under the bar, in order.
  lines: string[];
  // Offer the live output and shell actions.
  actions: boolean;
}

// runtimeCard is what the job page shows for an estimate, or null when
// it shows nothing: no estimate, or a job that is neither waiting (1)
// nor running (2). fetchedAt (unix seconds) is when the estimate was
// read; a running job's clock times count from it.
export function runtimeCard(
  r: RuntimeEstimate | undefined,
  status: number | undefined,
  fetchedAt: number,
  locale?: string,
): RuntimeCard | null {
  if (!r || !r.available || r.estimate_seconds === undefined) return null;
  if (status !== 1 && status !== 2) return null;
  const running = status === 2;
  const rough = !!r.rough;
  const total = approxDuration(r.estimate_seconds);
  const basis = sentence(basisLine(r.basis));
  const [About, about] = rough ? ['Roughly', 'roughly'] : ['About', 'about'];
  const max = axisMax(running ? r : { ...r, elapsed_seconds: undefined });
  const bar = barGeometry(r, max, running);
  const range = rangeText(r);
  const elapsed = running ? r.elapsed_seconds : undefined;

  if (running && r.exceeded_history && elapsed !== undefined) {
    const hi = r.p90_seconds !== undefined ? approxDuration(r.p90_seconds) : undefined;
    const under = hi && hi !== total ? `, nearly all under ${hi}` : '';
    const now = `now: ${approxDuration(elapsed)}`;
    return {
      longer: true,
      rough,
      headline: `Similar jobs took ${about} ${total}${under}`,
      bar,
      axis: bar.elapsedCapped
        ? { left: '0', right: now }
        : { left: '0', middle: now, right: approxDuration(max) },
      lines: [
        'It may be stuck, or this input may need more work than usual.',
        ...(basis ? [basis] : []),
      ],
      actions: true,
    };
  }

  if (running && elapsed !== undefined) {
    const start = fetchedAt - elapsed;
    const spent = `Running ${approxDuration(elapsed)} of ${about} ${total}.`;
    const middle =
      range && r.p10_seconds !== undefined && r.p90_seconds !== undefined
        ? `${rough ? 'done anywhere from' : 'usually done'} ${clockRange(start + r.p10_seconds, start + r.p90_seconds, fetchedAt, locale)}`
        : undefined;
    const headline =
      r.remaining_seconds !== undefined
        ? `${About} ${approxDuration(r.remaining_seconds)} left · ${rough ? 'perhaps' : 'likely'} done around ${clockTime(fetchedAt + r.remaining_seconds, fetchedAt, locale)}`
        : `${About} ${total} in all`;
    return {
      longer: false,
      rough,
      headline,
      bar,
      axis: {
        left: `started ${clockTime(start, fetchedAt, locale)}`,
        middle,
        right: clockTime(start + max, fetchedAt, locale),
      },
      lines: [basis ? `${spent} ${basis}` : spent],
      actions: false,
    };
  }

  const waiting = 'Time spent waiting to start depends on the pool and is not included.';
  return {
    longer: false,
    rough,
    // A rough guess is a figure, not a promise about the run.
    headline: running || rough ? `${About} ${total}` : `${About} ${total} once it starts`,
    bar,
    axis: { left: '0', middle: range, right: approxDuration(max) },
    lines: running ? (basis ? [basis] : []) : [basis ? `${basis} ${waiting}` : waiting],
    actions: false,
  };
}
