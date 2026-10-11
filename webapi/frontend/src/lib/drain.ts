// "If this node were drained now, when would it be empty?" -- the types
// of GET /api/v1/pool/drain-estimates and the pure helpers that turn it
// into the Pool page's words. Mirrors webapi/drainest; renames on the Go
// side must update this in lockstep.
//
// Seconds in the response count from generated_at; every helper here
// takes the response's age_seconds and subtracts it, so a cached answer
// does not read a minute later than it is.

export interface DrainExpectedEnd {
  seconds: number;
  usually_by_seconds: number;
  cpus: number;
}

export interface DrainSlot {
  name: string;
  owner?: string;
  cpus: number;
  backfill?: boolean;
  submitted_from?: string;
  from_this_ap: boolean;
  running_seconds?: number;
  expected_end?: string;
  usually_by?: string;
  exceeded: boolean;
  retirement_deadline?: string;
  evicted_on_drain: boolean;
}

export interface MachineDrain {
  machine: string;
  draining: boolean;
  jobs_total: number;
  jobs_estimated: number;
  jobs_from_this_ap: number;
  jobs_unknown_end: number;
  jobs_unknown_from_other_aps: number;
  likely_empty_seconds?: number;
  likely_empty_at?: string;
  at_least_seconds?: number;
  at_most_seconds?: number;
  at_most_at?: string;
  unknown_up_to_seconds?: number;
  evicted_on_drain: number;
  exceeded: number;
  expected_ends?: DrainExpectedEnd[];
  slots?: DrainSlot[];
}

export interface DrainSummary {
  machines: number;
  jobs_running: number;
  jobs_estimated: number;
  jobs_from_this_ap: number;
  cores_freeing_next_hour: number;
  draining_nodes: number;
  draining_likely_empty_within_2h: number;
}

export interface DrainEstimates {
  generated_at: string;
  age_seconds: number;
  stale: boolean;
  error?: string;
  estimates_available: boolean;
  access_point?: string;
  summary: DrainSummary;
  machines: MachineDrain[];
}

const MINUTE = 60;
const HOUR = 3600;
const DAY = 86400;

// left is a server figure in seconds, less the answer's age.
function left(seconds: number | undefined, age: number): number | undefined {
  if (seconds === undefined) return undefined;
  return Math.max(0, seconds - age);
}

// drainDuration renders a length of time the way the column speaks:
// "40m", "2h10m", "1 day 5h", "3 days". Rounded to what it can honestly
// claim -- minutes under a day, hours under two, days beyond.
export function drainDuration(seconds: number): string {
  const s = Math.max(0, Math.round(seconds));
  if (s < MINUTE) return 'under a minute';
  if (s < HOUR) return `${Math.round(s / MINUTE)}m`;
  if (s < DAY) {
    const total = Math.round(s / MINUTE);
    const h = Math.floor(total / 60);
    const m = total % 60;
    if (h >= 24) return '1 day';
    return m === 0 ? `${h}h` : `${h}h${String(m).padStart(2, '0')}m`;
  }
  if (s < 2 * DAY) {
    const h = Math.round((s - DAY) / HOUR);
    return h === 0 || h === 24 ? (h === 24 ? '2 days' : '1 day') : `1 day ${h}h`;
  }
  return `${Math.round(s / DAY)} days`;
}

// clockTime renders a moment relative to now: "5:20 PM" today,
// "Mon 8:10 AM" within the week, "Oct 20 8:10 AM" beyond.
export function clockTime(at: Date, now: Date): string {
  const time = at.toLocaleTimeString(undefined, { hour: 'numeric', minute: '2-digit' });
  if (at.toDateString() === now.toDateString()) return time;
  const days = (at.getTime() - now.getTime()) / (DAY * 1000);
  if (days >= 0 && days < 6) {
    return `${at.toLocaleDateString(undefined, { weekday: 'short' })} ${time}`;
  }
  return `${at.toLocaleDateString(undefined, { month: 'short', day: 'numeric' })} ${time}`;
}

function plural(n: number, one: string, many: string): string {
  return `${n.toLocaleString()} ${n === 1 ? one : many}`;
}

// DrainCell is one node's "Empty if drained now" cell.
export interface DrainCell {
  // primary is the headline: "About 2h10m", "At least 1h30m", ...
  primary: string;
  // detail is the muted line under it; empty when there is nothing to add.
  detail: string;
  // warning, when set, is shown in amber after the detail.
  warning?: string;
}

function evictedPart(m: MachineDrain): string {
  return m.evicted_on_drain > 0
    ? `${plural(m.evicted_on_drain, 'job', 'jobs')} would be evicted`
    : '';
}

function exceededPart(m: MachineDrain): string | undefined {
  if (m.exceeded <= 0) return undefined;
  return m.exceeded === 1
    ? '1 job is running longer than usual'
    : `${m.exceeded.toLocaleString()} jobs are running longer than usual`;
}

function join(...parts: string[]): string {
  return parts.filter(Boolean).join(' · ');
}

function lowerFirst(s: string): string {
  return s.charAt(0).toLowerCase() + s.slice(1);
}

// unknownPart describes the jobs nobody can say the end of.
function unknownPart(m: MachineDrain, upTo: number | undefined): string {
  const n = m.jobs_unknown_end;
  const who =
    m.jobs_unknown_from_other_aps === n
      ? `${n.toLocaleString()} from ${n === 1 ? 'another access point' : 'other access points'}`
      : `${n.toLocaleString()} without an estimate`;
  if (upTo === undefined) return `${who} ${n === 1 ? 'has' : 'have'} no time limit`;
  return `${who} could run up to ${drainDuration(upTo)}`;
}

// drainCell is the text for one node. m is undefined for a node the
// answer does not list, which has nothing running.
export function drainCell(
  m: MachineDrain | undefined,
  age: number,
  now: Date,
): DrainCell {
  const cell = drainCellBody(m, age, now);
  if (m?.draining && m.jobs_total > 0) {
    cell.primary = `Draining · ${lowerFirst(cell.primary)}`;
  }
  return cell;
}

function drainCellBody(m: MachineDrain | undefined, age: number, now: Date): DrainCell {
  if (!m || m.jobs_total === 0) {
    return { primary: m?.draining ? 'Drained' : 'Empty now', detail: '' };
  }
  const likely = left(m.likely_empty_seconds, age);
  const upTo = left(m.unknown_up_to_seconds ?? m.at_most_seconds, age);
  const warning = exceededPart(m);

  // Every job's end is known.
  if (m.jobs_unknown_end === 0 && likely !== undefined) {
    const allEstimated =
      m.jobs_estimated === m.jobs_total
        ? m.jobs_total === 1
          ? 'its 1 job estimated'
          : `all ${m.jobs_total.toLocaleString()} jobs estimated`
        : '';
    if (likely < MINUTE) {
      return { primary: 'Empty in seconds', detail: join(evictedPart(m) || allEstimated), warning };
    }
    const by = m.likely_empty_at ? `likely by ${clockTime(new Date(m.likely_empty_at), now)}` : '';
    return {
      primary: `About ${drainDuration(likely)}`,
      detail: join(by, m.evicted_on_drain > 0 ? evictedPart(m) : allEstimated),
      warning,
    };
  }

  // Some ends are known, some are not: a lower bound.
  const atLeast = left(m.at_least_seconds, age);
  if (atLeast !== undefined && atLeast >= MINUTE) {
    return {
      primary: `At least ${drainDuration(atLeast)}`,
      detail: join(
        `${m.jobs_estimated.toLocaleString()} of ${plural(m.jobs_total, 'job', 'jobs')} estimated`,
        unknownPart(m, upTo),
        evictedPart(m),
      ),
      warning,
    };
  }

  // Nothing useful is known about when the rest end.
  if (warning) {
    return {
      primary: 'Unclear',
      detail: join(upTo !== undefined ? `could run up to ${drainDuration(upTo)}` : '', evictedPart(m)),
      warning,
    };
  }
  const detail =
    m.jobs_unknown_from_other_aps === m.jobs_unknown_end
      ? m.jobs_unknown_end === 1
        ? 'a job from another access point'
        : 'jobs from other access points'
      : `no estimate for ${plural(m.jobs_unknown_end, 'job', 'jobs')}`;
  return {
    primary: upTo !== undefined ? `Up to ${drainDuration(upTo)}` : 'No time limit',
    detail: join(detail, evictedPart(m)),
  };
}

// SlotEnd is one running job's "Expected end" cell in the expanded node.
export interface SlotEnd {
  primary: string;
  detail: string;
  warning?: string;
}

export function slotEnd(s: DrainSlot, now: Date): SlotEnd {
  const limit = s.retirement_deadline ? new Date(s.retirement_deadline) : undefined;
  const evicted = 'evicted if drained now';
  if (s.expected_end) {
    const usually = s.usually_by ? `usually by ${clockTime(new Date(s.usually_by), now)}` : '';
    return {
      primary: `~${clockTime(new Date(s.expected_end), now)}`,
      detail: join(usually, s.evicted_on_drain ? evicted : ''),
    };
  }
  const limitPart = s.evicted_on_drain
    ? evicted
    : limit
      ? `retirement limit ${clockTime(limit, now)}`
      : '';
  if (s.exceeded) {
    return { primary: '', detail: limitPart, warning: 'Running longer than usual' };
  }
  return { primary: 'No estimate', detail: limitPart };
}

export function submittedFrom(s: DrainSlot): string {
  if (s.from_this_ap) return 'this access point';
  return s.submitted_from || '—';
}

// DrainTotals is the summary cards' figures for the nodes in view.
export interface DrainTotals {
  jobsRunning: number;
  jobsEstimated: number;
  coresFreeingNextHour: number;
  drainingNodes: number;
  drainingLikelyEmptyWithin2h: number;
}

// drainTotals adds up the nodes in view, so the cards follow the page's
// filter. A node's estimated jobs count toward the next hour when they
// are expected to finish on their own within it.
export function drainTotals(machines: MachineDrain[], age: number): DrainTotals {
  const t: DrainTotals = {
    jobsRunning: 0,
    jobsEstimated: 0,
    coresFreeingNextHour: 0,
    drainingNodes: 0,
    drainingLikelyEmptyWithin2h: 0,
  };
  for (const m of machines) {
    t.jobsRunning += m.jobs_total;
    t.jobsEstimated += m.jobs_estimated;
    for (const e of m.expected_ends ?? []) {
      if (e.seconds - age <= HOUR) t.coresFreeingNextHour += e.cpus;
    }
    if (m.draining) {
      t.drainingNodes++;
      const likely = left(m.likely_empty_seconds, age);
      if (m.jobs_unknown_end === 0 && likely !== undefined && likely <= 2 * HOUR) {
        t.drainingLikelyEmptyWithin2h++;
      }
    }
  }
  return t;
}

// The timeline: a node's next six hours.
export const TIMELINE_SECONDS = 6 * HOUR;

export interface TimelineMarks {
  // ticks are estimated jobs' expected ends, as fractions of the window;
  // bands their usual range (expected end to usually-by), clipped.
  ticks: number[];
  bands: { from: number; to: number }[];
  // unknown is how far the jobs without a known end may run, as a
  // fraction (1 when past the window); undefined when there are none.
  unknown?: number;
  // beyond labels an unknown band that runs past the window: "3 days".
  beyond?: string;
  exceeded: boolean;
}

export function timelineMarks(m: MachineDrain, age: number): TimelineMarks {
  const frac = (s: number) => Math.min(1, Math.max(0, s / TIMELINE_SECONDS));
  const marks: TimelineMarks = { ticks: [], bands: [], exceeded: m.exceeded > 0 };
  for (const e of m.expected_ends ?? []) {
    const end = Math.max(0, e.seconds - age);
    const usually = Math.max(end, e.usually_by_seconds - age);
    if (end <= TIMELINE_SECONDS) marks.ticks.push(frac(end));
    if (end < TIMELINE_SECONDS) marks.bands.push({ from: frac(end), to: frac(usually) });
  }
  if (m.jobs_unknown_end > 0) {
    const upTo = left(m.unknown_up_to_seconds ?? m.at_most_seconds, age);
    if (upTo === undefined) {
      marks.unknown = 1;
    } else {
      marks.unknown = frac(upTo);
      if (upTo > TIMELINE_SECONDS) marks.beyond = drainDuration(upTo);
    }
  }
  return marks;
}

// byMachine indexes an answer's machines case-insensitively, as ClassAd
// names compare.
export function byMachine(machines: MachineDrain[] | undefined): Map<string, MachineDrain> {
  const out = new Map<string, MachineDrain>();
  for (const m of machines ?? []) out.set(m.machine.toLowerCase(), m);
  return out;
}
