// Shared status interpretation for interactive jobs (Jupyter + Terminal).
//
// Both detail pages and both list views run the same job ad through
// `interpretJobStatus()` so the same condition produces the same label,
// pill, and banner everywhere. The labels and banners we render off the
// returned status are deliberately phrased neutrally enough to apply to
// either job type — when the type-specific phrasing matters (e.g.
// "JupyterLab is initializing"), the caller wraps the status with its
// own copy.

import type { ClassAd } from '@/lib/api';

export type Status =
  | 'loading' // SPA hasn't loaded the job ad yet
  | 'spooling' // schedd is spooling input files (transient hold)
  | 'idle' // JobStatus=1, waiting to be matched to an execute node
  | 'transferring_input' // JobStatus=2, but the executable hasn't started yet
  | 'executing' // JobStatus=2 + JobCurrentStartExecutingDate set
  | 'launching' // helper / shell process is up; user-side bring-up in progress
  | 'ready' // user can interact (iframe mounted, terminal attached)
  | 'held' // schedd put the job on hold for a real reason
  | 'closed' // job completed normally / session ended
  | 'removed' // condor_rm'd
  | 'gone' // we don't know about this job (404)
  | 'error'; // generic load failure

// HTCondor's HoldReasonCode 16 == "Spooling input data files". This is
// the schedd's normal pause-while-we-upload state, not a real hold.
export const HOLD_REASON_SPOOLING_INPUT = 16;

interface InterpretInputs {
  // Job ad polled from /api/v1/jobs/{id}. May be undefined while the
  // first fetch is still in flight.
  job?: ClassAd | null;
  // For Jupyter: whether the helper has dialed back the websocket
  // tunnel. Undefined for terminal jobs (no helper concept).
  helperConnected?: boolean;
  // For Jupyter / Terminal: terminal user-side states the caller may
  // already know about (e.g. SSE flipped us to "ready"). Pass through
  // so the helper doesn't downgrade us when the job ad hasn't caught
  // up yet.
  override?: Status;
}

/**
 * Map a job ad + side-channel signals to one of the Status values.
 * Pure: callers can call this from useEffect / useMemo / list rows
 * alike without coupling to react-query or other state machinery.
 */
export function interpretJobStatus(inp: InterpretInputs): Status {
  if (inp.override === 'ready' || inp.override === 'closed' || inp.override === 'launching') {
    return inp.override;
  }
  // Helper has dialed back but the job ad doesn't know yet (or wasn't
  // queried). Treat as "launching" — the user-visible iframe / pty is
  // about to come up.
  if (inp.helperConnected === true) {
    return 'launching';
  }
  if (!inp.job) {
    return 'loading';
  }
  const s = num(inp.job.JobStatus);
  switch (s) {
    case 1:
      return 'idle';
    case 2:
      // JobCurrentStartExecutingDate is set when the executable
      // actually started running, after any docker pull or input
      // transfer. JobStatus=2 with this UNDEFINED means we're still
      // in the pre-execution phase.
      return num(inp.job.JobCurrentStartExecutingDate)
        ? 'executing'
        : 'transferring_input';
    case 3:
      return 'removed';
    case 4:
      return 'closed';
    case 5:
      // Distinguish the "spooling input files" transient hold from a
      // real hold. The spool finishes within seconds for our small
      // submits; surfacing red "Held" briefly is alarming.
      if (num(inp.job.HoldReasonCode) === HOLD_REASON_SPOOLING_INPUT) {
        return 'spooling';
      }
      return 'held';
    case 6:
      return 'closed';
    default:
      return inp.job ? 'idle' : 'loading';
  }
}

/**
 * visualStatus is the "what color is the pill?" projection of a Status,
 * remapping job-kind-specific cases so the green/Ready presentation is
 * used consistently when the session is actually usable by the user.
 *
 * For interactive terminal sessions, JobStatus=2 with
 * JobCurrentStartExecutingDate set (= our 'executing' Status) means
 * the executable is up and the SSH bridge can attach immediately —
 * indistinguishable from "ready" from the user's POV. We don't have
 * a separate readiness signal to wait for (no helper protocol like
 * Jupyter has), and "Executing" / amber is misleading: nothing more
 * is going to happen before the user can use it.
 *
 * For Jupyter we DON'T remap here — the detail page and list both
 * arrive at 'ready' via useJupyterReadyProbe, after JupyterLab has
 * confirmed it's serving. Until then 'launching' (amber) is honest.
 *
 * Pass the literal kind ('terminal' | 'jupyter') at the render site
 * where you know which one it is. Callers who don't have a kind
 * (e.g. the generic /jobs list) can omit it and get the raw Status.
 */
export function visualStatus(status: Status, kind?: 'jupyter' | 'terminal'): Status {
  if (kind === 'terminal' && status === 'executing') {
    return 'ready';
  }
  return status;
}

/**
 * Short label suitable for status pills and table cells. The detail
 * page can override the banner text with type-specific phrasing.
 */
export function statusLabel(status: Status): string {
  switch (status) {
    case 'loading':
      return 'Loading';
    case 'spooling':
      return 'Spooling';
    case 'idle':
      return 'Idle';
    case 'transferring_input':
      return 'Transferring input';
    case 'executing':
      return 'Executing';
    case 'launching':
      return 'Launching';
    case 'ready':
      return 'Ready';
    case 'held':
      return 'Held';
    case 'closed':
      return 'Closed';
    case 'removed':
      return 'Removed';
    case 'gone':
      return 'Unavailable';
    case 'error':
      return 'Error';
  }
}

/**
 * Tailwind classes for the status pill background + text + dot, keyed
 * by status. The "spinner" cases (status that means "still working")
 * use animate-pulse on the dot.
 */
export interface StatusPillStyle {
  badge: string; // outer span class
  dot: string; // inner indicator-dot class (empty = no dot)
}

export function statusPillStyle(status: Status): StatusPillStyle {
  // Bucket statuses into 4 visual styles: in-progress (amber spinner),
  // success (green), neutral/done (gray), failure (red).
  switch (status) {
    case 'ready':
      return {
        badge:
          'inline-flex items-center gap-1.5 rounded-full bg-green-100 px-2 py-0.5 text-xs font-medium text-green-800',
        dot: 'h-1.5 w-1.5 rounded-full bg-green-600',
      };
    case 'idle':
      return {
        badge:
          'inline-flex items-center gap-1.5 rounded-full bg-blue-100 px-2 py-0.5 text-xs font-medium text-blue-800',
        dot: 'h-1.5 w-1.5 rounded-full bg-blue-600',
      };
    case 'spooling':
    case 'transferring_input':
    case 'executing':
    case 'launching':
    case 'loading':
      return {
        badge:
          'inline-flex items-center gap-1.5 rounded-full bg-amber-100 px-2 py-0.5 text-xs font-medium text-amber-800',
        dot: 'h-1.5 w-1.5 rounded-full bg-amber-500 animate-pulse',
      };
    case 'held':
    case 'gone':
    case 'error':
      return {
        badge:
          'inline-flex items-center gap-1.5 rounded-full bg-red-100 px-2 py-0.5 text-xs font-medium text-red-800',
        dot: '',
      };
    case 'removed':
    case 'closed':
      return {
        badge:
          'inline-flex items-center gap-1.5 rounded-full bg-gray-100 px-2 py-0.5 text-xs font-medium text-gray-700',
        dot: '',
      };
  }
}

function num(v: unknown): number | undefined {
  if (typeof v === 'number') return v;
  if (typeof v === 'string') {
    const n = Number(v);
    if (!Number.isNaN(n)) return n;
  }
  return undefined;
}
