'use client';

// The issues page's two dials, remembered.
//
// Both are questions a facilitator answers once for how they work, not
// once per visit: somebody who watches the last hour and wants problems
// split finely is going to want that again tomorrow. Stored the same way
// as the listing scope (lib/preference.ts), so they survive a reload and
// agree across tabs.

import {
  createBoolPreference,
  createNumberPreference,
  useBoolPreference,
  useNumberPreference,
} from '@/lib/preference';

// The windows offered. Anything the server accepts would work, but a row
// of buttons is faster to use than a number field and these are the
// spans people actually ask for: the shift they are on, the working day,
// yesterday, the week.
export const ISSUE_WINDOWS = [
  { label: '1h', seconds: 3600 },
  { label: '8h', seconds: 8 * 3600 },
  { label: '24h', seconds: 24 * 3600 },
  { label: '3d', seconds: 3 * 24 * 3600 },
  { label: '7d', seconds: 7 * 24 * 3600 },
] as const;

const DEFAULT_WINDOW = 24 * 3600;

// A stored value that is not one of the offered windows would leave every
// button unselected, so it snaps to the nearest one instead.
function nearestWindow(seconds: number): number {
  let best: { label: string; seconds: number } = ISSUE_WINDOWS[0];
  for (const w of ISSUE_WINDOWS) {
    if (Math.abs(w.seconds - seconds) < Math.abs(best.seconds - seconds)) {
      best = w;
    }
  }
  return best.seconds;
}

const windowPref = createNumberPreference(
  'htcondor.issueWindow',
  DEFAULT_WINDOW,
  nearestWindow,
);

// Granularity runs 0 (coarsest) to 1 (finest). The middle is the default
// because both ends are useful and neither is where you want to start.
const granularityPref = createNumberPreference(
  'htcondor.issueGranularity',
  0.5,
  (v) => Math.min(1, Math.max(0, Math.round(v * 20) / 20)),
);

// Reading run-attempt history is what turns "what is stuck" into "what
// has gone wrong", and it is the expensive half. On by default because
// the page is close to useless without it on an access point where jobs
// are retried rather than held.
const includeEndedPref = createBoolPreference('htcondor.issueIncludeEnded', true);

export function useIssueWindow(): [number, (next: number) => void] {
  return useNumberPreference(windowPref);
}

export function useIssueGranularity(): [number, (next: number) => void] {
  return useNumberPreference(granularityPref);
}

export function useIssueIncludeEnded(): [boolean, (next: boolean) => void] {
  return useBoolPreference(includeEndedPref);
}
