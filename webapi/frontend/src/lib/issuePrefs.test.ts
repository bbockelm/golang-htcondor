import { beforeEach, describe, expect, it } from 'vitest';
import { ISSUE_WINDOWS } from './issuePrefs';
import { createNumberPreference } from './preference';

// The sanitizers, tested through the store the page uses. Both exist to
// stop a stored value putting the UI into a state its controls cannot
// express: an unselected row of window buttons, or a slider thumb off
// its track.

function nearestWindow(seconds: number): number {
  let best: { label: string; seconds: number } = ISSUE_WINDOWS[0];
  for (const w of ISSUE_WINDOWS) {
    if (Math.abs(w.seconds - seconds) < Math.abs(best.seconds - seconds)) best = w;
  }
  return best.seconds;
}

describe('issue window preference', () => {
  beforeEach(() => window.localStorage.clear());

  it('snaps a value that is not on the dial to the nearest one that is', () => {
    const pref = createNumberPreference('t.window', 86400, nearestWindow);
    pref.set(7200); // two hours: between the 1h and 8h buttons
    // Without this, every button renders unselected and the page looks
    // broken in a way the user cannot undo by clicking.
    expect(pref.getSnapshot()).toBe(3600);
  });

  it('survives a hand-edited or stale stored value', () => {
    window.localStorage.setItem('t.window2', 'not a number');
    expect(createNumberPreference('t.window2', 86400, nearestWindow).getSnapshot()).toBe(86400);
    window.localStorage.setItem('t.window3', '999999999');
    expect(createNumberPreference('t.window3', 86400, nearestWindow).getSnapshot()).toBe(
      ISSUE_WINDOWS[ISSUE_WINDOWS.length - 1].seconds,
    );
  });
});

describe('granularity preference', () => {
  beforeEach(() => window.localStorage.clear());
  const clamp = (v: number) => Math.min(1, Math.max(0, Math.round(v * 20) / 20));

  it('keeps the value on the slider', () => {
    const pref = createNumberPreference('t.gran', 0.5, clamp);
    pref.set(2);
    expect(pref.getSnapshot()).toBe(1);
    pref.set(-3);
    expect(pref.getSnapshot()).toBe(0);
  });

  it('snaps to the step the control offers', () => {
    // Otherwise the stored value and the rendered thumb disagree, and
    // the first nudge of the slider jumps.
    const pref = createNumberPreference('t.gran2', 0.5, clamp);
    pref.set(0.3333333);
    expect(pref.getSnapshot()).toBe(0.35);
  });
});
