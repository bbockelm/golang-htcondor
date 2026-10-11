'use client';

import { useSyncExternalStore } from 'react';

// useNarrow says whether the page is phone-width (under Tailwind's `sm`,
// 640px). Charts draw a different layout there -- a narrower viewBox, so
// their text is not scaled down to a few pixels -- and the workflows
// table becomes cards.
//
// Read through useSyncExternalStore so the pre-rendered HTML (which has
// no window) and the first client render agree: both start wide, and a
// phone corrects it on the next render.
export const NARROW_QUERY = '(max-width: 639px)';

function subscribe(onChange: () => void): () => void {
  if (typeof window === 'undefined' || !window.matchMedia) return () => {};
  const mq = window.matchMedia(NARROW_QUERY);
  mq.addEventListener('change', onChange);
  return () => mq.removeEventListener('change', onChange);
}

function getSnapshot(): boolean {
  return typeof window !== 'undefined' && !!window.matchMedia && window.matchMedia(NARROW_QUERY).matches;
}

export function useNarrow(): boolean {
  return useSyncExternalStore(subscribe, getSnapshot, () => false);
}
