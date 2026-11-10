'use client';

import { useSyncExternalStore } from 'react';

// useMatchMedia follows a CSS media query. Read through
// useSyncExternalStore so the pre-rendered HTML (which has no window) and
// the first client render agree: both start as "no match", and a small
// screen corrects it on the next render.
export function useMatchMedia(query: string): boolean {
  return useSyncExternalStore(
    (onChange) => {
      if (typeof window === 'undefined' || !window.matchMedia) return () => {};
      const mq = window.matchMedia(query);
      mq.addEventListener('change', onChange);
      return () => mq.removeEventListener('change', onChange);
    },
    () => typeof window !== 'undefined' && !!window.matchMedia && window.matchMedia(query).matches,
    () => false,
  );
}

// Phone-width: under Tailwind's `sm`, 640px. Charts draw a narrower
// viewBox there, so their text is not scaled down to a few pixels.
export const NARROW_QUERY = '(max-width: 639px)';
export function useNarrow(): boolean {
  return useMatchMedia(NARROW_QUERY);
}

// Under Tailwind's `lg`, 1024px, the workflows table becomes cards: its
// eight columns beside a phone's or tablet's width would be mostly
// sideways scrolling. From 1024px up the table stays, scrolling inside
// its own box where a long name makes it wider than the page.
export const CARDS_QUERY = '(max-width: 1023px)';
export function useCards(): boolean {
  return useMatchMedia(CARDS_QUERY);
}
