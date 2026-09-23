// A yes/no display preference that survives reloads and agrees across
// tabs.
//
// The pattern is lib/scope.ts's, generalized: the value lives in
// localStorage rather than React state so it outlives the page view, and
// it is read through useSyncExternalStore rather than an effect. That
// matters for two reasons — this app is a static export, so the
// pre-rendered HTML cannot know the stored value and a naive read during
// render would be a hydration mismatch; and useSyncExternalStore gives
// cross-tab agreement for free through the storage event.
//
// These are display preferences, never authorization inputs: the server
// decides what a session may see whatever is stored here.

'use client';

import { useSyncExternalStore } from 'react';

export interface BoolPreference {
  subscribe: (onChange: () => void) => () => void;
  getSnapshot: () => boolean;
  getServerSnapshot: () => boolean;
  set: (next: boolean) => void;
}

export function createBoolPreference(
  storageKey: string,
  defaultValue = false,
): BoolPreference {
  // cached is what getSnapshot returns. useSyncExternalStore compares
  // snapshots by identity and re-renders until two agree, so this MUST
  // be a stable value rather than a fresh read of localStorage each
  // call.
  let cached: boolean | null = null;
  const listeners = new Set<() => void>();

  function read(): boolean {
    try {
      const raw = window.localStorage.getItem(storageKey);
      if (raw === null) return defaultValue;
      return raw === 'true';
    } catch {
      // Private windows and "block site data" make even reading throw.
      // A preference is not worth failing a render over.
      return defaultValue;
    }
  }

  function notify() {
    listeners.forEach((l) => l());
  }

  // Another tab writing the key fires `storage` here. Re-read rather
  // than trusting event.newValue so a removed key falls back cleanly. A
  // null key means the whole store was cleared.
  function onStorage(e: StorageEvent) {
    if (e.key !== null && e.key !== storageKey) return;
    cached = read();
    notify();
  }

  return {
    subscribe(onChange) {
      // One window listener for all subscribers, attached with the
      // first and dropped with the last.
      if (listeners.size === 0) {
        window.addEventListener('storage', onStorage);
      }
      listeners.add(onChange);
      return () => {
        listeners.delete(onChange);
        if (listeners.size === 0) {
          window.removeEventListener('storage', onStorage);
        }
      };
    },
    getSnapshot() {
      if (cached === null) cached = read();
      return cached;
    },
    // Answers for the pre-rendered HTML, which has no localStorage.
    // Returning the default keeps hydration consistent; the first
    // client snapshot then corrects it.
    getServerSnapshot: () => defaultValue,
    set(next) {
      if (cached === next) return;
      cached = next;
      try {
        window.localStorage.setItem(storageKey, String(next));
      } catch {
        // Storage refused; the choice still applies to this page view.
      }
      notify();
    },
  };
}

export function useBoolPreference(
  pref: BoolPreference,
): [boolean, (next: boolean) => void] {
  const value = useSyncExternalStore(
    pref.subscribe,
    pref.getSnapshot,
    pref.getServerSnapshot,
  );
  return [value, pref.set];
}
