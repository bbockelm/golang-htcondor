'use client';

import { useEffect, useState } from 'react';

// useNowTick returns the current Unix-epoch *seconds* and re-renders
// the calling component every `intervalMs`. Used to keep the
// "12h3m ago"-style relative-time strings on the detail page roughly
// accurate without an explicit refetch.
export function useNowTick(intervalMs: number): number {
  const [now, setNow] = useState(() => Math.floor(Date.now() / 1000));
  useEffect(() => {
    const id = setInterval(
      () => setNow(Math.floor(Date.now() / 1000)),
      intervalMs,
    );
    return () => clearInterval(id);
  }, [intervalMs]);
  return now;
}
