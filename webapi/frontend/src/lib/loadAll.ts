// "Load the whole queue" as a remembered preference rather than a
// per-visit button press.
//
// Asking for everything once and getting a truncated list back on the
// next poll (or the next visit) is the annoying half of a bounded
// default: the user has already answered the question the truncation
// notice asks, and the page keeps re-asking it. So the answer is stored,
// and both ways of getting the rest of the queue follow from it:
//
//   - a live schedd cannot be paged, so the request asks for the
//     unlimited listing outright;
//   - an htcondordb mirror can, so useAutoLoadAll walks the cursor to
//     exhaustion, and keeps walking it after any refetch that drops
//     back to the first page.
//
// The bounded default still applies to anyone who has not asked.

'use client';

import { useEffect } from 'react';
import { createBoolPreference, useBoolPreference } from '@/lib/boolPreference';

const loadAllPref = createBoolPreference('htcondor.loadAllJobs', false);

export function useLoadAllJobs(): [boolean, (next: boolean) => void] {
  return useBoolPreference(loadAllPref);
}

// A ceiling on the cursor walk. Not a limit on how much a user may
// load -- it is the backstop against a cursor that never terminates,
// which would otherwise fetch forever. At the page sizes these listings
// use it is several hundred thousand jobs.
export const MAX_AUTO_PAGES = 500;

// useAutoLoadAll keeps pulling pages while the preference is on.
//
// Driven off react-query's own state rather than a loop: every render
// where another page exists and none is in flight starts the next one,
// which means a background refetch that resets the query to one page
// is walked forward again without the user touching anything.
export function useAutoLoadAll({
  enabled,
  hasNextPage,
  isFetching,
  pageCount,
  fetchNextPage,
}: {
  enabled: boolean;
  hasNextPage: boolean;
  // Any fetch in flight, not just a next-page one: starting a
  // next-page fetch while the first page is still loading throws away
  // the cursor the walk is supposed to follow.
  isFetching: boolean;
  pageCount: number;
  fetchNextPage: () => void;
}) {
  useEffect(() => {
    if (!enabled || !hasNextPage || isFetching) return;
    if (pageCount >= MAX_AUTO_PAGES) return;
    fetchNextPage();
  }, [enabled, hasNextPage, isFetching, pageCount, fetchNextPage]);
}
