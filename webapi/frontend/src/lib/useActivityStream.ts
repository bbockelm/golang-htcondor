'use client';

import { useEffect, useRef, useState } from 'react';

// The dashboard's live ticker.
//
// The activity lists on the page are a query answered when it loads.
// This is the other half -- what is happening right now -- and it comes
// from the daemon's existing mirror watch rather than from polling.
//
// The stream exists only where an htcondordb mirror does. The endpoint
// answers 501 otherwise, and this reports that as `unavailable` so the
// page can leave the panel out instead of showing one that never moves.

/** One transition. The vocabulary is closed; see jobwatch/activity.go. */
export type ActivityEvent = {
  kind: 'submitted' | 'started' | 'held' | 'released' | 'completed' | 'removed';
  cluster_id: number;
  proc_id: number;
  owner?: string;
  /** Unix seconds, when the daemon observed it. */
  at: number;
  detail?: string;
  /** How many events were lost before this one because this browser was
   *  not reading fast enough. Shown rather than hidden: a gap that looks
   *  like a quiet minute is worse than one that says it is a gap. */
  skipped?: number;
};

export type ActivityStreamState = {
  events: ActivityEvent[];
  connected: boolean;
  /** True once the server has said it has no mirror to stream from.
   *  Distinct from "not connected", which is a transient state the
   *  browser retries out of. */
  unavailable: boolean;
};

/** How many events the ticker keeps for scrollback.
 *
 *  The panel shows roughly ten at a time and scrolls; this is about ten
 *  screens of history, which is enough to look back over a burst without
 *  letting a tab left open overnight accumulate without limit. Beyond it
 *  the oldest fall off. */
const MAX_EVENTS = 100;

export function useActivityStream(ownedByMe: boolean, enabled = true): ActivityStreamState {
  // Tagged with the scope they arrived under rather than cleared when
  // the scope changes: clearing means a setState synchronously inside
  // the effect, which cascades renders. Comparing the tag at read time
  // gives the same answer in one pass. (The same shape as goneFor in
  // useJobWatch, for the same reason.)
  const [buffer, setBuffer] = useState<{ scope: boolean; events: ActivityEvent[] }>({
    scope: ownedByMe,
    events: [],
  });
  const [connected, setConnected] = useState(false);
  const [unavailable, setUnavailable] = useState(false);
  // EventSource reconnects on its own, and a 501 is not a transient
  // failure: without this the browser would retry an endpoint that will
  // never exist on this deployment, forever.
  const givenUp = useRef(false);

  useEffect(() => {
    if (!enabled) return;
    givenUp.current = false;

    const es = new EventSource(
      `/api/v1/dashboard/activity/stream?owned_by_me=${ownedByMe ? 'true' : 'false'}`,
    );

    es.addEventListener('open', () => setConnected(true));
    es.addEventListener('activity', (e) => {
      setConnected(true);
      let ev: ActivityEvent;
      try {
        ev = JSON.parse((e as MessageEvent).data);
      } catch {
        return;
      }
      setBuffer((prev) => ({
        scope: ownedByMe,
        // A scope change starts a new list: the events already held
        // describe a different set of jobs.
        events: [ev, ...(prev.scope === ownedByMe ? prev.events : [])].slice(0, MAX_EVENTS),
      }));
    });
    es.onerror = () => {
      setConnected(false);
      // EventSource cannot see the status code, only that the
      // connection failed while it was CLOSED rather than CONNECTING.
      // That distinction is how a 501 is told apart from a dropped
      // connection: the browser gives up on the former by itself.
      if (es.readyState === EventSource.CLOSED) {
        givenUp.current = true;
        setUnavailable(true);
      }
    };

    return () => {
      es.close();
      setConnected(false);
    };
  }, [ownedByMe, enabled]);

  return {
    events: buffer.scope === ownedByMe ? buffer.events : [],
    connected,
    unavailable,
  };
}
