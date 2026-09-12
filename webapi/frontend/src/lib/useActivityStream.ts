'use client';

import { useEffect, useState } from 'react';

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
  /** Arrival order, assigned here rather than by the server: it is the
   *  React key, and nothing the event carries is unique. Two changes to
   *  one job within a second are identical in every other field. */
  seq?: number;
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

  useEffect(() => {
    if (!enabled) return;

    let stopped = false;
    let es: EventSource | null = null;
    let retry: ReturnType<typeof setTimeout> | undefined;
    // Whether this stream has ever delivered. It separates the two
    // reasons a connection can fail: an endpoint that does not exist on
    // this deployment (no mirror, answered 501) from one that worked and
    // then dropped. The first is permanent; the second must be retried,
    // and treating it as permanent is what made the ticker stop for good
    // after a while.
    let everConnected = false;
    let backoff = 1000;
    // A monotonic counter used as the React key. Keying on what an event
    // says about itself collides -- two changes to one job inside the
    // same second are equal in every field -- and React responds to
    // duplicate keys by reusing the wrong DOM node, which reads as rows
    // appearing in random places instead of a stream.
    let seq = 0;

    const connect = () => {
      if (stopped) return;
      es = new EventSource(
        `/api/v1/dashboard/activity/stream?owned_by_me=${ownedByMe ? 'true' : 'false'}`,
      );

      es.addEventListener('open', () => {
        everConnected = true;
        backoff = 1000;
        setConnected(true);
      });

      es.addEventListener('activity', (e) => {
        everConnected = true;
        setConnected(true);
        let ev: ActivityEvent;
        try {
          ev = JSON.parse((e as MessageEvent).data);
        } catch {
          return;
        }
        seq += 1;
        const keyed = { ...ev, seq };
        setBuffer((prev) => ({
          scope: ownedByMe,
          // A scope change starts a new list: the events already held
          // describe a different set of jobs.
          events: [keyed, ...(prev.scope === ownedByMe ? prev.events : [])].slice(0, MAX_EVENTS),
        }));
      });

      es.onerror = () => {
        setConnected(false);
        // CLOSED means the browser has STOPPED retrying -- it is not a
        // state it recovers from on its own, so reconnecting is ours to
        // do. CONNECTING means it is already retrying and we leave it
        // alone.
        if (es?.readyState !== EventSource.CLOSED) return;
        es.close();
        if (!everConnected) {
          // Never worked: this deployment has no mirror to stream from.
          // Retrying an endpoint that will keep answering 501 just
          // burns requests.
          setUnavailable(true);
          return;
        }
        retry = setTimeout(connect, backoff);
        backoff = Math.min(backoff * 2, 30_000);
      };
    };

    connect();

    return () => {
      stopped = true;
      if (retry) clearTimeout(retry);
      es?.close();
      setConnected(false);
    };
  }, [ownedByMe, enabled]);

  return {
    events: buffer.scope === ownedByMe ? buffer.events : [],
    connected,
    unavailable,
  };
}
