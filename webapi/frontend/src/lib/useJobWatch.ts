'use client';

import { useEffect, useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';

import { STATUS_AD_ATTRS } from '@/lib/jobStatus';

// Follow one job over Server-Sent Events instead of polling it.
//
// The pages that wait on a job used to poll every 2-3s while it started
// and then stop: refetchInterval returned false once the job was
// running, and with refetchOnWindowFocus at its default a foregrounded
// tab never looked again. A session that was held or evicted afterwards
// read as "running" until the user tabbed away and back.
//
// The stream writes into the same react-query cache entry the page
// already reads, so nothing downstream has to know where the data came
// from. Values arrive in the shape GET /api/v1/jobs/{id} returns, so an
// update merges into the cached ad directly.

// WATCH_DISPLAY_ATTRS are what the session pages show beyond the status
// itself: the hold text, where it ran, how it ended. Requested alongside
// STATUS_AD_ATTRS so a change to either list is one edit.
const WATCH_DISPLAY_ATTRS = [
  'HoldReason',
  'RemoteHost',
  'JobCurrentStartDate',
  'CompletionDate',
  'EnteredCurrentStatus',
  'ExitCode',
  'ExitBySignal',
  'ExitSignal',
  'NumJobStarts',
  'TransferringInput',
];

export type JobWatchState = {
  // connected says the stream is open. The pages use it to decide
  // whether they still need to poll: a browser with no EventSource, a
  // proxy that buffers, or a server too old for the endpoint all end up
  // here, and polling is the answer in each case.
  connected: boolean;
  // gone says the job left the queue (removed, on its way to the
  // archive). Not the same as finished -- a completed job stays in the
  // queue for days and arrives as an ordinary update.
  gone: boolean;
};

export function useJobWatch(id: string | undefined, enabled = true): JobWatchState {
  const qc = useQueryClient();
  const [connected, setConnected] = useState(false);
  // Keyed by job id rather than reset when the effect re-runs: clearing
  // it synchronously inside the effect is a setState during render,
  // which cascades. Comparing against the current id gives the same
  // answer without the extra pass.
  const [goneFor, setGoneFor] = useState<string | null>(null);

  useEffect(() => {
    // '_' is the placeholder the static export prerenders under; there
    // is no such job and asking for it would 404 in a loop.
    if (!enabled || !id || id === '_') return;

    let closed = false;
    // Ask for the attributes this page's state machine reads, rather
    // than trusting the server's default projection to include them.
    // The two drifted once already: the default omitted
    // JobCurrentStartExecutingDate, so a running session never left
    // "Transferring input" -- the stream was healthy and carrying the
    // wrong columns.
    const attrs = [...new Set([...STATUS_AD_ATTRS, ...WATCH_DISPLAY_ATTRS])];
    const es = new EventSource(
      `/api/v1/jobs/${encodeURIComponent(id)}/watch?attrs=${encodeURIComponent(attrs.join(','))}`,
    );

    const merge = (patch: Record<string, unknown>) => {
      qc.setQueryData(['job', id], (prev: Record<string, unknown> | undefined) => {
        if (!prev) return prev;
        const next = { ...prev };
        for (const [k, v] of Object.entries(patch)) {
          // null means the attribute went away -- a hold clearing, a
          // RemoteHost disappearing when the job stops running.
          if (v === null) delete next[k];
          else next[k] = v;
        }
        return next;
      });
    };

    es.addEventListener('open', () => {
      if (!closed) setConnected(true);
    });
    es.addEventListener('snapshot', (e) => {
      if (!closed) setConnected(true);
      merge(JSON.parse((e as MessageEvent).data));
    });
    es.addEventListener('update', (e) => {
      merge(JSON.parse((e as MessageEvent).data));
    });
    es.addEventListener('gone', () => {
      setGoneFor(id);
      // Nothing further is coming; closing here stops EventSource from
      // reconnecting to an endpoint that will now 404.
      closed = true;
      es.close();
      setConnected(false);
    });
    es.onerror = () => {
      // EventSource reconnects on its own, so this is not fatal. It does
      // mean the page should not trust the stream to be carrying
      // changes right now, which is what connected=false tells it.
      if (!closed) setConnected(false);
    };

    return () => {
      closed = true;
      es.close();
      setConnected(false);
    };
  }, [id, enabled, qc]);

  return { connected, gone: goneFor !== null && goneFor === id };
}
