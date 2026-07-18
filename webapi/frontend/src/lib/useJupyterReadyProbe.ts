'use client';

// useJupyterReadyProbe is the shared "is JupyterLab actually serving?"
// signal used by both the per-instance detail page and the interactive
// list rows. It exists so the two views agree on the colored status
// pill: before this hook was extracted, the detail page ran the probe
// (and could flip to "Ready" / green) while the list page only had the
// helper-connected boolean (and was stuck on "Launching" / amber even
// after JupyterLab was fully usable).
//
// Helper-connected just means the websocket tunnel between the
// browser-facing API server and the in-job helper is up — it's a
// necessary but not sufficient condition. The proxy URL goes through
// that tunnel into a UDS that JupyterLab itself owns; until the lab
// process binds the UDS and finishes startup, requests through the
// tunnel hang or 502. So a real readiness check has to actually hit
// JupyterLab and see a meaningful response.
//
// We probe `<proxy_path>/api/status` (jupyter_server's tiny readiness
// endpoint) once per second up to 60s. The first 200 (or non-401 4xx,
// which still proves the server is serving) flips the hook to ready.
// Network errors and 5xx keep us probing. After the cap we give up
// and report ready anyway — at that point JupyterLab is unlikely to
// recover, but mounting the iframe lets the user see what state it
// IS in and click Reload / End session manually. It's a UX
// compromise: false-ready is less confusing than perpetually
// "Launching".

import { useEffect, useRef, useState } from 'react';

export interface UseJupyterReadyProbeArgs {
  /** Proxy path that routes through the helper to JupyterLab. */
  proxyPath?: string;
  /** Stable instance identifier — used to reset state on reuse. */
  instanceID?: string;
  /** True iff the helper has dialed back via the websocket tunnel. */
  helperConnected: boolean;
}

/**
 * Returns true once a probe to `<proxyPath>/api/status` has confirmed
 * JupyterLab is serving (or after the 60s timeout). Returns false
 * when the helper isn't connected yet, or while the probe is still
 * running. Re-probes from scratch when instanceID changes (e.g. End
 * session → Launch new lands on a fresh instance with the same URL).
 */
export function useJupyterReadyProbe(args: UseJupyterReadyProbeArgs): boolean {
  const { proxyPath, instanceID, helperConnected } = args;
  const [ready, setReady] = useState(false);

  // Tracks the last instanceID we initiated a probe for. Lets us
  // detect "the host swapped to a new instance" and reset.
  const lastInstanceRef = useRef<string | null>(null);

  useEffect(() => {
    if (!helperConnected || !proxyPath || !instanceID) return undefined;
    if (lastInstanceRef.current === instanceID && ready) return undefined;
    if (lastInstanceRef.current !== instanceID) {
      lastInstanceRef.current = instanceID;
      setReady(false);
    }

    let cancelled = false;
    // Strip a trailing slash so we don't synthesize "//api/status".
    const base = proxyPath.replace(/\/$/, '');
    const statusURL = `${base}/api/status`;
    const probe = async () => {
      for (let i = 0; i < 60; i++) {
        if (cancelled) return;
        try {
          const res = await fetch(statusURL, {
            credentials: 'include',
            method: 'GET',
            cache: 'no-store',
          });
          // 200 = JupyterLab is fully up. 4xx except 401 still
          // proves the server is responding. 5xx and aborts mean
          // it's still booting — stay in the loop.
          if (res.status === 200) {
            if (!cancelled) setReady(true);
            return;
          }
          if (res.status >= 400 && res.status < 500 && res.status !== 401) {
            if (!cancelled) setReady(true);
            return;
          }
        } catch {
          // Network error / abort — JupyterLab not listening yet.
        }
        await new Promise((r) => setTimeout(r, 1000));
      }
      // 60s timeout: report ready so the iframe mounts even if
      // something's wrong with JupyterLab. False-ready beats
      // perpetual-launching from a UX standpoint.
      if (!cancelled) setReady(true);
    };
    probe();
    return () => {
      cancelled = true;
    };
  }, [helperConnected, proxyPath, instanceID, ready]);

  return ready;
}
