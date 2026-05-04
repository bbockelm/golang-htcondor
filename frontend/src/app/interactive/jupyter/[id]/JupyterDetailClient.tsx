'use client';

// JupyterDetailClient mounts the iframe + SSE plumbing for a single
// JupyterLab instance. See /interactive/page.tsx for the listing page.
//
// Cold-load case (user typed the URL directly or refreshed):
//   - GET /jupyter/instances/<id> tells us whether the helper is already
//     connected. If so, we skip straight to "ready".
//   - Otherwise we open SSE and wait for tunnel-connected.
//
// Warm-load case (user just hit "Launch" and was navigated here):
//   - The launcher invalidated the list, so the query above gets a
//     fresh result. SSE replays "created" and we wait for connect.

import { useEffect, useRef, useState } from 'react';
import Link from 'next/link';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useRouter } from 'next/navigation';
import {
  api,
  ApiError,
  displayJobStatus,
  type JupyterInstanceSummary,
} from '@/lib/api';
import { useResolvedParams } from '@/lib/useResolvedParams';
import {
  interpretJobStatus,
  statusLabel,
  statusPillStyle,
  type Status,
} from '@/lib/jobStatus';
import { MatchAnalysisPanel } from '@/components/MatchAnalysisPanel';

// Status interpretation lives in lib/jobStatus.ts so list + detail
// views render the same labels for the same conditions. This page
// also polls the underlying HTCondor job ad — so a held / removed
// job shows up immediately instead of looking like a slow startup.

export default function JupyterDetailClient() {
  const { id } = useResolvedParams<{ id: string }>('/interactive/jupyter/[id]');
  const router = useRouter();
  const queryClient = useQueryClient();

  const { data, error, refetch } = useQuery({
    queryKey: ['jupyter', 'instance', id],
    queryFn: () => api.jupyter.get(id),
    enabled: !!id && id !== '_',
    // Poll every 3s until the helper has dialed back. SSE was the
    // original signal here, but in practice the demo's HTTP/2 + self-
    // signed cert path swallows the `event: tunnel-connected` line on
    // some browsers, leaving the page stuck on "executing" until a
    // manual refetch. Aggressive polling makes the transition deterministic
    // (and cheap — 3s only for the brief startup window). Once
    // connected we drop back to a 30s staleTime so we're not spamming
    // the registry.
    refetchInterval: (q) => {
      const d = q.state.data as
        | { connected?: boolean }
        | undefined;
      return d?.connected ? false : 3000;
    },
    staleTime: 30_000,
  });

  // condor_rm the underlying cluster + bounce back to /interactive.
  // Removes every proc in the cluster so a multi-proc Jupyter (rare;
  // we currently submit one) tears down cleanly.
  const endSession = useMutation({
    mutationFn: () => {
      const cluster = data?.cluster_id;
      if (!cluster) {
        return Promise.reject(new Error('no cluster id known yet'));
      }
      return api.jobs.removeByConstraint(`ClusterId == ${cluster}`);
    },
    onSettled: () => {
      queryClient.invalidateQueries({ queryKey: ['jupyter', 'instances'] });
      queryClient.invalidateQueries({ queryKey: ['jobs'] });
      router.push('/interactive');
    },
  });

  // Whenever we have a cluster id and the helper hasn't connected, poll
  // the underlying job ad. The first proc (`<cluster>.0`) is fine — our
  // submit always queues exactly one. We stop polling once the helper
  // connects (status flips to "ready"), since at that point HTCondor
  // says "running" and we don't need it anymore.
  const clusterID = data?.cluster_id;
  const jobIDForPoll = clusterID ? `${clusterID}.0` : null;
  const jobQuery = useQuery({
    queryKey: ['job', jobIDForPoll],
    queryFn: () => api.jobs.get(jobIDForPoll!),
    enabled: !!jobIDForPoll && data?.connected !== true,
    refetchInterval: 3000,
    staleTime: 0,
  });

  const [status, setStatus] = useState<Status>('loading');
  const [reloadKey, setReloadKey] = useState(0);

  // jupyterReady = "we've successfully reached jupyter-lab through the
  // proxy". Helper-connected just means the websocket tunnel is up;
  // jupyter-lab inside the sandbox might still be doing its own
  // startup (creating the UDS, loading extensions, etc.). Mounting the
  // iframe before jupyter-lab is listening produces a blank iframe
  // that doesn't auto-retry — the user has to hit Reload manually.
  // Probing the proxy URL until it responds gives us the right signal.
  const [jupyterReady, setJupyterReady] = useState(false);
  // Remember the last instance we readied for — a brand new instance
  // (after End session → Launch new) should re-probe from scratch.
  const readyForRef = useRef<string | null>(null);

  useEffect(() => {
    if (error) {
      if (error instanceof ApiError && error.status === 404) {
        setStatus('gone');
      } else {
        setStatus('error');
      }
      return;
    }
    if (!data) {
      setStatus('loading');
      return;
    }
    if (data.connected) {
      // Helper is up; mount the iframe only once we've also confirmed
      // jupyter-lab itself is responding (see the probe effect below).
      // Until then, sit in "launching" with a banner so the user knows
      // why nothing's appearing.
      setStatus((s) => {
        if (s === 'closed') return s;
        return jupyterReady ? 'ready' : 'launching';
      });
      return;
    }
    // Not yet connected: derive a more specific in-progress status
    // (idle / transferring_input / executing / spooling / held / ...).
    setStatus(
      interpretJobStatus({
        job: jobQuery.data,
        helperConnected: data.connected,
      }),
    );
  }, [data, error, jobQuery.data, jupyterReady]);

  // Probe loop: GET <proxy>/api/status until it returns 200. That's
  // jupyter_server's little JSON status endpoint — implemented at the
  // ServerApp level (not a lab extension), so a 200 means the HTTP
  // server is fully up AND its routing is wired AND it can serve real
  // requests, not just "the process is alive enough to reject HEAD".
  //
  // We deliberately don't probe `proxy_path` itself with HEAD: Tornado
  // returns 405 on HEAD for handlers that only define `get()`, which
  // happens BEFORE the rest of the app finishes initializing — that's
  // how we ended up mounting the iframe too early in the previous
  // version. /api/status is GET-only and returns a real payload only
  // when the server is serving for real.
  useEffect(() => {
    if (!data?.connected || !data.proxy_path) return;
    if (readyForRef.current === data.instance_id && jupyterReady) return;
    if (readyForRef.current !== data.instance_id) {
      readyForRef.current = data.instance_id;
      setJupyterReady(false);
    }

    let cancelled = false;
    // Strip a trailing slash so we don't end up with "//api/status".
    const base = data.proxy_path.replace(/\/$/, '');
    const statusURL = `${base}/api/status`;
    const probe = async () => {
      // 60-iteration cap (~60s with 1s sleeps) so a permanently broken
      // jupyter doesn't keep us probing forever — past that we just
      // mount the iframe and let the user see whatever Jupyter is
      // serving (or click Reload).
      for (let i = 0; i < 60; i++) {
        if (cancelled) return;
        try {
          const res = await fetch(statusURL, {
            credentials: 'include',
            method: 'GET',
            cache: 'no-store',
          });
          // 200 = jupyter_server is fully up. 4xx other than 401 means
          // the route exists but the request was malformed somehow —
          // unexpected, but it still proves jupyter is responding, so
          // mount the iframe and let the user investigate. 5xx and
          // throws (connection refused, mid-flight reset) keep us in
          // the retry loop.
          if (res.status === 200) {
            if (!cancelled) setJupyterReady(true);
            return;
          }
          if (res.status >= 400 && res.status < 500 && res.status !== 401) {
            if (!cancelled) setJupyterReady(true);
            return;
          }
        } catch {
          // Network error — connection refused / abort mid-flight.
          // Jupyter isn't listening yet; retry.
        }
        await new Promise((r) => setTimeout(r, 1000));
      }
      // Timed out probing. Mount anyway so the user can see what's
      // happening; the "End session" button stays available.
      if (!cancelled) setJupyterReady(true);
    };
    probe();
    return () => {
      cancelled = true;
    };
  }, [data?.connected, data?.proxy_path, data?.instance_id, jupyterReady]);

  useEffect(() => {
    if (!data) return;
    // We still subscribe so `closed` events tear the iframe down
    // promptly. The connect signal is now driven by the polled GET
    // above; SSE delivery has been unreliable on the demo HTTPS path
    // and we don't want to depend on it for the happy path.
    const es = new EventSource(api.jupyter.eventsUrl(data.instance_id));
    es.addEventListener('tunnel-connected', () => {
      // Belt-and-suspenders: if SSE *does* deliver, refresh the GET
      // so the page transitions to "ready" right away instead of
      // waiting for the next 3s tick.
      refetch();
    });
    es.addEventListener('closed', () => {
      setStatus('closed');
      es.close();
    });
    es.onerror = () => {
      // EventSource auto-reconnects on its own; just nudge the GET
      // so we don't sit on stale data while it does.
      refetch();
    };
    return () => es.close();
  }, [data, refetch]);

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        <Link
          href="/interactive"
          className="text-sm text-gray-500 hover:text-gray-700"
        >
          ← Interactive
        </Link>
        <h1 className="text-2xl font-bold text-gray-900">JupyterLab</h1>
        {data && (
          <span className="text-xs text-gray-500 font-mono">
            {data.instance_id}
          </span>
        )}
        {/* End session: condor_rm the underlying cluster. Reachable
            for any non-terminal state where we know the cluster id. */}
        {data?.cluster_id &&
          status !== 'closed' &&
          status !== 'removed' &&
          status !== 'gone' && (
            <div className="ml-auto">
              <button
                onClick={() => {
                  if (
                    confirm(
                      'End the session? This removes the job from the queue.',
                    )
                  ) {
                    endSession.mutate();
                  }
                }}
                disabled={endSession.isPending}
                className="text-xs rounded border border-red-300 bg-white px-2 py-1 text-red-700 hover:bg-red-50 disabled:opacity-50"
              >
                {endSession.isPending ? 'Ending…' : 'End session'}
              </button>
            </div>
          )}
      </div>

      {endSession.error && (
        <Banner kind="error">
          Could not end session:{' '}
          {endSession.error instanceof Error
            ? endSession.error.message
            : String(endSession.error)}
        </Banner>
      )}

      {data && (
        <Header
          instance={data}
          status={status}
          onReload={() => setReloadKey((k) => k + 1)}
        />
      )}

      {status === 'loading' && <Banner kind="info">Loading session…</Banner>}

      {status === 'spooling' && (
        <Banner kind="info">
          Schedd is spooling input files. This usually finishes in a few
          seconds.
        </Banner>
      )}

      {status === 'idle' && (
        <Banner kind="info">
          Job is idle, waiting to be matched to an execute node.
        </Banner>
      )}

      {status === 'transferring_input' && (
        <Banner kind="info">
          Worker is pulling the Docker image and/or transferring input
          files. This can take a minute or two on a fresh node.
        </Banner>
      )}

      {status === 'executing' && (
        <Banner kind="info">
          The executable is running on the worker; waiting for the helper
          to dial back over the websocket tunnel…
        </Banner>
      )}

      {status === 'launching' && (
        <Banner kind="info">
          Helper connected. Waiting for JupyterLab to finish starting up
          inside the sandbox…
        </Banner>
      )}

      {status === 'held' && (
        <Banner kind="error">
          Job is held by the schedd; the helper will not start.
          {(() => {
            const reason = str(jobQuery.data?.HoldReason);
            return reason ? <> Reason: <code>{reason}</code></> : null;
          })()}{' '}
          <Link href="/interactive" className="underline">
            Launch another
          </Link>
          .
        </Banner>
      )}

      {status === 'removed' && (
        <Banner kind="info">
          Job was removed from the queue.{' '}
          <Link href="/interactive" className="underline">
            Launch another
          </Link>
          .
        </Banner>
      )}

      {/* Match-analysis widget for "why hasn't this started?" debugging.
          Render whenever we have a cluster id and the helper hasn't
          connected yet — that covers idle, transferring_input,
          executing, held, and any of the "stuck" intermediate states
          where the user might want to know which slot constraint is
          excluding them. We don't render after the helper connects:
          once the iframe is live, the analysis isn't useful anymore.
          The widget itself still requires a button click to run. */}
      {jobIDForPoll && data?.connected !== true && status !== 'gone' && status !== 'closed' && status !== 'removed' ? (
        <MatchAnalysisPanel
          jobID={jobIDForPoll}
          title="Why hasn't this session started?"
          // jobStatus drives the widget's "Run" button gate (only
          // 'idle'/'held' enabled). jobQDate drives the "wait a
          // minute" banner for fresh jobs. Both come from the
          // backing job ad polled in jobQuery — when it's not loaded
          // yet (cold start), pass undefined so the widget falls
          // back to its "allow but no banner" default rather than
          // misreporting "running".
          jobStatus={
            jobQuery.data
              ? displayJobStatus({
                  status: jobQuery.data.JobStatus as
                    | number
                    | string
                    | null
                    | undefined,
                  holdReasonCode: jobQuery.data.HoldReasonCode as
                    | number
                    | string
                    | null
                    | undefined,
                }).key
              : undefined
          }
          jobQDate={numAttr(jobQuery.data?.QDate)}
          helperText={
            status === 'held'
              ? 'The hold reason is shown above. The analysis below explains which slots could in principle match the requirements once the hold is released.'
              : "Run a slot-pool analysis to see which job requirement is excluding the most slots. The collector query is cached for ~30 seconds so re-running is cheap."
          }
        />
      ) : null}

      {status === 'ready' && data && (
        // Only mount once the probe loop has confirmed jupyter-lab is
        // serving (/api/status returned 200). Mounting at "launching"
        // — i.e. the moment the helper dials back — used to produce a
        // blank iframe that never recovered: JupyterLab inside hadn't
        // finished initializing, the iframe loaded a 502 / partial
        // page, and React's reconciler kept the same <iframe> element
        // when status flipped to "ready" (same key + same src), so
        // the browser never re-fetched. Mounting only at "ready"
        // means the first load is always against a known-good server.
        <iframe
          key={reloadKey}
          src={data.proxy_path}
          className="w-full rounded border border-gray-300 bg-white"
          style={{ height: '80vh' }}
          // Permissive sandbox so kernels get the broad set of features
          // Jupyter expects. Same-origin: the cookie still applies.
          sandbox="allow-scripts allow-same-origin allow-forms allow-downloads allow-popups allow-popups-to-escape-sandbox"
        />
      )}

      {status === 'closed' && (
        <Banner kind="info">
          Session ended. The worker has released the slot.{' '}
          <Link href="/interactive" className="underline">
            Launch another
          </Link>
          .
        </Banner>
      )}

      {status === 'gone' && (
        <Banner kind="info">
          No such session. It may have been closed or the API server may
          have restarted (sessions don&apos;t survive restarts).{' '}
          <Link href="/interactive" className="underline">
            Back to sessions
          </Link>
          .
        </Banner>
      )}

      {status === 'error' && (
        <Banner kind="error">
          Could not load this session:{' '}
          {error instanceof Error ? error.message : 'unknown error'}
        </Banner>
      )}
    </div>
  );
}

// (Old local deriveJobBackedStatus + num removed — interpretJobStatus
// in lib/jobStatus.ts is the single source of truth now.)

function str(v: unknown): string | undefined {
  if (typeof v === 'string') return v;
  if (v == null) return undefined;
  return String(v);
}

// numAttr coerces a ClassAd attribute value to a number. ClassAd
// numerics often arrive as strings on the wire; lib/api decodes them
// permissively, so callers see either type. Returns undefined when
// the value isn't numeric — the match-analysis panel uses that to
// suppress the young-job banner rather than misreport.
function numAttr(v: unknown): number | undefined {
  if (typeof v === 'number') return v;
  if (typeof v === 'string') {
    const n = Number(v);
    return Number.isFinite(n) ? n : undefined;
  }
  return undefined;
}

function Header({
  instance,
  status,
  onReload,
}: {
  instance: JupyterInstanceSummary;
  status: Status;
  onReload: () => void;
}) {
  return (
    <div className="flex flex-wrap items-center gap-3 text-sm">
      <StatusBadge status={status} />
      {instance.cluster_id && (
        // Jupyter clusters always have a single proc (proc 0); show the
        // canonical "<cluster>.0" form rather than just the cluster.
        <span className="text-gray-700">
          job <span className="font-mono">{instance.cluster_id}.0</span>
        </span>
      )}
      {instance.image && (
        <span className="text-gray-500 font-mono text-xs truncate max-w-md">
          {instance.image}
        </span>
      )}
      {(status === 'ready' || status === 'launching') && (
        <>
          <button
            onClick={onReload}
            className="ml-auto text-xs text-gray-500 hover:text-gray-700"
          >
            Reload iframe
          </button>
          <a
            href={instance.proxy_path}
            target="_blank"
            rel="noreferrer"
            className="text-xs text-gray-500 hover:text-gray-700"
          >
            Open in new tab ↗
          </a>
        </>
      )}
    </div>
  );
}

function StatusBadge({ status }: { status: Status }) {
  // Delegates to the shared lib/jobStatus styling so list + detail
  // views render identical pills.
  const style = statusPillStyle(status);
  return (
    <span className={style.badge}>
      {style.dot && <span className={style.dot} />}
      {statusLabel(status)}
    </span>
  );
}

function Banner({
  kind,
  children,
}: {
  kind: 'info' | 'error';
  children: React.ReactNode;
}) {
  const cls =
    kind === 'error'
      ? 'border-red-200 bg-red-50 text-red-700'
      : 'border-blue-200 bg-blue-50 text-blue-800';
  return (
    <div className={`rounded border px-3 py-2 text-sm ${cls}`}>{children}</div>
  );
}
