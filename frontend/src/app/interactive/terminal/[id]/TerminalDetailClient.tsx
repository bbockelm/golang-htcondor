'use client';

// TerminalDetailClient hosts the xterm.js terminal for an interactive
// terminal job. The job id is the cluster.proc string.
//
// Lifecycle:
//   1. Cold load: poll the job's classad until JobStatus == 2 (Running).
//      The SSH bridge can only attach to a running job, so we hide the
//      terminal until then.
//   2. Mount <JobTerminal/>: it opens the SSH WebSocket and bridges
//      keystrokes <-> stdio. The server-side SSH bridge (handlers_ssh.go)
//      detects this is an interactive job (by JobBatchName) and starts
//      the heartbeat goroutine that multiplexes a "touch .heartbeat"
//      session over the same ssh.Client when the user has typed
//      recently.
//   3. The watchdog inside the job exits if the heartbeat goes stale
//      (default ~120s of no user activity), which closes the SSH
//      connection and surfaces as an exit frame in the terminal.

import Link from 'next/link';
import dynamic from 'next/dynamic';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useRouter } from 'next/navigation';
import { api, ApiError, type ClassAd } from '@/lib/api';
import { useResolvedParams } from '@/lib/useResolvedParams';
import {
  HOLD_REASON_SPOOLING_INPUT,
  interpretJobStatus,
  statusLabel,
  statusPillStyle,
  type Status,
} from '@/lib/jobStatus';

// xterm.js touches `window` at import time; load it client-only so the
// static export doesn't try to render a terminal during build.
const JobTerminal = dynamic(
  () => import('@/components/JobTerminal').then((m) => m.JobTerminal),
  { ssr: false },
);

export default function TerminalDetailClient() {
  const { id } = useResolvedParams<{ id: string }>(
    '/interactive/terminal/[id]',
  );
  const router = useRouter();
  const queryClient = useQueryClient();

  const { data, error } = useQuery({
    queryKey: ['job', id],
    queryFn: () => api.jobs.get(id),
    enabled: !!id && id !== '_',
    // Poll every 2s while the job hasn't started running so the
    // terminal mounts as soon as the schedd matches it. Once running,
    // react-query's automatic cache cuts the request rate to once per
    // staleTime. Spooling-hold (transient, ~seconds) gets the same
    // poll cadence so we don't sit on a stale "starting" view.
    refetchInterval: (q) => {
      const ad = q.state.data as ClassAd | undefined;
      // Run through the same interpreter so the cadence and the
      // banner agree about which states are "still settling".
      const s = interpretJobStatus({ job: ad });
      return s === 'idle' ||
        s === 'spooling' ||
        s === 'transferring_input' ||
        s === 'loading'
        ? 2000
        : false;
    },
    staleTime: 30_000,
  });

  // condor_rm the job + bounce back to the list. Used by the explicit
  // "End session" button — the WebSocket-close path doesn't trigger
  // this; the watchdog inside the job will time out from a clean
  // disconnect on its own.
  const endSession = useMutation({
    mutationFn: () => api.jobs.remove(id),
    onSettled: () => {
      queryClient.invalidateQueries({ queryKey: ['interactive', 'terminals'] });
      queryClient.invalidateQueries({ queryKey: ['jobs'] });
      router.push('/interactive');
    },
  });

  // Run the polled job ad through the shared interpreter so list +
  // detail views agree. Once the schedd reports JobStatus=2 +
  // JobCurrentStartExecutingDate the interpreter returns "executing",
  // which is when we let JobTerminal mount and attach to ssh; we map
  // that to "running" locally since the terminal doesn't have a
  // separate "helper has dialed back" notion.
  const status: Status = (() => {
    if (error) {
      return error instanceof ApiError && error.status === 404
        ? 'gone'
        : 'error';
    }
    return interpretJobStatus({ job: data });
  })();

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        <Link
          href="/interactive"
          className="text-sm text-gray-500 hover:text-gray-700"
        >
          ← Interactive
        </Link>
        <h1 className="text-2xl font-bold text-gray-900">Terminal</h1>
        <span className="text-xs text-gray-500 font-mono">{id}</span>
        <div className="ml-auto flex items-center gap-3">
          <StatusPill status={status} />
          {/* "End session" is reachable as long as the job exists and
              isn't already gone/completed/removed. Calls condor_rm and
              navigates back. */}
          {status !== 'gone' &&
            status !== 'closed' &&
            status !== 'removed' &&
            status !== 'error' && (
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
            )}
        </div>
      </div>

      {endSession.error && (
        <Banner kind="error">
          Could not end session:{' '}
          {endSession.error instanceof Error
            ? endSession.error.message
            : String(endSession.error)}
        </Banner>
      )}

      {status === 'loading' && (
        <Banner kind="info">Looking up job…</Banner>
      )}

      {status === 'spooling' && (
        <Banner kind="info">
          Schedd is spooling input files. This usually finishes in a few
          seconds.
        </Banner>
      )}

      {status === 'idle' && (
        <Banner kind="info">
          Job is idle. The terminal will attach as soon as the schedd
          starts it on an execute node.
        </Banner>
      )}

      {status === 'transferring_input' && (
        <Banner kind="info">
          Transferring input files to the execute node…
        </Banner>
      )}

      {status === 'held' && data && (
        <Banner kind="error">
          Job is held.{' '}
          {(() => {
            const reason = str(data.HoldReason);
            return reason ? `Reason: ${reason}` : null;
          })()}
        </Banner>
      )}

      {(status === 'closed' || status === 'removed') && (
        <Banner kind="info">
          Session ended. The watchdog inside the job exited (likely because
          the heartbeat went stale or the user typed <kbd>exit</kbd>).{' '}
          <Link href="/interactive" className="underline">
            Launch another
          </Link>
          .
        </Banner>
      )}

      {status === 'gone' && (
        <Banner kind="info">
          No such job. It may have been removed.{' '}
          <Link href="/interactive" className="underline">
            Back to sessions
          </Link>
          .
        </Banner>
      )}

      {status === 'error' && (
        <Banner kind="error">
          Could not look up this job:{' '}
          {error instanceof Error ? error.message : 'unknown error'}
        </Banner>
      )}

      {/* Mount the xterm bridge once the executable is actually
          running. interpretJobStatus returns "executing" once
          JobCurrentStartExecutingDate is set; before that the SSH
          bridge has nothing to attach to. */}
      {status === 'executing' && <JobTerminal jobID={id} />}
    </div>
  );
}

function StatusPill({ status }: { status: Status }) {
  // Delegate to lib/jobStatus so list + detail render the same pill.
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

function str(v: unknown): string | undefined {
  if (typeof v === 'string') return v;
  if (v == null) return undefined;
  return String(v);
}
