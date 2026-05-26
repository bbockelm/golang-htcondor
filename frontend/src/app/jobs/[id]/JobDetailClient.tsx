'use client';

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import dynamic from 'next/dynamic';
import {
  api,
  ApiError,
  displayJobStatus,
  type ClassAd,
  type DisplayStatus,
} from '@/lib/api';
import { useResolvedParams } from '@/lib/useResolvedParams';
import { ChatPanel, type ToolHandler } from '@/components/ChatPanel';
import { ConfirmButton } from '@/components/ConfirmButton';
import { LogViewerPanel } from '@/components/LogViewerPanel';
import { MatchAnalysisPanel } from '@/components/MatchAnalysisPanel';

// xterm.js touches `window` at import time; load it client-only so the static
// export doesn't try to render a terminal during build.
const JobTerminal = dynamic(
  () => import('@/components/JobTerminal').then((m) => m.JobTerminal),
  { ssr: false },
);

export default function JobDetailClient(_props: {
  // Next.js 16 still hands us a `params` Promise, but for static-export
  // builds it resolves to the placeholder ("_") declared in
  // generateStaticParams. We read the real cluster.proc ID off the URL
  // via useResolvedParams instead — see frontend/src/lib/useResolvedParams.ts.
}) {
  const { id } = useResolvedParams<{ id: string }>('/jobs/[id]');
  const { data, isLoading, error } = useQuery({
    queryKey: ['job', id],
    queryFn: () => api.jobs.get(id),
    refetchInterval: 10_000,
    // id is "" briefly during initial client hydration if the pathname
    // hasn't been read yet; skip those calls.
    enabled: !!id && id !== '_',
  });

  const router = useRouter();
  const queryClient = useQueryClient();

  // Status 3 = Removed, 4 = Completed. Don't offer Remove for those.
  const status = data ? num(data.JobStatus) : undefined;
  const isTerminal = status === 3 || status === 4;
  // Status 5 = Held. Surface a Release button so the user doesn't
  // have to drop to the CLI to un-hold a job.
  const isHeld = status === 5;

  const removeMut = useMutation({
    mutationFn: () => api.jobs.remove(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['jobs'] });
      router.push('/jobs');
    },
  });

  const releaseMut = useMutation({
    mutationFn: () => api.jobs.release(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['jobs'] });
      queryClient.invalidateQueries({ queryKey: ['job', id] });
    },
  });

  // Split "<batch>.<job>" — id is e.g. "3.0" where 3 is the batch
  // (cluster) id and 0 is the job (proc) index inside it.
  const [batchID, jobIdx] = id.split('.');

  return (
    <div className="space-y-6 max-w-4xl">
      <div className="flex items-center gap-3 flex-wrap">
        <Link href="/jobs" className="text-sm text-gray-500 hover:text-gray-700">
          ← All batches
        </Link>
        <h1 className="text-2xl font-bold text-gray-900">
          Job {jobIdx ?? '?'}
          <span className="ml-2 text-base font-normal text-gray-500">
            in batch {batchID ?? '?'}
          </span>
        </h1>
        <div className="ml-auto flex items-center gap-2">
          {isHeld && data && (
            <button
              type="button"
              onClick={() => releaseMut.mutate()}
              disabled={releaseMut.isPending}
              className="rounded border border-brand-600 bg-white px-3 py-1.5 text-sm font-medium text-brand-700 hover:bg-brand-50 disabled:opacity-50"
              title={`Release held job ${id}`}
            >
              {releaseMut.isPending ? 'Releasing…' : 'Release'}
            </button>
          )}
          {!isTerminal && data && (
            <ConfirmButton
              onConfirm={() => removeMut.mutate()}
              pending={removeMut.isPending}
              title={`Remove job ${id}`}
            />
          )}
        </div>
      </div>

      {removeMut.error && (
        <div className="rounded border border-red-200 bg-red-50 p-3 text-sm text-red-700">
          Remove failed:{' '}
          {removeMut.error instanceof ApiError
            ? removeMut.error.message
            : String(removeMut.error)}
        </div>
      )}

      {releaseMut.error && (
        <div className="rounded border border-red-200 bg-red-50 p-3 text-sm text-red-700">
          Release failed:{' '}
          {releaseMut.error instanceof ApiError
            ? releaseMut.error.message
            : String(releaseMut.error)}
        </div>
      )}

      {isLoading && <p className="text-gray-400">Loading...</p>}

      {error && (
        <div className="rounded border border-red-200 bg-red-50 p-3 text-sm text-red-700">
          {(error as Error).message}
        </div>
      )}

      {data && <JobDetail jobID={id} job={data} />}
    </div>
  );
}

function JobDetail({ jobID, job }: { jobID: string; job: ClassAd }) {
  const status = num(job.JobStatus);
  const owner = str(job.Owner);
  const cmd = str(job.Cmd);
  const args = str(job.Args);
  const qdate = num(job.QDate);
  // JobStartDate is the most recent time the job started running. It
  // resets on every requeue / restart, so for "how long has the
  // process been alive?" this is the right anchor (vs JobCurrentStartDate
  // which behaves the same on stock HTCondor and is what we fall back
  // to). LastJobStartDate is the previous run's start; not useful here.
  const startDate =
    num(job.JobStartDate) ?? num(job.JobCurrentStartDate);
  const completionDate = num(job.CompletionDate);
  const holdReason = str(job.HoldReason);

  // useNowTick re-renders the relative-time strings every minute even
  // if the underlying job ad hasn't changed.
  const now = useNowTick(60_000);

  const display = displayJobStatus({
    status: job.JobStatus as number | string | null | undefined,
    holdReasonCode: job.HoldReasonCode as number | string | null | undefined,
  });

  // When we re-label "Held + spool" as "Uploading Inputs", the
  // HoldReason field becomes redundant noise. Suppress it in that
  // case so the panel stays clean.
  const showHoldReason =
    holdReason !== undefined && display.key !== 'uploading';

  // Exit code only meaningful for jobs that have actually run to
  // completion. Surface it in the top box too (in addition to the
  // execution table further down) so users see it without scrolling.
  const exitCodeNum = num(job.ExitCode);
  const exitBySignal = job.ExitBySignal === true || job.ExitBySignal === 'true';
  const showExitCode = exitCodeNum !== undefined || exitBySignal;

  return (
    <div className="space-y-6">
      {/* Chat sits at the top: it's the primary affordance for
          investigation ("why is this held?", "tail my stderr") and
          users don't scroll past two screens of panels to find a
          collapsed pill at the bottom. */}
      <JobDetailChat jobID={jobID} job={job} />

      <div className="rounded border border-gray-200 bg-white p-4 grid grid-cols-2 gap-3 text-sm">
        <Field label="Status" value={<StatusBadge display={display} />} />
        <Field label="Owner" value={owner ?? '—'} />
        <Field
          label="Submitted"
          value={qdate ? new Date(qdate * 1000).toLocaleString() : '—'}
          sub={
            qdate
              ? `${humanDuration(now - qdate)} ago`
              : undefined
          }
        />
        <Field
          label="Last Started"
          value={
            startDate ? new Date(startDate * 1000).toLocaleString() : '—'
          }
          sub={
            startDate
              ? completionDate
                ? `ran for ${humanDuration(completionDate - startDate)}`
                : `${humanDuration(now - startDate)} ago`
              : undefined
          }
        />
        <Field
          label="Completed"
          value={
            completionDate
              ? new Date(completionDate * 1000).toLocaleString()
              : '—'
          }
          sub={
            completionDate && startDate
              ? `${humanDuration(completionDate - startDate)} since start`
              : completionDate
                ? `${humanDuration(now - completionDate)} ago`
                : undefined
          }
        />
        {showExitCode && (
          <Field label="Exit Code" value={exitCodeCell(job)} />
        )}
        <Field label="Command" value={cmd ?? '—'} mono full />
        {args && <Field label="Arguments" value={args} mono full />}
        {showHoldReason && (
          <Field label="Hold Reason" value={holdReason!} full warn />
        )}
      </div>

      <OutputFilesPanel jobID={jobID} status={status} />

      <LiveTailPanel jobID={jobID} status={status} />

      <TerminalPanel jobID={jobID} status={status} />

      <LogViewerPanel jobID={jobID} />

      {/* Match analysis is most useful for Idle (1) and Held (5) jobs —
          it answers "why isn't this running?". We expose the panel
          for every status (so the operator can read about it) but
          start collapsed regardless of state: the page already has
          plenty going on, and the operator opting in by clicking the
          summary is a clearer signal of intent than auto-expanding.
          The widget itself further gates the Run button on
          display.key (only 'idle'/'held' enabled). jobQDate drives
          the "wait a minute" banner for fresh jobs. */}
      <MatchAnalysisPanel
        jobID={jobID}
        defaultOpen={false}
        jobStatus={display.key}
        jobQDate={qdate}
        helperText={
          status === 1
            ? 'Job is idle. Run the analysis to see which requirement is excluding the most slots in the pool.'
            : status === 5
              ? 'Job is held. The hold reason is shown above; the analysis below explains which slots could in principle match the requirements.'
              : undefined
        }
      />

      <JobDetailsSection jobID={jobID} job={job} />
    </div>
  );
}

// Build a short page-context string the LLM can read so it doesn't
// have to ask "which job?" on every turn. Keep this terse — it's
// appended to the system prompt on every request, so verbosity costs
// tokens. Only include facts the LLM might want to act on (the job_id
// for run_in_job, the status to know whether ssh-to-job is even
// available, the last host for cross-referencing).
function buildJobChatContext(jobID: string, job: ClassAd): string {
  const parts: string[] = [`job_id=${jobID}`];
  const status = num(job.JobStatus);
  if (status !== undefined) {
    const display = displayJobStatus({
      status: job.JobStatus as number | string | null | undefined,
      holdReasonCode: job.HoldReasonCode as
        | number
        | string
        | null
        | undefined,
    });
    parts.push(`status=${display.label} (JobStatus=${status})`);
  }
  const owner = str(job.Owner);
  if (owner) parts.push(`owner=${owner}`);
  const lastHost = str(job.LastRemoteHost) ?? str(job.RemoteHost);
  if (lastHost) parts.push(`last_host=${lastHost}`);
  const hold = str(job.HoldReason);
  if (hold) parts.push(`hold_reason=${hold}`);
  return parts.join('\n');
}

// JobDetailChat hosts the per-job ChatPanel. Builds the per-request
// page-context string and the client-side tool dispatch hooks. The
// hooks operate against the React Query cache where possible (so a
// follow-up read doesn't re-hit the schedd) and otherwise call the
// underlying API client.
//
// === KEEP IN SYNC WITH jobDetailPageInstructions IN
// httpserver/handlers_chat_tools.go ===
function JobDetailChat({ jobID, job }: { jobID: string; job: ClassAd }) {
  const queryClient = useQueryClient();
  const { data: chatInfo } = useQuery({
    queryKey: ['chat-info'],
    queryFn: api.chat.info,
    staleTime: Infinity,
    retry: false,
  });
  const chatVisible = !!chatInfo?.enabled;

  const pageContext = useMemo(
    () => buildJobChatContext(jobID, job),
    [jobID, job],
  );

  const hooks = useMemo<Record<string, ToolHandler>>(
    () => ({
      get_job_attributes: (input) => {
        const names = Array.isArray(input.names)
          ? (input.names as unknown[]).filter(
              (n): n is string => typeof n === 'string',
            )
          : null;
        if (!names || names.length === 0) {
          // Full-ad request. Cap on size to protect the LLM context.
          // Was 64 KiB; tightened to 24 KiB (~6k tokens) in 2026-05.
          // Common interesting projections are well under 1 KiB, so
          // 24 KiB leaves plenty of room for "the full ad" on
          // ordinary jobs while keeping a chirp-spam'd ad from
          // single-handedly consuming a turn.
          const text = JSON.stringify(job);
          if (text.length > 24 * 1024) {
            return {
              ok: false,
              error:
                'job ClassAd exceeds 24 KiB; pass `names` with the specific attributes you need (typical interesting set: JobStatus, HoldReason, RemoteHost, RequestMemory, NumShadowStarts, ExitCode).',
            };
          }
          return { ok: true, attributes: job };
        }
        // Case-insensitive lookup against the ad's keys. ClassAds are
        // case-insensitive on the wire; the JSON marshaling preserves
        // whatever cap the schedd handed back, so the LLM might ask for
        // "holdReason" while the ad has "HoldReason".
        const lc: Record<string, unknown> = {};
        for (const [k, v] of Object.entries(job)) {
          lc[k.toLowerCase()] = v;
        }
        const out: Record<string, unknown> = {};
        for (const n of names) {
          const v = lc[n.toLowerCase()];
          if (v !== undefined) out[n] = v;
        }
        return { ok: true, attributes: out, missing: names.filter((n) => lc[n.toLowerCase()] === undefined) };
      },

      get_job_log: async (input) => {
        try {
          const data = await queryClient.fetchQuery({
            queryKey: ['job-log', jobID],
            queryFn: () => api.jobs.log(jobID),
            staleTime: 5_000,
          });
          // Cap events newest-first. The full log can contain hundreds
          // of entries for re-tried jobs; the LLM rarely needs more
          // than the recent slice. The original total event count is
          // surfaced via total_events / truncated so the LLM knows
          // when to ask for more.
          const maxEvents = clampInt(input.max_events, 1, 100, 40);
          const allEvents = data.events ?? [];
          const trimmed =
            allEvents.length > maxEvents
              ? allEvents.slice(allEvents.length - maxEvents)
              : allEvents;
          return {
            ok: true,
            ...data,
            events: trimmed,
            total_events: allEvents.length,
            event_window_truncated: trimmed.length < allEvents.length,
          };
        } catch (e) {
          return { ok: false, error: errMsg(e) };
        }
      },

      get_match_analysis: async () => {
        try {
          const data = await queryClient.fetchQuery({
            queryKey: ['job-match-analysis', jobID],
            queryFn: () => api.jobs.matchAnalysis(jobID),
            staleTime: 30_000,
          });
          // Project the analyzer's full Result down to the fields
          // the LLM can act on, dropping the heavy ones (per-predicate
          // attribute distributions, long sample-host arrays). The
          // SPA panel keeps the full response in its own cache; this
          // trimming applies only to what we forward to the model.
          const result = data.result;
          const trimmedPredicates = (result.predicates ?? []).map((p) => ({
            index: p.index,
            source: p.source,
            matched: p.matched,
            not_matched: p.not_matched,
            undefined: p.undefined,
            error: p.error,
            narrowing_score: p.narrowing_score,
            sample_matched_hosts: (p.sample_matched_hosts ?? []).slice(0, 5),
            sample_not_matched_hosts: (p.sample_not_matched_hosts ?? []).slice(
              0,
              5,
            ),
            // attribute_distributions deliberately omitted — useful
            // for the GUI's histogram, useless for the chat LLM and
            // can be tens of KB on big pools.
          }));
          return {
            ok: true,
            job_id: data.job_id,
            requirements: data.requirements,
            result: {
              total_slots: result.total_slots,
              full_matches: result.full_matches,
              narrowing_predicate_index: result.narrowing_predicate_index,
              predicates: trimmedPredicates,
            },
          };
        } catch (e) {
          return { ok: false, error: errMsg(e) };
        }
      },

      read_job_output: async (input) => {
        const stream = String(input.stream ?? '');
        if (stream !== 'stdout' && stream !== 'stderr') {
          return { ok: false, error: 'stream must be "stdout" or "stderr"' };
        }
        const mode = String(input.mode ?? '');
        if (!['head', 'tail', 'grep'].includes(mode)) {
          return { ok: false, error: 'mode must be "head", "tail", or "grep"' };
        }
        // Byte budget shared by all three modes. Lines that would
        // push us over the cap are dropped and a `truncated_by_bytes`
        // flag is returned so the LLM can react. 8 KiB ≈ ~2k tokens
        // — enough for "what did this print near the end?" but not
        // a token sink for chatty outputs.
        const BYTE_CAP = 8 * 1024;
        // Bound each individual line too. A single >1 KiB line is
        // almost certainly base64 / a JSON blob / a stack trace dump
        // — the LLM doesn't need the full payload to answer "what
        // failed?". Long lines are truncated with an `…` marker.
        const LINE_CAP = 1024;
        const trimLine = (s: string): string =>
          s.length > LINE_CAP ? s.slice(0, LINE_CAP) + '… [line truncated]' : s;
        const takeLines = (
          src: string[],
        ): { lines: string[]; truncatedByBytes: boolean } => {
          const out: string[] = [];
          let total = 0;
          for (const raw of src) {
            const line = trimLine(raw);
            if (total + line.length + 1 > BYTE_CAP) {
              return { lines: out, truncatedByBytes: true };
            }
            out.push(line);
            total += line.length + 1;
          }
          return { lines: out, truncatedByBytes: false };
        };
        try {
          const fetcher =
            stream === 'stdout' ? api.jobs.stdoutText : api.jobs.stderrText;
          const data = await queryClient.fetchQuery({
            queryKey: ['job-output', jobID, stream],
            queryFn: () => fetcher(jobID),
            staleTime: 60_000,
          });
          const lines = data.text.split('\n');
          const n = clampInt(input.lines, 1, 150, 30);
          if (mode === 'head') {
            const sliced = lines.slice(0, n);
            const { lines: out, truncatedByBytes } = takeLines(sliced);
            return {
              ok: true,
              stream,
              mode,
              lines: out,
              total_lines: lines.length,
              truncated: data.truncated,
              truncated_by_bytes: truncatedByBytes,
            };
          }
          if (mode === 'tail') {
            // For tail, byte-cap from the END so the most recent
            // lines (the ones the user usually wants) survive when
            // the slice is too big.
            const sliced = lines.slice(Math.max(0, lines.length - n));
            const reversed = sliced.slice().reverse();
            const { lines: outRev, truncatedByBytes } = takeLines(reversed);
            return {
              ok: true,
              stream,
              mode,
              lines: outRev.reverse(),
              total_lines: lines.length,
              truncated: data.truncated,
              truncated_by_bytes: truncatedByBytes,
            };
          }
          // grep mode
          const pattern = String(input.pattern ?? '');
          if (!pattern) {
            return { ok: false, error: 'grep mode requires a pattern' };
          }
          const flags =
            input.case_insensitive === true ? 'i' : '';
          let re: RegExp;
          try {
            re = new RegExp(pattern, flags);
          } catch (e) {
            return { ok: false, error: `invalid regex: ${errMsg(e)}` };
          }
          const ctx = clampInt(input.context_lines, 0, 5, 0);
          const matches: { line: number; text: string }[] = [];
          let bytes = 0;
          let truncatedByBytes = false;
          outer: for (let i = 0; i < lines.length; i++) {
            if (re.test(lines[i])) {
              const start = Math.max(0, i - ctx);
              const end = Math.min(lines.length, i + ctx + 1);
              for (let j = start; j < end; j++) {
                if (!matches.find((m) => m.line === j + 1)) {
                  const text = trimLine(lines[j]);
                  if (bytes + text.length + 1 > BYTE_CAP) {
                    truncatedByBytes = true;
                    break outer;
                  }
                  matches.push({ line: j + 1, text });
                  bytes += text.length + 1;
                }
              }
            }
            // Cap returned matches so a too-broad pattern doesn't
            // blow out the model's context window. Dropped from 200
            // → 100 to align with the new byte budget.
            if (matches.length >= 100) break;
          }
          return {
            ok: true,
            stream,
            mode,
            pattern,
            matches,
            match_count: matches.length,
            total_lines: lines.length,
            truncated: data.truncated,
            truncated_by_bytes: truncatedByBytes,
          };
        } catch (e) {
          return { ok: false, error: errMsg(e) };
        }
      },
    }),
    [job, jobID, queryClient],
  );

  return (
    <ChatPanel
      visible={chatVisible}
      page="job-detail"
      pageContext={pageContext}
      hooks={hooks}
      headerLabel="Job assistant"
      togglerLabel="Ask about this job"
      // Chat is the primary affordance on this page (investigation
      // patterns: "why held?", "tail stderr", "ps inside the job"),
      // so default to expanded so it's there the moment the page
      // mounts instead of behind a pill click.
      defaultOpen
      pageHelp={`Ask things like "why is this held?", "what's it doing right now?", "show me the last 30 lines of stderr", or "did it actually start matching slots?".`}
    />
  );
}

function errMsg(e: unknown): string {
  if (e instanceof Error) return e.message;
  return String(e);
}

function clampInt(
  v: unknown,
  min: number,
  max: number,
  defaultValue: number,
): number {
  const n = typeof v === 'number' ? v : Number(v);
  if (!Number.isFinite(n)) return defaultValue;
  if (n < min) return min;
  if (n > max) return max;
  return Math.floor(n);
}

function TerminalPanel({
  jobID,
  status,
}: {
  jobID: string;
  status: number | undefined;
}) {
  const [open, setOpen] = useState(false);

  // condor_ssh_to_job only works while the job is Running (2) or
  // Transferring Output (6). Anything else, surface a hint and don't even
  // mount the WebSocket.
  const canSSH = status === 2 || status === 6;

  return (
    <div className="rounded border border-gray-200 bg-white p-4 space-y-3">
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-medium text-gray-900">Terminal</h2>
        {!canSSH && (
          <span className="text-xs text-gray-400">
            Available while the job is running.
          </span>
        )}
      </div>
      {canSSH && !open && (
        <button
          onClick={() => setOpen(true)}
          className="rounded border border-gray-300 bg-white px-3 py-1.5 text-sm text-gray-700 hover:bg-gray-50"
        >
          Open shell
        </button>
      )}
      {canSSH && open && (
        <>
          <div className="flex justify-end">
            <button
              onClick={() => setOpen(false)}
              className="text-xs text-gray-500 hover:text-gray-700"
            >
              Close
            </button>
          </div>
          <JobTerminal jobID={jobID} />
        </>
      )}
    </div>
  );
}

// OutputFilesPanel exposes the job's transferred-back files as a tar
// download or a short-lived shareable link.
//
// Output files only exist once the job has finished — the starter
// transfers them to the schedd's spool when JobStatus moves to 4
// (Completed) or 3 (Removed, after a rough exit). For any earlier
// state we keep the panel visible but greyed out so users don't get
// surprised by an empty download or a 4xx from the API.
function OutputFilesPanel({
  jobID,
  status,
}: {
  jobID: string;
  status: number | undefined;
}) {
  const [share, setShare] = useState<{
    url: string;
    expires: Date;
  } | null>(null);
  const [copied, setCopied] = useState(false);

  const shareMut = useMutation({
    mutationFn: () => api.jobs.shareOutput(jobID, 600),
    onSuccess: (resp) =>
      setShare({ url: resp.url, expires: new Date(resp.expires_at) }),
  });

  // 3 = Removed, 4 = Completed. Both terminal states; both have (or
  // had) a chance to leave files behind. Anything else → disabled.
  const ready = status === 3 || status === 4;
  const hint = ready
    ? null
    : status === 1
      ? 'Job is idle; output files appear once it completes.'
      : status === 2
        ? 'Job is running; output files appear once it completes.'
        : status === 5
          ? 'Job is held; output files appear once it completes.'
          : 'Output files appear once the job completes.';

  const handleCopy = () => {
    if (!share) return;
    navigator.clipboard?.writeText(share.url);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div
      className={`rounded border border-gray-200 bg-white p-4 space-y-3 ${
        ready ? '' : 'opacity-60'
      }`}
    >
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-medium text-gray-900">Output Files</h2>
        {hint && <span className="text-xs text-gray-400">{hint}</span>}
      </div>

      <div className="flex flex-wrap gap-3">
        {ready ? (
          <a
            href={api.jobs.outputDownloadUrl(jobID)}
            className="text-sm rounded bg-brand-600 px-3 py-1.5 text-white hover:bg-brand-700"
            download
          >
            Download as tar
          </a>
        ) : (
          <button
            type="button"
            disabled
            className="text-sm rounded bg-brand-600 px-3 py-1.5 text-white opacity-60 cursor-not-allowed"
            title={hint ?? ''}
          >
            Download as tar
          </button>
        )}
        <button
          onClick={() => shareMut.mutate()}
          disabled={!ready || shareMut.isPending}
          className="text-sm rounded border border-gray-300 bg-white px-3 py-1.5 text-gray-700 hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {shareMut.isPending ? 'Generating...' : 'Generate share link'}
        </button>
      </div>

      {shareMut.isError && (
        <div className="text-sm text-red-700">
          {(shareMut.error as Error).message}
        </div>
      )}

      {share && (
        <div className="rounded border border-amber-200 bg-amber-50 p-3 text-xs space-y-2">
          <div className="text-amber-900">
            Anyone with this link can download the output files until{' '}
            <strong>{share.expires.toLocaleString()}</strong>.
          </div>
          <div className="flex gap-2">
            <input
              readOnly
              value={share.url}
              className="flex-1 min-w-0 rounded border border-amber-300 bg-white px-2 py-1 font-mono"
              onFocus={(e) => e.currentTarget.select()}
            />
            <button
              onClick={handleCopy}
              className="rounded bg-amber-200 px-2 py-1 text-amber-900 hover:bg-amber-300 min-w-16"
              type="button"
            >
              {copied ? 'Copied' : 'Copy'}
            </button>
          </div>
        </div>
      )}

      {ready && (
        <div className="space-y-2 pt-1">
          <OutputStreamPreview
            label="stdout"
            fetcher={() => api.jobs.stdoutText(jobID)}
          />
          <OutputStreamPreview
            label="stderr"
            fetcher={() => api.jobs.stderrText(jobID)}
          />
        </div>
      )}
    </div>
  );
}

// LiveTailPanel polls the schedd's STARTER_PEEK protocol (the same
// path condor_tail uses) to surface stdout / stderr from a job's
// sandbox while it's still running — the OutputFilesPanel above
// only sees what got transferred back at completion. The panel
// renders only for running jobs (status=2); idle / held / completed
// jobs hide it since there's nothing live to peek at.
//
// Polling is paused by default to avoid surprise schedd / starter
// load. Hitting "Live tail" arms a 3-second loop that runs until
// the user pauses, the job leaves the running state, or the
// component unmounts. Each poll asks for the bytes since the last
// returned offset, so the wire stays small once the initial tail
// snapshot has been pulled.
function LiveTailPanel({
  jobID,
  status,
}: {
  jobID: string;
  status: number | undefined;
}) {
  const isRunning = status === 2;

  // engaged: the user has clicked "Live tail" at least once. Until
  // then we don't render the dark output area or the controls — the
  // panel stays a single button. Once engaged, it stays expanded
  // for the rest of the session even when polling is paused.
  const [engaged, setEngaged] = useState(false);

  // Tab selector — most users want stdout, but a held / failing job
  // is usually best diagnosed from stderr, so we make switching
  // cheap. Switching resets text/offset so each tab has its own
  // independent rolling window.
  const [stream, setStream] = useState<'stdout' | 'stderr'>('stdout');

  // Accumulated text + the next offset to ask for. Both reset when
  // the user switches stream or hits Clear.
  const [text, setText] = useState('');
  const [offset, setOffset] = useState<number | null>(null); // null = "tail" (-1 on the wire)
  const [active, setActive] = useState(false); // polling on?
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);

  // Auto-scroll the textarea so the latest output stays visible.
  // useRef keeps us out of React's render cycle for what's a pure
  // DOM-side effect.
  const preRef = useRef<HTMLPreElement | null>(null);
  useEffect(() => {
    if (preRef.current) {
      preRef.current.scrollTop = preRef.current.scrollHeight;
    }
  }, [text]);

  // Stop polling automatically when the job leaves the running state
  // — the starter session goes away with it, and another second of
  // polling would just produce 409s. The set-state-in-effect rule
  // doesn't have a great answer for "synchronize derived state to
  // external props"; we silence it the same way the rest of the
  // codebase does.
  useEffect(() => {
    if (!isRunning && active) {
      // eslint-disable-next-line react-hooks/set-state-in-effect
      setActive(false);
    }
  }, [isRunning, active]);

  const fetchOnce = useCallback(async () => {
    setPending(true);
    setError(null);
    try {
      const params: Parameters<typeof api.jobs.peek>[1] = { stream };
      // First call leaves offsets unset → server uses -1 (tail).
      // Subsequent calls feed the prior offset back so we only
      // pull new bytes.
      if (offset !== null) {
        if (stream === 'stdout') params.stdout_offset = offset;
        else params.stderr_offset = offset;
      }
      const res = await api.jobs.peek(jobID, params);
      const got = stream === 'stdout' ? res.stdout : res.stderr;
      if (got) {
        // First fetch (offset===null) replaces the buffer — the
        // starter returned a tail snapshot we want to display
        // verbatim. Subsequent fetches append.
        setText((prev) => (offset === null ? got.text : prev + got.text));
        setOffset(got.offset);
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setPending(false);
    }
  }, [jobID, stream, offset]);

  // Polling loop. We use setTimeout (rather than setInterval) so a
  // slow fetch can't pile up — we wait for one to complete before
  // scheduling the next.
  useEffect(() => {
    if (!active) return;
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | null = null;

    const tick = async () => {
      if (cancelled) return;
      await fetchOnce();
      if (cancelled) return;
      timer = setTimeout(tick, 3000);
    };
    void tick();

    return () => {
      cancelled = true;
      if (timer) clearTimeout(timer);
    };
  }, [active, fetchOnce]);

  const switchStream = (s: 'stdout' | 'stderr') => {
    if (s === stream) return;
    setStream(s);
    setText('');
    setOffset(null);
    setError(null);
  };

  // closePanel collapses the panel back to the unengaged state and
  // throws away the accumulated buffer + offset along the way.
  // Polling stops, the dark output area disappears, and the user is
  // back to the single "Live tail" button. Re-clicking it starts a
  // fresh tail from the current end-of-file.
  const closePanel = () => {
    setEngaged(false);
    setActive(false);
    setText('');
    setOffset(null);
    setError(null);
  };

  // Hide entirely until the job is running. Live tail only works
  // against a live starter, and showing a permanently-disabled
  // panel for idle / completed jobs is just visual noise.
  if (!isRunning) return null;

  // Job is running but the user hasn't engaged yet: show a single
  // affordance, no expansion. Clicking the button engages and starts
  // the first poll in one motion (setActive(true) primes the loop
  // effect; setEngaged(true) flips this branch off on the next
  // render).
  if (!engaged) {
    return (
      <div className="rounded border border-gray-200 bg-white p-3 flex items-center gap-3">
        <h2 className="text-sm font-medium text-gray-900">Live Tail</h2>
        <span className="text-xs text-gray-500">
          Stream stdout / stderr from the running sandbox.
        </span>
        <button
          type="button"
          onClick={() => {
            setEngaged(true);
            setActive(true);
          }}
          className="ml-auto text-xs rounded border border-brand-600 bg-white px-2 py-0.5 text-brand-700 hover:bg-brand-50"
        >
          Live tail
        </button>
      </div>
    );
  }

  return (
    <div className="rounded border border-gray-200 bg-white p-4 space-y-3">
      <div className="flex flex-wrap items-center gap-3">
        <h2 className="text-sm font-medium text-gray-900">Live Tail</h2>
        <div className="inline-flex rounded border border-gray-300 bg-white p-0.5 text-xs">
          <button
            type="button"
            onClick={() => switchStream('stdout')}
            className={`rounded px-2 py-0.5 ${
              stream === 'stdout'
                ? 'bg-gray-200 text-gray-900'
                : 'text-gray-600 hover:bg-gray-100'
            }`}
          >
            stdout
          </button>
          <button
            type="button"
            onClick={() => switchStream('stderr')}
            className={`rounded px-2 py-0.5 ${
              stream === 'stderr'
                ? 'bg-gray-200 text-gray-900'
                : 'text-gray-600 hover:bg-gray-100'
            }`}
          >
            stderr
          </button>
        </div>

        <div className="ml-auto flex items-center gap-2">
          <button
            type="button"
            onClick={() => setActive((a) => !a)}
            className={`text-xs rounded border px-2 py-0.5 ${
              active
                ? 'border-amber-500 bg-amber-50 text-amber-800 hover:bg-amber-100'
                : 'border-brand-600 bg-white text-brand-700 hover:bg-brand-50'
            }`}
          >
            {active ? 'Pause' : pending ? '…' : 'Resume'}
          </button>
          <button
            type="button"
            onClick={closePanel}
            className="inline-flex h-6 w-6 items-center justify-center rounded border border-gray-300 bg-white text-gray-500 hover:bg-gray-50 hover:text-gray-700"
            title="Close the live tail (clears the buffer)"
            aria-label="Close live tail"
          >
            <svg
              xmlns="http://www.w3.org/2000/svg"
              width="12"
              height="12"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
              aria-hidden
            >
              <line x1="18" y1="6" x2="6" y2="18" />
              <line x1="6" y1="6" x2="18" y2="18" />
            </svg>
          </button>
        </div>
      </div>

      {error && (
        <p className="text-xs text-red-700 whitespace-pre-wrap">
          {error}
        </p>
      )}

      <pre
        ref={preRef}
        className="h-64 overflow-auto rounded bg-gray-900 px-3 py-2 font-mono text-[11px] text-gray-100 whitespace-pre-wrap break-words"
      >
        {text || (
          <span className="text-gray-500">
            Waiting for output on {stream}…
          </span>
        )}
      </pre>

      {active && (
        <p className="text-[11px] text-gray-500">
          Polling every 3 seconds.{' '}
          {offset !== null && (
            <span className="text-gray-400">
              Offset: {offset.toLocaleString()} bytes
            </span>
          )}
        </p>
      )}
    </div>
  );
}

// OutputStreamPreview lazily fetches the (capped) text of a stdout or
// stderr file and renders it inside a collapsible <details>. We
// trigger the fetch on first open so unrelated detail-page traffic
// doesn't churn the schedd retrieving big files nobody asked for.
function OutputStreamPreview({
  label,
  fetcher,
}: {
  label: 'stdout' | 'stderr';
  fetcher: () => Promise<{ text: string; truncated: boolean }>;
}) {
  const [open, setOpen] = useState(false);
  const [data, setData] = useState<{ text: string; truncated: boolean } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const load = () => {
    if (data || loading) return;
    setLoading(true);
    setError(null);
    fetcher()
      .then((res) => setData(res))
      .catch((e: unknown) => setError(e instanceof Error ? e.message : String(e)))
      .finally(() => setLoading(false));
  };

  return (
    <details
      className="rounded border border-gray-200 bg-gray-50"
      onToggle={(e) => {
        const next = (e.currentTarget as HTMLDetailsElement).open;
        setOpen(next);
        if (next) load();
      }}
    >
      <summary className="cursor-pointer px-3 py-1.5 text-xs font-medium text-gray-700 hover:bg-gray-100">
        {label}{' '}
        {data && data.truncated && (
          <span className="ml-2 rounded-full bg-amber-100 px-1.5 py-0.5 text-[10px] uppercase tracking-wide text-amber-800">
            truncated to 1 MB
          </span>
        )}
      </summary>
      <div className="px-3 pb-3">
        {loading && <p className="text-xs text-gray-500">Loading…</p>}
        {error && (
          <p className="text-xs text-red-700">Could not load {label}: {error}</p>
        )}
        {data && (
          data.text === '' ? (
            <p className="text-xs italic text-gray-500">(empty)</p>
          ) : (
            <pre className="max-h-96 overflow-auto rounded border border-gray-200 bg-white p-2 text-[11px] font-mono whitespace-pre-wrap">
              {data.text}
            </pre>
          )
        )}
        {!loading && !error && !data && open && (
          // Defensive: should never see this — load() runs synchronously
          // on toggle. Surfaces cleanly if a future rewiring breaks the
          // contract.
          <p className="text-xs text-gray-500">Click to load.</p>
        )}
      </div>
    </details>
  );
}

// JobDetailsSection collects the schedd-side facts users want to see
// once they've opened a job: requested vs. used resources, environment
// (universe / IWD / restarts), and the full raw ClassAd as a
// drop-down with Copy-to-clipboard.
export function JobDetailsSection({
  jobID,
  job,
  editable = true,
}: {
  jobID: string;
  job: ClassAd;
  // editable forwards through to AttributesTable. The archive
  // detail page passes false to render the section as read-only —
  // history records are immutable.
  editable?: boolean;
}) {
  return (
    <section className="rounded border border-gray-200 bg-white">
      <header className="border-b border-gray-200 bg-gray-50 px-4 py-2.5 rounded-t">
        <h2 className="text-sm font-semibold text-gray-900">Job Details</h2>
        <p className="text-xs text-gray-500 mt-0.5">
          Resource requests vs. usage, plus the full ClassAd at the bottom.
        </p>
      </header>
      <div className="p-4 space-y-4">
        <ResourceTable job={job} />
        <ExecutionTable job={job} />
        <AttributesTable jobID={jobID} job={job} editable={editable} />
        <RawClassAd job={job} />
      </div>
    </section>
  );
}

// AttributeType is what the user picks (or what we infer from the
// existing value) to decide how to encode the new value into a
// ClassAd literal at write time. "raw" lets the user supply any
// expression — useful for references like `Memory * 2` or for
// resetting an attribute to UNDEFINED.
type AttributeType = 'string' | 'integer' | 'real' | 'boolean' | 'raw';

interface AttributeRow {
  name: string;
  value: string;        // human-readable rendering of the current value
  type: AttributeType;  // best-guess type from the JSON shape
}

// inferAttributeType picks a reasonable default editor type from a
// JSON-decoded ClassAd attribute value. The user can override in the
// edit row; we just want the dropdown to land on the most common
// answer for each kind of value. Numbers split int/real; everything
// else falls back to 'raw' (objects, arrays, expressions decoded as
// strings that already look like ClassAd code, etc.).
function inferAttributeType(v: unknown): AttributeType {
  if (typeof v === 'boolean') return 'boolean';
  if (typeof v === 'number') {
    return Number.isInteger(v) ? 'integer' : 'real';
  }
  if (typeof v === 'string') return 'string';
  return 'raw';
}

// formatAttributeForEdit renders the *editable* default text for the
// edit-row's value input given the existing value. For strings we
// surface the text *unquoted* — quotes are an encoding concern, the
// user shouldn't have to type them. Everything else round-trips
// through stringifyAdValue.
function formatAttributeForEdit(v: unknown): string {
  if (typeof v === 'string') return v;
  return stringifyAdValue(v);
}

// validateAttributeInput runs the same checks the server will run, so
// the user gets fast inline feedback ("not a valid integer") instead
// of a 400 round-trip. We deliberately do NOT do the string quoting
// here — that lives on the Go side using classad.Quote, which has the
// authoritative escape table for ClassAd literals (\, ", \n, \t,
// control chars, …). Mirroring it in JS would just recreate the
// hand-rolled-quote-loop bug we hit the first time around.
//
// Returns null if valid, or an error message string if not.
function validateAttributeInput(
  type: AttributeType,
  raw: string,
): string | null {
  switch (type) {
    case 'string':
      // Any text is a valid string; the empty string is meaningful
      // (`""` after server quoting), so don't reject.
      return null;
    case 'integer': {
      const trimmed = raw.trim();
      const n = Number.parseInt(trimmed, 10);
      if (!Number.isFinite(n) || String(n) !== trimmed) {
        return `"${raw}" is not a valid integer`;
      }
      return null;
    }
    case 'real': {
      const n = Number.parseFloat(raw.trim());
      if (!Number.isFinite(n)) return `"${raw}" is not a valid real number`;
      return null;
    }
    case 'boolean': {
      const v = raw.trim().toLowerCase();
      if (v === 'true' || v === 'false') return null;
      return `boolean must be "true" or "false", not "${raw}"`;
    }
    case 'raw':
      // Trust the user but reject empty / whitespace-only — too easy
      // to "set X to nothing" silently.
      if (raw.trim() === '') return 'expression must not be empty';
      return null;
  }
}

// AttributesTable surfaces the entire ClassAd as a searchable list,
// in between the curated Resource/Execution rollups and the raw JSON
// drop-down. Power users routinely need to peek at attributes that
// don't have first-class UI (RemoteSysCpu, JobCurrentStartDate,
// custom site-specific tags, …) without scrolling through 200 lines
// of ClassAd JSON.
//
// Rows are also editable in place — click "edit" or double-click the
// row to expand it into a value+type form. The (value, type) tuple
// is encoded into a ClassAd expression (encodeAttributeForWire) and
// PATCHed at /api/v1/jobs/{id}; the schedd refuses immutable /
// protected attributes with a 403, surfaced inline.
//
// The table caps its visible rows at MAX_VISIBLE so it doesn't push
// the rest of the page off-screen on a busy job; the rest scrolls
// inside the body. A filter input matches case-insensitively against
// either the attribute name or the rendered value.
export function AttributesTable({
  jobID,
  job,
  editable = true,
}: {
  jobID: string;
  job: ClassAd;
  // editable=false renders the table in pure read-only mode: no edit
  // button column, no double-click-to-edit, no AttributeEditRow path.
  // Used by the archive detail page since history records are
  // immutable. Defaults to true so the live-job detail page (the
  // first / canonical caller) doesn't have to opt in.
  editable?: boolean;
}) {
  const [filter, setFilter] = useState('');

  // Which row, if any, is currently in edit mode. Stored as the
  // attribute name so it survives reorders / re-renders that might
  // change row indices in the filtered list. null = nobody editing.
  const [editingName, setEditingName] = useState<string | null>(null);

  const queryClient = useQueryClient();

  const rows = useMemo<AttributeRow[]>(() => {
    const all = Object.entries(job).map(([name, raw]) => ({
      name,
      value: stringifyAdValue(raw),
      type: inferAttributeType(raw),
    }));
    all.sort((a, b) => a.name.localeCompare(b.name));
    return all;
  }, [job]);

  const filtered = useMemo(() => {
    const q = filter.trim().toLowerCase();
    if (!q) return rows;
    return rows.filter(
      (r) =>
        r.name.toLowerCase().includes(q) ||
        r.value.toLowerCase().includes(q),
    );
  }, [rows, filter]);

  // 7 rows of ~28px (py-1.5 + line-height) plus a header. Keeping
  // this in line-height-units rather than a fixed px height means
  // the cap stays right if the row padding ever shifts. The edit
  // row blows the cap when active (it has form fields), but that's
  // intentional — once you're editing, you want to see the controls
  // without scrolling.
  const MAX_VISIBLE = 7;
  const ROW_HEIGHT_PX = 28;

  return (
    <div>
      <div className="flex items-baseline justify-between gap-3 mb-2">
        <h3 className="text-xs font-semibold uppercase tracking-wide text-gray-500">
          All Attributes
        </h3>
        <span className="text-[11px] text-gray-400 tabular-nums">
          {filter ? `${filtered.length} / ${rows.length}` : `${rows.length}`}
        </span>
      </div>
      <input
        type="text"
        value={filter}
        onChange={(e) => setFilter(e.target.value)}
        placeholder="Filter by attribute name or value…"
        className="mb-2 w-full rounded border border-gray-300 px-2 py-1 text-xs"
        aria-label="Filter ClassAd attributes"
      />
      <div className="overflow-hidden rounded border border-gray-200">
        <table className="min-w-full text-xs table-fixed">
          <thead className="bg-gray-50 text-left text-[10px] uppercase tracking-wide text-gray-500">
            <tr>
              <th className="px-3 py-1.5 w-56">Attribute</th>
              <th className="px-3 py-1.5 w-20">Type</th>
              <th className="px-3 py-1.5">Value</th>
              {editable && <th className="px-3 py-1.5 w-16 text-right" />}
            </tr>
          </thead>
        </table>
        {filtered.length === 0 ? (
          <p className="px-3 py-2 text-xs text-gray-500">
            No matches.
          </p>
        ) : (
          <div
            className="overflow-y-auto"
            // Don't cap height while editing — the form needs room.
            style={
              editingName
                ? undefined
                : { maxHeight: ROW_HEIGHT_PX * MAX_VISIBLE }
            }
          >
            <table className="min-w-full text-xs table-fixed">
              <tbody className="divide-y divide-gray-100">
                {filtered.map((r) =>
                  editable && editingName === r.name ? (
                    <AttributeEditRow
                      key={r.name}
                      jobID={jobID}
                      row={r}
                      onCancel={() => setEditingName(null)}
                      onSaved={() => {
                        // Refresh the job ad so the row reflects the
                        // schedd's authoritative value (it may have
                        // canonicalised our expression).
                        queryClient.invalidateQueries({ queryKey: ['job', jobID] });
                        setEditingName(null);
                      }}
                    />
                  ) : (
                    <AttributeViewRow
                      key={r.name}
                      row={r}
                      onEdit={editable ? () => setEditingName(r.name) : undefined}
                    />
                  ),
                )}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

// AttributeViewRow is the read-only display for one attribute. The
// whole row is a click target — double-clicking enters edit mode
// (handy on laptops where the inline icon button is fiddly), and
// the explicit "edit" button at the right covers the discoverability
// case. The hover background highlights the row the cursor is on,
// which is the difference between "I'll click this" and "I think
// I'm clicking this".
function AttributeViewRow({
  row,
  onEdit,
}: {
  row: AttributeRow;
  // onEdit=undefined puts the row into pure read-only mode (no edit
  // button, no double-click handler, no "double-click to edit"
  // tooltip). Archive detail page passes undefined since history
  // records are immutable.
  onEdit?: () => void;
}) {
  return (
    <tr
      className="hover:bg-gray-50 cursor-default"
      onDoubleClick={onEdit}
      title={onEdit ? 'Double-click to edit' : undefined}
    >
      <td className="px-3 py-1.5 w-56 font-mono text-gray-700 align-top break-all">
        {row.name}
      </td>
      <td className="px-3 py-1.5 w-20 text-gray-500 align-top">
        {row.type}
      </td>
      <td className="px-3 py-1.5 font-mono text-gray-900 break-all align-top">
        {row.value}
      </td>
      {onEdit && (
        <td className="px-3 py-1.5 w-16 text-right align-top">
          <button
            type="button"
            onClick={onEdit}
            className="text-[11px] rounded border border-gray-300 bg-white px-2 py-0.5 text-gray-700 hover:bg-gray-50"
          >
            edit
          </button>
        </td>
      )}
    </tr>
  );
}

// AttributeEditRow swaps the value cell for a (type, value) pair of
// inputs and turns the trailing button into a Save / Cancel pair.
// Submission goes through api.jobs.edit; the parent invalidates the
// job query on success so the row re-renders with the persisted
// value (which may differ from what we sent — e.g. integer truncated,
// expression evaluated server-side).
function AttributeEditRow({
  jobID,
  row,
  onCancel,
  onSaved,
}: {
  jobID: string;
  row: AttributeRow;
  onCancel: () => void;
  onSaved: () => void;
}) {
  const [type, setType] = useState<AttributeType>(row.type);
  // Initial text mirrors the displayed value. Strings come out
  // un-quoted (the user types raw text — server quotes via
  // classad.Quote); booleans default to the lowercase string form so
  // the dropdown lands on the right option.
  const [text, setText] = useState(() => {
    if (row.type === 'boolean') {
      const v = row.value.trim().toLowerCase();
      return v === 'true' || v === 'false' ? v : 'true';
    }
    return formatAttributeForEdit(row.value);
  });
  const [error, setError] = useState<string | null>(null);

  // When the user changes the type dropdown, keep the value field
  // sane: switching INTO boolean snaps to "true" so the dropdown has
  // a valid selection; switching OUT preserves what they typed.
  const changeType = (next: AttributeType) => {
    setType(next);
    setError(null);
    if (next === 'boolean') {
      const v = text.trim().toLowerCase();
      if (v !== 'true' && v !== 'false') setText('true');
    }
  };

  const editMut = useMutation({
    mutationFn: async () => {
      // Send the typed shape — server does the encoding via
      // classad.Quote so we don't have to mirror Go's full string
      // escape table on the SPA side.
      return api.jobs.edit(jobID, {
        [row.name]: { type, value: text },
      });
    },
    onSuccess: () => onSaved(),
    onError: (e) =>
      setError(e instanceof Error ? e.message : String(e)),
  });

  const submit = () => {
    setError(null);
    const validation = validateAttributeInput(type, text);
    if (validation) {
      setError(validation);
      return;
    }
    editMut.mutate();
  };

  return (
    <tr className="bg-amber-50/50">
      <td className="px-3 py-1.5 w-56 font-mono text-gray-700 align-top break-all">
        {row.name}
      </td>
      <td className="px-3 py-1.5 w-20 align-top">
        <select
          value={type}
          onChange={(e) => changeType(e.target.value as AttributeType)}
          className="w-full rounded border border-gray-300 bg-white px-1 py-0.5 text-[11px]"
          aria-label="Attribute type"
        >
          <option value="string">string</option>
          <option value="integer">integer</option>
          <option value="real">real</option>
          <option value="boolean">boolean</option>
          <option value="raw">raw</option>
        </select>
      </td>
      <td className="px-3 py-1.5 align-top">
        {type === 'boolean' ? (
          // Booleans get a dropdown: free text just invites typos
          // ("True"/"yes"/"1") that fail validation, and there are
          // only two valid values anyway.
          <select
            value={text === 'false' ? 'false' : 'true'}
            onChange={(e) => setText(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') submit();
              if (e.key === 'Escape') onCancel();
            }}
            autoFocus
            className="w-full rounded border border-gray-300 bg-white px-2 py-0.5 font-mono text-xs"
            aria-label="Boolean value"
          >
            <option value="true">true</option>
            <option value="false">false</option>
          </select>
        ) : (
          <input
            type="text"
            value={text}
            onChange={(e) => setText(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') submit();
              if (e.key === 'Escape') onCancel();
            }}
            autoFocus
            spellCheck={false}
            className="w-full rounded border border-gray-300 bg-white px-2 py-0.5 font-mono text-xs"
            placeholder={
              type === 'string'
                ? 'value (typed verbatim, no quotes)'
                : type === 'raw'
                  ? 'classad expression (e.g. Memory * 2)'
                  : `${type} value`
            }
          />
        )}
        {error && (
          <p className="mt-1 text-[11px] text-red-700">{error}</p>
        )}
      </td>
      <td className="px-3 py-1.5 w-16 text-right align-top whitespace-nowrap">
        <div className="inline-flex items-center gap-1">
          <button
            type="button"
            onClick={submit}
            disabled={editMut.isPending}
            className="text-[11px] rounded border border-brand-600 bg-brand-600 px-2 py-0.5 font-medium text-white hover:bg-brand-700 disabled:opacity-50"
          >
            {editMut.isPending ? '…' : 'save'}
          </button>
          <button
            type="button"
            onClick={onCancel}
            disabled={editMut.isPending}
            className="text-[11px] rounded border border-gray-300 bg-white px-2 py-0.5 text-gray-700 hover:bg-gray-50 disabled:opacity-50"
          >
            cancel
          </button>
        </div>
      </td>
    </tr>
  );
}

// stringifyAdValue collapses any JSON-shaped attribute value to a
// short readable string. For nested objects / arrays we fall back to
// JSON.stringify so the user can still see the structure inline; the
// Raw ClassAd panel below has the pretty-printed version when they
// need it.
function stringifyAdValue(v: unknown): string {
  if (v === null || v === undefined) return '';
  if (typeof v === 'string') return v;
  if (typeof v === 'number' || typeof v === 'boolean') return String(v);
  try {
    return JSON.stringify(v);
  } catch {
    return String(v);
  }
}

export function ResourceTable({ job }: { job: ClassAd }) {
  // Each row pulls a "requested" attribute and an "actual usage"
  // attribute. Most usage attributes are present only after the job
  // has run at least once; treat absence as "—".
  const rows: { label: string; requested: string; used: string }[] = [
    {
      label: 'CPUs',
      requested: fmtRequested(job.RequestCpus),
      used: fmtUsage(job.CpusUsage ?? job.CumulativeRemoteSysCpu),
    },
    {
      label: 'Memory',
      requested: fmtMiB(job.RequestMemory),
      used: fmtMiB(job.MemoryUsage ?? job.ResidentSetSize_RAW),
    },
    {
      label: 'Disk',
      requested: fmtKiBAsMiB(job.RequestDisk),
      used: fmtKiBAsMiB(job.DiskUsage ?? job.DiskUsage_RAW),
    },
    {
      label: 'GPUs',
      requested: fmtRequested(job.RequestGpus),
      used: fmtUsage(job.GpusUsage),
    },
  ];

  // Drop GPUs row when both columns are empty (most jobs).
  const visible = rows.filter(
    (r) => !(r.label === 'GPUs' && r.requested === '—' && r.used === '—'),
  );

  return (
    <div>
      <h3 className="text-xs font-semibold uppercase tracking-wide text-gray-500 mb-2">
        Resources
      </h3>
      <div className="overflow-hidden rounded border border-gray-200">
        <table className="min-w-full text-sm">
          <thead className="bg-gray-50 text-left text-xs uppercase tracking-wide text-gray-500">
            <tr>
              <th className="px-3 py-1.5 w-32">Resource</th>
              <th className="px-3 py-1.5">Requested</th>
              <th className="px-3 py-1.5">Used</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-100">
            {visible.map((r) => (
              <tr key={r.label}>
                <td className="px-3 py-1.5 font-medium text-gray-700">{r.label}</td>
                <td className="px-3 py-1.5 text-gray-900 tabular-nums">{r.requested}</td>
                <td className="px-3 py-1.5 text-gray-900 tabular-nums">{r.used}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export function ExecutionTable({ job }: { job: ClassAd }) {
  const rows: { label: string; value: React.ReactNode }[] = [
    { label: 'Universe', value: universeLabel(job.JobUniverse) },
    { label: 'Working dir', value: monoOrDash(str(job.Iwd)) },
    {
      label: 'Last host',
      value: monoOrDash(str(job.LastRemoteHost) ?? str(job.RemoteHost)),
    },
    {
      label: 'Job starts',
      value: numOrDash(job.NumJobStarts),
    },
    {
      label: 'Restarts',
      value: numOrDash(job.NumRestarts),
    },
    {
      label: 'Exit code',
      value: exitCodeCell(job),
    },
    {
      label: 'Batch name',
      value: monoOrDash(str(job.JobBatchName)),
    },
  ];

  return (
    <div>
      <h3 className="text-xs font-semibold uppercase tracking-wide text-gray-500 mb-2">
        Execution
      </h3>
      <div className="overflow-hidden rounded border border-gray-200">
        <table className="min-w-full text-sm">
          <tbody className="divide-y divide-gray-100">
            {rows.map((r) => (
              <tr key={r.label}>
                <td className="px-3 py-1.5 w-40 font-medium text-gray-700 bg-gray-50">
                  {r.label}
                </td>
                <td className="px-3 py-1.5 text-gray-900 break-all">{r.value}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export function RawClassAd({ job }: { job: ClassAd }) {
  const [copied, setCopied] = useState(false);
  const text = JSON.stringify(job, null, 2);
  const handleCopy = () => {
    navigator.clipboard?.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };
  return (
    <details className="rounded border border-gray-200">
      <summary className="cursor-pointer flex items-center px-3 py-1.5 text-xs font-medium text-gray-700 hover:bg-gray-50">
        <span>Raw ClassAd</span>
        <button
          type="button"
          onClick={(e) => {
            e.preventDefault();
            e.stopPropagation();
            handleCopy();
          }}
          className="ml-auto rounded border border-gray-300 bg-white px-2 py-0.5 text-[11px] text-gray-700 hover:bg-gray-50"
          title="Copy raw ClassAd to clipboard"
        >
          {copied ? 'Copied' : 'Copy'}
        </button>
      </summary>
      <pre className="px-3 py-2 text-[11px] bg-gray-50 overflow-auto font-mono max-h-[32rem]">
        {text}
      </pre>
    </details>
  );
}

// --- Tiny formatting helpers -----------------------------------------

function fmtRequested(v: unknown): string {
  const n = num(v);
  return n === undefined ? '—' : n.toLocaleString();
}

function fmtUsage(v: unknown): string {
  const n = num(v);
  if (n === undefined) return '—';
  if (n === 0) return '0';
  // Most "usage" attributes are integer counters; round to 0–1
  // decimals for readability.
  return n >= 100 ? n.toLocaleString() : n.toLocaleString(undefined, { maximumFractionDigits: 1 });
}

// Memory request lands in MiB on HTCondor's wire; same for usage.
function fmtMiB(v: unknown): string {
  const n = num(v);
  if (n === undefined) return '—';
  return `${n.toLocaleString()} MiB`;
}

// Disk request lands in KiB on HTCondor's wire (yes, really —
// RequestDisk and DiskUsage are kilobytes). Display as MiB for sane
// reading.
function fmtKiBAsMiB(v: unknown): string {
  const n = num(v);
  if (n === undefined) return '—';
  const mib = n / 1024;
  return `${mib.toLocaleString(undefined, { maximumFractionDigits: 1 })} MiB`;
}

function numOrDash(v: unknown): React.ReactNode {
  const n = num(v);
  return n === undefined ? '—' : <span className="tabular-nums">{n}</span>;
}

function monoOrDash(s: string | undefined): React.ReactNode {
  return s ? <span className="font-mono text-xs">{s}</span> : '—';
}

function universeLabel(v: unknown): string {
  const n = num(v);
  // From condor_attributes.h:
  //   STANDARD=1, VANILLA=5, SCHEDULER=7, MPI=8, GRID=9, JAVA=10,
  //   PARALLEL=11, LOCAL=12, VM=13, DOCKER=14
  switch (n) {
    case 1:
      return 'Standard';
    case 5:
      return 'Vanilla';
    case 7:
      return 'Scheduler';
    case 8:
      return 'MPI';
    case 9:
      return 'Grid';
    case 10:
      return 'Java';
    case 11:
      return 'Parallel';
    case 12:
      return 'Local';
    case 13:
      return 'VM';
    case 14:
      return 'Docker';
    default:
      return n === undefined ? '—' : `Universe ${n}`;
  }
}

function exitCodeCell(job: ClassAd): React.ReactNode {
  const exitCode = num(job.ExitCode);
  const exitBySignal = job.ExitBySignal === true || job.ExitBySignal === 'true';
  const exitSignal = num(job.ExitSignal);
  if (exitBySignal && exitSignal !== undefined) {
    return (
      <span className="tabular-nums">
        killed by signal {exitSignal}
      </span>
    );
  }
  if (exitCode === undefined) return '—';
  const cls = exitCode === 0 ? 'text-green-700' : 'text-red-700';
  return <span className={`tabular-nums ${cls}`}>{exitCode}</span>;
}

export function Field({
  label,
  value,
  sub,
  mono,
  full,
  warn,
}: {
  label: string;
  value: React.ReactNode;
  // Optional secondary line shown below the value in muted text.
  // Used for relative timestamps ("12h3m ago") under absolute ones.
  sub?: React.ReactNode;
  mono?: boolean;
  full?: boolean;
  warn?: boolean;
}) {
  return (
    <div className={full ? 'col-span-2' : ''}>
      <div className="text-xs uppercase tracking-wide text-gray-500">
        {label}
      </div>
      <div
        className={`mt-0.5 ${mono ? 'font-mono text-xs' : 'text-sm'} ${
          warn ? 'text-red-700' : 'text-gray-900'
        } break-words`}
      >
        {value}
      </div>
      {sub && (
        <div className="mt-0.5 text-xs text-gray-500 tabular-nums">{sub}</div>
      )}
    </div>
  );
}

// statusPillCls maps a DisplayStatus key to a Tailwind class for the
// pill badge. Kept colocated with StatusBadge so the listing page can
// re-export the same lookup.
export function statusPillCls(key: DisplayStatus): string {
  switch (key) {
    case 'running':
      return 'bg-green-100 text-green-800';
    case 'idle':
      return 'bg-blue-100 text-blue-800';
    case 'held':
      return 'bg-red-100 text-red-800';
    case 'completed':
      return 'bg-gray-100 text-gray-700';
    case 'uploading':
      // Uploading is genuinely "in progress" from the user's POV;
      // amber matches the "transferring output" mood.
      return 'bg-amber-100 text-amber-800';
    case 'transferring':
    case 'suspended':
    case 'removed':
      return 'bg-amber-100 text-amber-800';
    case 'unknown':
    default:
      return 'bg-gray-100 text-gray-500';
  }
}

export function StatusBadge({
  display,
}: {
  display: { key: DisplayStatus; label: string };
}) {
  return (
    <span
      className={`inline-flex rounded-full px-2 py-0.5 text-xs font-medium ${statusPillCls(display.key)}`}
    >
      {display.label}
    </span>
  );
}

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

// humanDuration renders a non-negative number of seconds as a compact
// "1d2h", "5h3m", "12m4s", or "30s" string. Negative inputs are
// clamped to 0 so a slight clock skew between the client and the
// schedd's wallclock doesn't produce nonsense like "-3s ago".
export function humanDuration(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds < 0) seconds = 0;
  const s = Math.floor(seconds);
  if (s < 60) return `${s}s`;

  const days = Math.floor(s / 86400);
  const hrs = Math.floor((s % 86400) / 3600);
  const mins = Math.floor((s % 3600) / 60);
  const secs = s % 60;

  // Two most-significant non-zero units. Pick the right pair so a
  // 3-day-2-hour-old job doesn't display "3d0h2h" or drop the hours.
  if (days > 0) return hrs > 0 ? `${days}d${hrs}h` : `${days}d`;
  if (hrs > 0) return mins > 0 ? `${hrs}h${mins}m` : `${hrs}h`;
  return secs > 0 ? `${mins}m${secs}s` : `${mins}m`;
}

function num(v: unknown): number | undefined {
  if (typeof v === 'number') return v;
  if (typeof v === 'string') {
    const n = Number(v);
    if (!Number.isNaN(n)) return n;
  }
  return undefined;
}

function str(v: unknown): string | undefined {
  if (typeof v === 'string') return v;
  if (v === undefined || v === null) return undefined;
  return String(v);
}
