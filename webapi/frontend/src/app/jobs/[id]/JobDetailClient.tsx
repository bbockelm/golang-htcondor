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
  type DagGraphGroup,
  type DagGraphResponse,
  type DisplayStatus,
} from '@/lib/api';
import { useResolvedParams } from '@/lib/useResolvedParams';
import { summarizeRequirements, standardLabels } from '@/lib/requirements';
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

  // Hold is the counterpart to Release, and offered on the same terms
  // Remove is: anything not already finished. A held job is excluded
  // because holding it again does nothing, and the button beside it
  // already says Release.
  const holdMut = useMutation({
    mutationFn: () => api.jobs.hold(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['jobs'] });
      queryClient.invalidateQueries({ queryKey: ['job', id] });
    },
  });
  const canHold = data !== undefined && !isTerminal && !isHeld;

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
              className="rounded-sm border border-brand-600 bg-white px-3 py-1.5 text-sm font-medium text-brand-700 hover:bg-brand-50 disabled:opacity-50"
              title={`Release held job ${id}`}
            >
              {releaseMut.isPending ? 'Releasing…' : 'Release'}
            </button>
          )}
          {canHold && (
            <button
              type="button"
              onClick={() => holdMut.mutate()}
              disabled={holdMut.isPending}
              className="rounded-sm border border-gray-300 bg-white px-3 py-1.5 text-sm font-medium text-gray-700 hover:bg-gray-50 disabled:opacity-50"
              title={`Hold job ${id}`}
            >
              {holdMut.isPending ? 'Holding…' : 'Hold'}
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

      {holdMut.error && (
        <div className="rounded-sm border border-red-200 bg-red-50 p-3 text-sm text-red-700">
          Hold failed:{' '}
          {holdMut.error instanceof ApiError
            ? holdMut.error.message
            : String(holdMut.error)}
        </div>
      )}

      {removeMut.error && (
        <div className="rounded-sm border border-red-200 bg-red-50 p-3 text-sm text-red-700">
          Remove failed:{' '}
          {removeMut.error instanceof ApiError
            ? removeMut.error.message
            : String(removeMut.error)}
        </div>
      )}

      {releaseMut.error && (
        <div className="rounded-sm border border-red-200 bg-red-50 p-3 text-sm text-red-700">
          Release failed:{' '}
          {releaseMut.error instanceof ApiError
            ? releaseMut.error.message
            : String(releaseMut.error)}
        </div>
      )}

      {isLoading && <p className="text-gray-400">Loading...</p>}

      {error && (
        <div className="rounded-sm border border-red-200 bg-red-50 p-3 text-sm text-red-700">
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

      <div className="rounded-sm border border-gray-200 bg-white p-4 grid grid-cols-2 gap-3 text-sm">
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

      <OutputFilesPanel jobID={jobID} status={status} job={job} />

      <WorkflowLogPanel jobID={jobID} job={job} />

      <WorkflowGraphPanel jobID={jobID} job={job} />

      <LiveTailPanel jobID={jobID} status={status} job={job} />

      <TerminalPanel jobID={jobID} status={status} job={job} />

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

      <RequirementsSection job={job} />

      <JobDetailsSection jobID={jobID} job={job} />
    </div>
  );
}

// RequirementsSection turns the job's Requirements AND-tree into a line per
// notable clause plus a single "standard resource requirements" summary,
// so the interesting constraint (a machine/pool pin) isn't buried in
// boilerplate. The full expression stays available behind a disclosure.
function RequirementsSection({ job }: { job: ClassAd }) {
  const summary = summarizeRequirements(str(job.Requirements));
  if (summary.empty) return null;
  const labels = standardLabels(summary.standard);
  const nothingNotable = summary.notable.length === 0 && !summary.hasStandard;
  return (
    <div className="space-y-3 rounded-lg border border-gray-200 bg-white p-4">
      <h2 className="text-sm font-semibold text-gray-900">Requirements</h2>
      {nothingNotable ? (
        <p className="text-sm text-gray-500">
          No constraints beyond the ClassAd defaults.
        </p>
      ) : (
        <ul className="space-y-1.5">
          {summary.notable.map((clause, i) => (
            <li key={i} className="flex items-start gap-2 text-sm">
              <span className="mt-0.5 text-brand-500" aria-hidden>
                •
              </span>
              <code className="break-all font-mono text-gray-900">{clause}</code>
            </li>
          ))}
          {summary.hasStandard && (
            <li className="flex items-start gap-2 text-sm text-gray-500">
              <span className="mt-0.5" aria-hidden>
                •
              </span>
              <span>
                Standard resource requirements
                {labels.length > 0 && <> ({labels.join(', ')})</>}
              </span>
            </li>
          )}
        </ul>
      )}
      <details className="text-xs">
        <summary className="cursor-pointer text-gray-400 hover:text-gray-600">
          Show raw expression
        </summary>
        <pre className="mt-2 overflow-x-auto whitespace-pre-wrap rounded-sm bg-gray-50 p-2 font-mono text-gray-700">
          {summary.raw}
        </pre>
      </details>
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
  // Universe, because it decides which of the tools the model has are
  // even possible: run_in_job and ssh-to-job need a starter, and
  // scheduler / grid universe never have one. Without this the model
  // proposed run_in_job for a running DAGMan manager on every turn.
  const universe = num(job.JobUniverse);
  if (universe !== undefined) {
    parts.push(
      `universe=${universeLabel(universe)} (JobUniverse=${universe})` +
        (supportsRemoteAccess(job)
          ? ''
          : ' — no starter: run_in_job and ssh-to-job are unavailable for this universe'),
    );
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
  job,
}: {
  jobID: string;
  status: number | undefined;
  job: ClassAd;
}) {
  const [open, setOpen] = useState(false);

  // condor_ssh_to_job only works while the job is Running (2) or
  // Transferring Output (6). Anything else, surface a hint and don't even
  // mount the WebSocket.
  const canSSH = (status === 2 || status === 6) && supportsRemoteAccess(job);

  // Scheduler and grid universe have no starter to ssh into, ever. The
  // card used to render anyway with "Available while the job is
  // running" -- which for a scheduler-universe job that IS running
  // reads as a bug in the page rather than as a property of the job.
  if (!supportsRemoteAccess(job)) return null;

  return (
    <div className="rounded-sm border border-gray-200 bg-white p-4 space-y-3">
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
          className="rounded-sm border border-gray-300 bg-white px-3 py-1.5 text-sm text-gray-700 hover:bg-gray-50"
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
// Output files land in the schedd's spool when the starter transfers
// them back, which happens when the job finishes -- JobStatus 4
// (Completed) or 3 (Removed, after a rough exit).
//
// Finishing is not the only way to get there. A job that ran and was
// then put back in the queue -- held mid-run, evicted, released to idle
// for another attempt -- can have left a sandbox behind from the
// attempt that ended, and gating on the terminal states alone greys out
// the download for exactly the case where somebody is trying to find
// out what the failed attempt produced.
//
// So the gate is "has this job ever run, in an attempt that is over" --
// plus scheduler universe, which writes into its spool as it goes and
// so has files to serve while it is still running. outputReadiness()
// below everRan() is where that lives, along with the wording; what it
// cannot promise is that files are actually there, so the hint says
// "may" and the download is allowed to come back empty rather than
// being refused here on a guess.
function OutputFilesPanel({
  jobID,
  status,
  job,
}: {
  jobID: string;
  status: number | undefined;
  job?: ClassAd;
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

  const { ready, hint } = outputReadiness(job, status);

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
            className="text-sm rounded-sm bg-brand-600 px-3 py-1.5 text-white hover:bg-brand-700"
            download
          >
            Download as tar
          </a>
        ) : (
          <button
            type="button"
            disabled
            className="text-sm rounded-sm bg-brand-600 px-3 py-1.5 text-white opacity-60 cursor-not-allowed"
            title={hint ?? ''}
          >
            Download as tar
          </button>
        )}
        <button
          onClick={() => shareMut.mutate()}
          disabled={!ready || shareMut.isPending}
          className="text-sm rounded-sm border border-gray-300 bg-white px-3 py-1.5 text-gray-700 hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed"
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
        <div className="rounded-sm border border-amber-200 bg-amber-50 p-3 text-xs space-y-2">
          <div className="text-amber-900">
            Anyone with this link can download the output files until{' '}
            <strong>{share.expires.toLocaleString()}</strong>.
          </div>
          <div className="flex gap-2">
            <input
              readOnly
              value={share.url}
              className="flex-1 min-w-0 rounded-sm border border-amber-300 bg-white px-2 py-1 font-mono"
              onFocus={(e) => e.currentTarget.select()}
            />
            <button
              onClick={handleCopy}
              className="rounded-sm bg-amber-200 px-2 py-1 text-amber-900 hover:bg-amber-300 min-w-16"
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
  job,
}: {
  jobID: string;
  status: number | undefined;
  job: ClassAd;
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

  // Hide entirely until the job is running, and for the universes with
  // no starter behind them. Live tail only works against a live
  // starter: the schedd refuses GET_JOB_CONNECT_INFO for scheduler and
  // grid universe outright, so offering the button there buys the user
  // a 409 and nothing else. (A scheduler-universe job's output is not
  // lost -- it is in the spool, and the Output Files panel above
  // serves it live.)
  if (!isRunning || !supportsRemoteAccess(job)) return null;

  // Job is running but the user hasn't engaged yet: show a single
  // affordance, no expansion. Clicking the button engages and starts
  // the first poll in one motion (setActive(true) primes the loop
  // effect; setEngaged(true) flips this branch off on the next
  // render).
  if (!engaged) {
    return (
      <div className="rounded-sm border border-gray-200 bg-white p-3 flex items-center gap-3">
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
          className="ml-auto text-xs rounded-sm border border-brand-600 bg-white px-2 py-0.5 text-brand-700 hover:bg-brand-50"
        >
          Live tail
        </button>
      </div>
    );
  }

  return (
    <div className="rounded-sm border border-gray-200 bg-white p-4 space-y-3">
      <div className="flex flex-wrap items-center gap-3">
        <h2 className="text-sm font-medium text-gray-900">Live Tail</h2>
        <div className="inline-flex rounded-sm border border-gray-300 bg-white p-0.5 text-xs">
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
            className="inline-flex h-6 w-6 items-center justify-center rounded-sm border border-gray-300 bg-white text-gray-500 hover:bg-gray-50 hover:text-gray-700"
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
        className="h-64 overflow-auto rounded-sm bg-gray-900 px-3 py-2 font-mono text-[11px] text-gray-100 whitespace-pre-wrap wrap-break-word"
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
// `caption` is a one-line note rendered under the content -- used to
// say what a fetch costs where that isn't obvious. `refreshable` adds a
// Refresh button for content that changes under a job that is still
// running; deliberately opt-in and deliberately not a timer.
function OutputStreamPreview({
  label,
  fetcher,
  caption,
  refreshable = false,
}: {
  label: string;
  fetcher: () => Promise<{ text: string; truncated: boolean }>;
  caption?: string;
  refreshable?: boolean;
}) {
  const [open, setOpen] = useState(false);
  const [data, setData] = useState<{ text: string; truncated: boolean } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const fetchNow = () => {
    setLoading(true);
    setError(null);
    fetcher()
      .then((res) => setData(res))
      .catch((e: unknown) => setError(e instanceof Error ? e.message : String(e)))
      .finally(() => setLoading(false));
  };

  const load = () => {
    if (data || loading) return;
    fetchNow();
  };

  return (
    <details
      className="rounded-sm border border-gray-200 bg-gray-50"
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
            <pre className="max-h-96 overflow-auto rounded-sm border border-gray-200 bg-white p-2 text-[11px] font-mono whitespace-pre-wrap">
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
        {open && (refreshable || caption) && (
          <div className="mt-2 flex items-center gap-3">
            {refreshable && (
              <button
                type="button"
                onClick={fetchNow}
                disabled={loading}
                className="rounded-sm border border-gray-300 bg-white px-2 py-0.5 text-[11px] text-gray-700 hover:bg-gray-50 disabled:opacity-50"
              >
                {loading ? 'Loading…' : 'Refresh'}
              </button>
            )}
            {caption && <span className="text-[11px] text-gray-500">{caption}</span>}
          </div>
        )}
      </div>
    </details>
  );
}

// WorkflowLogPanel surfaces a DAGMan manager's own log -- the
// *.dagman.out that says which nodes were submitted, which failed and
// what the manager is waiting on. Nothing else on the page answers
// "what is this workflow doing right now": the manager is a
// scheduler-universe job, so there is no starter, no tail and no
// terminal, and the useful file is simply sitting in the spool.
//
// Fetched only when the user opens it and only again when they ask.
// There is no single-file protocol between this server and the schedd:
// each of these re-transfers the whole set of files the job has changed
// since it started, so a poll loop here would be a poll loop over the
// entire workflow's spool. The caption says as much rather than leaving
// the cost invisible.
function WorkflowLogPanel({ jobID, job }: { jobID: string; job: ClassAd }) {
  // Scheduler universe is the manager; a DAGMan *node* job carries none
  // of these attributes and gets nothing here.
  if (num(job.JobUniverse) !== 7) return null;
  const { available, name, reason } = workflowLogAvailability(job);
  if (!name) return null;

  return (
    <div className="rounded-sm border border-gray-200 bg-white p-4 space-y-3">
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-medium text-gray-900">Workflow log</h2>
        {available && (
          <span className="text-xs text-gray-400">
            DAGMan manager output, from the job&apos;s spool.
          </span>
        )}
      </div>
      {available ? (
        <OutputStreamPreview
          label={name}
          refreshable
          caption="Each load re-fetches the workflow's spool from the access point."
          fetcher={() => api.jobs.fileText(jobID, name)}
        />
      ) : (
        // Not hidden: the panel's job is to answer "where is my DAG's
        // log", and for a shell-submitted workflow the answer is a
        // path, not a viewer. Offering a load button here would just
        // buy the user a 404 from the schedd's empty spool.
        <p className="text-xs text-gray-600">{reason}</p>
      )}
    </div>
  );
}

// --- Workflow graph -------------------------------------------------
//
// The panel below draws GET /api/v1/jobs/{id}/dag: the workflow's
// structure, collapsed so that nodes doing the same job in the same
// place are one shape. The collapse is what makes it drawable at all --
// a 50,000-way fan-out is two boxes and one line here -- and it is also
// the one thing a reader has to be told about, which is why the
// some-to-some note below is rendered rather than left in a comment.
//
// Everything here is explicit-load. There is no single-file protocol
// between this server and the schedd, so a cache miss re-transfers the
// workflow's whole spool; a poll loop would be a poll loop over every
// file the workflow has written.

// Box geometry for the drawing. Fixed rather than measured: the
// collapsed graph is small by construction, and measuring would buy a
// layout pass for a picture that is usually five boxes.
const DAG_BOX_W = 176;
const DAG_BOX_H = 58;
const DAG_H_GAP = 26;
const DAG_V_GAP = 72;
const DAG_PAD = 16;

// Past these the drawing stops being a drawing. A layer wider than
// DAG_MAX_LAYER is a wall of boxes nobody can trace an edge through,
// and a graph with more than DAG_MAX_GROUPS shapes is not a summary of
// anything. Rather than shrink the text to nothing (or attempt a real
// layout, which is a graph library's job and not this panel's), the
// panel says so and falls back to the group list.
const DAG_MAX_LAYER = 40;
const DAG_MAX_GROUPS = 150;

// dagLayers assigns every group a layer and returns the layers in
// drawing order, top to bottom. layer(g) is the longest path to g from
// any root, which is the assignment that makes every edge point
// strictly downwards -- the property that makes the picture readable.
//
// O(V+E): one pass to build the forward/reverse indexes, then a Kahn
// sweep that relaxes each child's layer as its parents settle. Within a
// layer the order is first appearance in `groups`, so the same response
// always draws the same picture; keying off Map/Set iteration order
// instead would reshuffle the row whenever the server reordered its
// array.
//
// Two inputs must not break it, because both arrive from real (torn or
// spliced) DAG files:
//   - a parent_ids entry naming a group that is not in the list. It is
//     dropped: treating a dangling reference as a real parent leaves
//     its child permanently unsettled, i.e. invisible.
//   - a cycle. The server flags that as approximate_layering; here the
//     members Kahn could not settle are placed just under the deepest
//     parent that did settle, rather than dropped.
export function dagLayers(
  groups: readonly { id: string; parent_ids?: string[] | null }[],
): string[][] {
  // Insertion order is first appearance, and every ordering below reads
  // it back out of this Map.
  const order = new Map<string, number>();
  groups.forEach((g, i) => {
    if (!order.has(g.id)) order.set(g.id, i);
  });
  if (order.size === 0) return [];

  const parents = new Map<string, string[]>();
  const children = new Map<string, string[]>();
  const indegree = new Map<string, number>();
  for (const id of order.keys()) {
    parents.set(id, []);
    children.set(id, []);
    indegree.set(id, 0);
  }
  for (const g of groups) {
    const seen = new Set<string>();
    for (const p of g.parent_ids ?? []) {
      // Self-edges and duplicates would each leave a permanent +1 on
      // the indegree, which is the same failure as a dangling parent.
      if (p === g.id || !order.has(p) || seen.has(p)) continue;
      seen.add(p);
      parents.get(g.id)!.push(p);
      children.get(p)!.push(g.id);
      indegree.set(g.id, indegree.get(g.id)! + 1);
    }
  }

  const layer = new Map<string, number>();
  const queue: string[] = [];
  for (const id of order.keys()) {
    if (indegree.get(id) === 0) {
      layer.set(id, 0);
      queue.push(id);
    }
  }
  for (let i = 0; i < queue.length; i++) {
    const id = queue[i];
    const at = layer.get(id)!;
    for (const c of children.get(id)!) {
      // Longest path, not shortest: a node with parents at depth 1 and
      // depth 3 belongs under the depth-3 one, or its edge points up.
      layer.set(c, Math.max(layer.get(c) ?? 0, at + 1));
      const left = indegree.get(c)! - 1;
      indegree.set(c, left);
      if (left === 0) queue.push(c);
    }
  }

  // Anything Kahn left unsettled is in a cycle. Place it below whatever
  // parent did settle, in input order so the result stays deterministic.
  for (const id of order.keys()) {
    if (layer.has(id)) continue;
    let deepest = -1;
    for (const p of parents.get(id)!) {
      const pl = layer.get(p);
      if (pl !== undefined) deepest = Math.max(deepest, pl);
    }
    layer.set(id, deepest + 1);
  }

  let depth = 0;
  for (const l of layer.values()) depth = Math.max(depth, l);
  const layers: string[][] = Array.from({ length: depth + 1 }, () => []);
  for (const id of order.keys()) layers[layer.get(id)!].push(id);
  return layers;
}

// DAG_STATE_STYLES is the one place a node state's urgency and its
// colour are decided, MOST URGENT FIRST.
//
// The order is the answer to "where is my workflow stuck", which is the
// question the panel exists for. A group holding one failed node among
// ninety-nine done ones is a red box, because the ninety-nine are not
// what the reader came to find; `done` sorts last for the same reason.
//
// Colours are the app's own job-status tokens (statusPillCls) rather
// than a palette of this panel's, so red here means what red means in
// the status pill at the top of the page. DAGMan has states JobStatus
// does not -- failed, futile, ready, unready, prerun/postrun -- so this
// is a superset, and those borrow the nearest token deliberately.
//
// `shape` is the SVG twin of `pill`: Tailwind's bg-/text- utilities do
// nothing to a <rect>, so a drawn box needs fill-/stroke- equivalents
// of the same colours.
const DAG_STATE_STYLES: readonly {
  state: string;
  pill: string;
  shape: string;
}[] = [
  // Stopped, and not on purpose. These two are why anyone opens this.
  { state: 'failed', pill: statusPillCls('held'), shape: 'fill-red-100 stroke-red-400' },
  { state: 'held', pill: statusPillCls('held'), shape: 'fill-red-100 stroke-red-400' },
  // Futile: an ancestor failed, so this node can never run. Not itself
  // broken, but it is the blast radius of the thing that is.
  { state: 'futile', pill: 'bg-orange-100 text-orange-800', shape: 'fill-orange-100 stroke-orange-400' },
  { state: 'removed', pill: statusPillCls('removed'), shape: 'fill-amber-100 stroke-amber-400' },
  { state: 'suspended', pill: statusPillCls('suspended'), shape: 'fill-amber-100 stroke-amber-400' },
  { state: 'running', pill: statusPillCls('running'), shape: 'fill-green-100 stroke-green-500' },
  // PRE and POST scripts run on the access point, not in the pool; they
  // are progress, so they share the "in flight" amber.
  { state: 'prerun', pill: statusPillCls('transferring'), shape: 'fill-amber-100 stroke-amber-400' },
  { state: 'postrun', pill: statusPillCls('transferring'), shape: 'fill-amber-100 stroke-amber-400' },
  { state: 'transferring', pill: statusPillCls('transferring'), shape: 'fill-amber-100 stroke-amber-400' },
  { state: 'submitted', pill: statusPillCls('idle'), shape: 'fill-blue-100 stroke-blue-400' },
  { state: 'idle', pill: statusPillCls('idle'), shape: 'fill-blue-100 stroke-blue-400' },
  { state: 'ready', pill: statusPillCls('idle'), shape: 'fill-blue-50 stroke-blue-300' },
  { state: 'unready', pill: statusPillCls('unknown'), shape: 'fill-white stroke-gray-300' },
  { state: 'done', pill: statusPillCls('completed'), shape: 'fill-gray-200 stroke-gray-400' },
];

const DAG_STATE_INDEX = new Map(DAG_STATE_STYLES.map((s, i) => [s.state, i]));

// dagStateRank orders node states by urgency, lowest number first.
//
// An unrecognised state ranks LAST -- below `done`. A state name this
// UI has not seen is not evidence of trouble, and ranking the unknown
// above `failed` would let a server-side rename silently recolour every
// group in every workflow red.
export function dagStateRank(state: string): number {
  const i = DAG_STATE_INDEX.get(state);
  return i === undefined ? DAG_STATE_STYLES.length : i;
}

// dagStatePill / dagStateShape: the badge and the drawn-box classes for
// a node state. Unknown states fall back to the app's "unknown" grey
// rather than to nothing, so an unrecognised state still renders.
export function dagStatePill(state: string): string {
  const i = DAG_STATE_INDEX.get(state);
  return i === undefined ? statusPillCls('unknown') : DAG_STATE_STYLES[i].pill;
}

export function dagStateShape(state: string): string {
  const i = DAG_STATE_INDEX.get(state);
  return i === undefined ? 'fill-gray-100 stroke-gray-400' : DAG_STATE_STYLES[i].shape;
}

// dagStatusEntries turns a group's histogram into a most-urgent-first
// list. Zero counts are dropped -- a server that emits every state with
// a count would otherwise fill the box with "0 held, 0 failed" -- and
// ties break on the name so the row is stable.
export function dagStatusEntries(
  status: Record<string, number> | null | undefined,
): { state: string; count: number }[] {
  return Object.entries(status ?? {})
    .filter(([, n]) => typeof n === 'number' && n > 0)
    .map(([state, count]) => ({ state, count }))
    .sort(
      (a, b) =>
        dagStateRank(a.state) - dagStateRank(b.state) ||
        a.state.localeCompare(b.state),
    );
}

// dominantDagState is the state a group's box is coloured by: the most
// URGENT state present, not the most numerous. One failed node among a
// thousand done ones is the fact the picture has to carry; averaging it
// away would make the panel answer a question nobody asked.
export function dominantDagState(
  status: Record<string, number> | null | undefined,
): string | undefined {
  return dagStatusEntries(status)[0]?.state;
}

// workflowGraphAvailability decides whether the Workflow graph panel
// renders at all, and what it says when it cannot draw.
//
// Same gate as the workflow log, for the same reason: the picture is
// read out of the schedd's spool, and a workflow submitted from a shell
// on the access point keeps its files in the user's own directory where
// nothing here can reach them.
//
// applicable=false means "this job is not a DAGMan manager" and the
// page gets no panel. A manager that was not spooled DOES get the
// panel, with one sentence: "why is there no graph" is a question worth
// an answer, and silence answers it worse.
export function workflowGraphAvailability(job: ClassAd): {
  applicable: boolean;
  available: boolean;
  reason?: string;
} {
  // dagmanLogName returning a name is the existing "is this a DAGMan
  // manager" test -- it keys off Cmd/-Dag, not off the log file.
  if (!dagmanLogName(job)) return { applicable: false, available: false };
  if (isSpooledJob(job)) return { applicable: true, available: true };
  return {
    applicable: true,
    available: false,
    // Deliberately NOT opening with the workflow log panel's sentence:
    // both panels render on this page for this job, and two paragraphs
    // starting identically read as one repeated.
    reason:
      "This workflow's structure files are not readable through this server: it was submitted " +
      'from a shell on the access point, so the .dot graph and node status file DAGMan writes ' +
      `are in ${str(job.Iwd) ?? 'the submit directory'}. Use condor_q -dag on the access point instead.`,
  };
}

// WorkflowGraphPanel draws the collapsed workflow. Explicit load, one
// Refresh button, no timer: see the block comment above for why.
function WorkflowGraphPanel({ jobID, job }: { jobID: string; job: ClassAd }) {
  const { applicable, available, reason } = workflowGraphAvailability(job);
  const [data, setData] = useState<DagGraphResponse | null>(null);
  // notice vs error: a 409 is the server telling us this workflow has
  // nothing to show and why, in a sentence already written for a human.
  // It is prose, not a failure.
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [selected, setSelected] = useState<string | null>(null);

  const load = useCallback(
    (refresh: boolean) => {
      setLoading(true);
      setError(null);
      setNotice(null);
      api.jobs
        .dagGraph(jobID, refresh ? { refresh: true } : undefined)
        .then((res) => {
          setData(res);
          // Keep the open group open across a refresh, but only if it
          // still exists -- a vanished group would leave the detail box
          // showing an empty member list with no explanation.
          setSelected((prev) =>
            prev && (res.groups ?? []).some((g) => g.id === prev) ? prev : null,
          );
        })
        .catch((e: unknown) => {
          if (e instanceof ApiError && e.status === 409) {
            setNotice(e.message);
            setData(null);
            setSelected(null);
            return;
          }
          setError(e instanceof Error ? e.message : String(e));
        })
        .finally(() => setLoading(false));
    },
    [jobID],
  );

  if (!applicable) return null;

  const loaded = data !== null || notice !== null;
  return (
    <div className="rounded-sm border border-gray-200 bg-white p-4 space-y-3">
      <div className="flex items-center justify-between gap-3">
        <h2 className="text-sm font-medium text-gray-900">Workflow graph</h2>
        {available && (
          <button
            type="button"
            onClick={() => load(loaded)}
            disabled={loading}
            className="rounded-sm border border-gray-300 bg-white px-3 py-1.5 text-xs font-medium text-gray-700 hover:bg-gray-50 disabled:opacity-50"
          >
            {loading
              ? loaded
                ? 'Refreshing…'
                : 'Loading…'
              : loaded
                ? 'Refresh'
                : 'Load graph'}
          </button>
        )}
      </div>

      {!available ? (
        // Not hidden, for the same reason the workflow log is not: the
        // panel's job is to answer "what does my workflow look like",
        // and a path is a better answer than an empty space.
        <p className="text-xs text-gray-600">{reason}</p>
      ) : (
        <>
          <p className="text-xs text-gray-500">
            The workflow&apos;s structure, with nodes that run the same thing
            in the same place drawn as one box. Loading is answered from a
            server-side cache and is cheap; <strong>Refresh</strong> is not
            — it re-fetches the workflow&apos;s entire spool from the access
            point to re-read the structure and node-status files. Nothing
            here polls.
          </p>

          {error && (
            <div className="rounded-sm border border-red-200 bg-red-50 p-3 text-xs text-red-700">
              Could not load the workflow graph: {error}
            </div>
          )}
          {notice && <p className="text-xs text-gray-600">{notice}</p>}
          {loading && !data && (
            <p className="text-xs text-gray-500">Loading…</p>
          )}

          {data && (
            <WorkflowGraphBody
              data={data}
              selected={selected}
              onSelect={setSelected}
              onRefresh={() => load(true)}
              refreshing={loading}
            />
          )}
        </>
      )}
    </div>
  );
}

// WorkflowGraphBody is everything below the Load button once there is a
// response: the honesty banners, the drawing, the caveat the drawing
// cannot state for itself, and the per-group detail.
function WorkflowGraphBody({
  data,
  selected,
  onSelect,
  onRefresh,
  refreshing,
}: {
  data: DagGraphResponse;
  selected: string | null;
  onSelect: (id: string | null) => void;
  onRefresh: () => void;
  refreshing: boolean;
}) {
  const groups = useMemo(() => data.groups ?? [], [data]);
  const layers = useMemo(() => dagLayers(groups), [groups]);
  const widest = layers.reduce((m, l) => Math.max(m, l.length), 0);
  const drawable =
    groups.length > 0 &&
    groups.length <= DAG_MAX_GROUPS &&
    widest <= DAG_MAX_LAYER;
  const open = selected ? groups.find((g) => g.id === selected) : undefined;

  return (
    <div className="space-y-3">
      <DagBanners data={data} onRefresh={onRefresh} refreshing={refreshing} />

      <p className="text-xs text-gray-500">
        <span className="tabular-nums">{data.node_count.toLocaleString()}</span>{' '}
        nodes and{' '}
        <span className="tabular-nums">{data.edge_count.toLocaleString()}</span>{' '}
        dependencies, collapsed into{' '}
        <span className="tabular-nums">{groups.length.toLocaleString()}</span>{' '}
        groups
        {/* link_count is one of the fields not every server version
            copies into the response; show it only when it is there. */}
        {data.link_count !== undefined && (
          <>
            {' '}
            joined by{' '}
            <span className="tabular-nums">
              {data.link_count.toLocaleString()}
            </span>{' '}
            links
          </>
        )}
        .
      </p>

      {groups.length === 0 ? (
        <p className="text-xs text-gray-600">
          The structure file named no nodes, so there is nothing to draw.
        </p>
      ) : drawable ? (
        <DagDrawing
          groups={groups}
          layers={layers}
          selected={selected}
          onSelect={onSelect}
        />
      ) : (
        <DagTooWide groups={groups} widest={widest} />
      )}

      {/* The caveat the picture cannot state for itself. Rendered, not
          hinted: a reader who takes a group link for "every node in A
          feeds every node in B" will misread a fan-out of independent
          chains as a synchronisation point, which is the opposite of
          what it is. */}
      <p className="rounded-sm border border-gray-200 bg-gray-50 px-3 py-2 text-xs text-gray-600">
        <strong className="font-medium text-gray-800">
          A line means &ldquo;some&rdquo;, not &ldquo;every&rdquo;.
        </strong>{' '}
        An arrow from one group to another says that <em>some</em> node in the
        first is a parent of <em>some</em> node in the second. Ten independent
        chains collapse to two boxes joined by one line, which draws like a
        complete crossing but is really a perfect matching. Open a group to
        see its members.
      </p>

      {groups.length > 0 && !drawable && (
        <DagGroupList groups={groups} selected={selected} onSelect={onSelect} />
      )}

      {open && <DagGroupDetail data={data} group={open} />}

      <DagProvenance data={data} />
    </div>
  );
}

// DagNote is the shared shell for the banners below. amber for "this
// picture may be wrong", grey for "here is where it came from".
function DagNote({
  tone = 'amber',
  children,
}: {
  tone?: 'amber' | 'gray';
  children: React.ReactNode;
}) {
  const cls =
    tone === 'amber'
      ? 'border-amber-200 bg-amber-50 text-amber-900'
      : 'border-gray-200 bg-gray-50 text-gray-600';
  return (
    <div className={`rounded-sm border px-3 py-2 text-xs ${cls}`}>{children}</div>
  );
}

// DagBanners renders, for each way this picture can be wrong, a
// sentence saying so -- and nothing at all when the field is absent.
//
// Absent matters: truncated / incomplete / dangling_edges are defined by
// dagman.Grouping but not copied into the HTTP response by every server
// version, so `undefined` here means "this server does not say", NOT
// "no". Rendering a reassuring "not truncated" would be a claim the
// response never made.
function DagBanners({
  data,
  onRefresh,
  refreshing,
}: {
  data: DagGraphResponse;
  onRefresh: () => void;
  refreshing: boolean;
}) {
  const dangling = data.dangling_edges ?? 0;
  return (
    <>
      {data.truncated && (
        <DagNote>
          The structure file was read while DAGMan was still writing it, so
          this picture may be missing dependencies. The generator writes every
          node before any arc, so the usual way to catch it half-written is
          with all the boxes present and some of the lines missing.{' '}
          <button
            type="button"
            onClick={onRefresh}
            disabled={refreshing}
            className="underline underline-offset-2 disabled:opacity-50"
          >
            {refreshing ? 'Refreshing…' : 'Refresh to re-read it'}
          </button>
          .
        </DagNote>
      )}

      {data.incomplete && (
        <DagNote>
          Part of this workflow is missing from the picture: a SPLICE or
          INCLUDE named a file that could not be read, so its nodes were never
          in the graph. A workflow that looks one node wide may simply be one
          whose other file was unreadable.
        </DagNote>
      )}

      {dangling > 0 && (
        <DagNote>
          <span className="tabular-nums">{dangling.toLocaleString()}</span>{' '}
          {dangling === 1 ? 'dependency references' : 'dependencies reference'}{' '}
          nodes that are not in the structure file, and{' '}
          {dangling === 1 ? 'was' : 'were'} dropped. Those arrows are missing
          from this drawing.
        </DagNote>
      )}

      {data.approximate_layering && (
        <DagNote>
          This grouping is coarser than the workflow&apos;s real structure, so
          the layers are a best effort rather than a topology: boxes may sit
          at a depth the dependencies do not justify.
          {data.approximate_reason === 'cycle' && (
            <> The graph has a cycle, so it has no layering at all.</>
          )}
          {data.approximate_reason === 'refinement-bound' && (
            <>
              {' '}
              Splitting the groups hit its bound before it settled, so distinct
              nodes are sharing a box.
            </>
          )}
        </DagNote>
      )}

      {(data.warnings ?? []).map((w, i) => (
        // Verbatim: these say what could NOT be consulted, and a missing
        // archive has to read as "not available" rather than as "nothing
        // ran". Paraphrasing is how that flips.
        <DagNote key={i}>{w}</DagNote>
      ))}
    </>
  );
}

// dagSourceLabel names a state source in words rather than in the
// response's tokens.
function dagSourceLabel(s: string): string {
  switch (s) {
    case 'status-file':
      return "DAGMan's node status file";
    case 'dot-file':
      return 'the structure (.dot) file';
    case 'queue':
      return 'the live job queue';
    case 'archive':
      return 'the job history';
    case 'inferred':
      return 'inference from the structure';
    default:
      return s;
  }
}

// DagProvenance says where the node states came from and how old they
// are. The two halves of the response have different freshness -- the
// queue half is live, the status-file half is as old as DAGMan's last
// write plus the last whole-spool fetch -- and a picture that does not
// say which is which invites the reader to trust the stale half.
function DagProvenance({ data }: { data: DagGraphResponse }) {
  const sources = data.state_sources ?? [];
  const hasStatusFile = sources.includes('status-file');
  // The same minute-resolution clock the rest of the page ages its
  // timestamps against: the point of the number below is that it keeps
  // growing while the panel sits open, which a value frozen at render
  // would not.
  const now = useNowTick(60_000);
  return (
    <DagNote tone="gray">
      <p>
        {sources.length > 0 ? (
          <>Node state came from {joinWords(sources.map(dagSourceLabel))}.</>
        ) : (
          <>This response did not say where the node states came from.</>
        )}{' '}
        Structure read from{' '}
        <code className="font-mono">{data.dot_file}</code>
        {data.status_file && (
          <>
            {' '}
            and <code className="font-mono">{data.status_file}</code>
          </>
        )}
        . Fetched {new Date(data.fetched_at).toLocaleString()}.
      </p>
      {data.status_file_time !== undefined && data.status_file_time > 0 && (
        <p className="mt-1">
          The node status file was last written{' '}
          {new Date(data.status_file_time * 1000).toLocaleString()} (
          {humanDuration(Math.max(0, now - data.status_file_time))} ago) — every
          state that came from it is at least that old, however live the queue
          half of this page is.
        </p>
      )}
      {!hasStatusFile && (
        <p className="mt-1">
          DAGMan&apos;s node status file did not contribute here, so per-node
          state is inferred from the queue. The queue cannot tell a node that
          has not started yet from one running a PRE or POST script — neither
          has a job in it — so both read the same way above.
        </p>
      )}
    </DagNote>
  );
}

// joinWords renders a list as "a", "a and b", "a, b and c".
function joinWords(items: string[]): string {
  if (items.length <= 1) return items[0] ?? '';
  return `${items.slice(0, -1).join(', ')} and ${items[items.length - 1]}`;
}

// truncateLabel keeps a label inside its box. The full text is in the
// box's <title> and in the detail panel, so nothing is lost -- only
// shortened.
function truncateLabel(s: string, max: number): string {
  return s.length <= max ? s : `${s.slice(0, max - 1)}…`;
}

// dagStatusSummary renders a histogram as "9 done · 1 failed", most
// urgent first.
function dagStatusSummary(
  status: Record<string, number> | null | undefined,
): string {
  return dagStatusEntries(status)
    .map((e) => `${e.count} ${e.state}`)
    .join(' · ');
}

// DagDrawing is the layered picture: one row per layer, one box per
// group, one line per parent_ids entry.
//
// It deliberately does NOT try to be a layout engine -- no crossing
// minimisation, no edge routing, no port assignment. Groups sit in
// first-appearance order within their row and edges are drawn straight
// through. On the graphs this endpoint produces (small by construction,
// which is the whole point of collapsing) that reads fine; on one where
// it would not, DagTooWide takes over rather than this degrading.
//
// The SVG is drawn at its natural size inside a scrolling box. Scaling
// it to fit would shrink an 11px label to unreadable exactly on the
// wide graphs that most need reading.
function DagDrawing({
  groups,
  layers,
  selected,
  onSelect,
}: {
  groups: DagGraphGroup[];
  layers: string[][];
  selected: string | null;
  onSelect: (id: string | null) => void;
}) {
  const widest = layers.reduce((m, l) => Math.max(m, l.length), 0);
  const contentW = widest * (DAG_BOX_W + DAG_H_GAP) - DAG_H_GAP;
  const width = contentW + DAG_PAD * 2;
  const height =
    layers.length * (DAG_BOX_H + DAG_V_GAP) - DAG_V_GAP + DAG_PAD * 2;

  const pos = new Map<string, { x: number; y: number }>();
  layers.forEach((ids, li) => {
    const rowW = ids.length * (DAG_BOX_W + DAG_H_GAP) - DAG_H_GAP;
    const x0 = DAG_PAD + (contentW - rowW) / 2;
    ids.forEach((id, i) => {
      pos.set(id, {
        x: x0 + i * (DAG_BOX_W + DAG_H_GAP),
        y: DAG_PAD + li * (DAG_BOX_H + DAG_V_GAP),
      });
    });
  });

  return (
    <div
      className="overflow-auto rounded-sm border border-gray-200 bg-white"
      style={{ maxHeight: 520 }}
    >
      <svg
        width={width}
        height={height}
        viewBox={`0 0 ${width} ${height}`}
        role="img"
        aria-label={`Workflow graph: ${groups.length} groups in ${layers.length} layers`}
        className="block"
      >
        <defs>
          <marker
            id="dag-arrow"
            viewBox="0 0 8 8"
            refX="7"
            refY="4"
            markerWidth="7"
            markerHeight="7"
            orient="auto-start-reverse"
          >
            <path d="M0,1 L7,4 L0,7 z" className="fill-gray-400" />
          </marker>
        </defs>

        {groups.flatMap((g) =>
          (g.parent_ids ?? []).map((p) => {
            const from = pos.get(p);
            const to = pos.get(g.id);
            // A dangling or self parent has no box to start from; the
            // banner above already counts those.
            if (!from || !to || p === g.id) return null;
            const x1 = from.x + DAG_BOX_W / 2;
            const y1 = from.y + DAG_BOX_H;
            const x2 = to.x + DAG_BOX_W / 2;
            const y2 = to.y;
            // Bow the curve out far enough that a line between adjacent
            // rows still reads as a direction. Clamped, because a cycle
            // can put the child ABOVE the parent.
            const dy = Math.max(18, (y2 - y1) / 2);
            return (
              <path
                key={`${p}->${g.id}`}
                d={`M${x1},${y1} C${x1},${y1 + dy} ${x2},${y2 - dy} ${x2},${y2}`}
                className="fill-none stroke-gray-400"
                strokeWidth={1.25}
                markerEnd="url(#dag-arrow)"
              />
            );
          }),
        )}

        {groups.map((g) => {
          const p = pos.get(g.id);
          if (!p) return null;
          const entries = dagStatusEntries(g.status);
          const dominant = entries[0]?.state;
          const total = entries.reduce((s, e) => s + e.count, 0);
          const summary = dagStatusSummary(g.status);
          const isSelected = selected === g.id;
          const toggle = () => onSelect(isSelected ? null : g.id);
          let barX = p.x + 10;
          let barLeft = DAG_BOX_W - 20;
          return (
            <g
              key={g.id}
              data-group-id={g.id}
              role="button"
              tabIndex={0}
              aria-pressed={isSelected}
              aria-label={`${g.label}${g.count > 1 ? `, ${g.count} nodes` : ''}${summary ? `: ${summary}` : ''}`}
              className="cursor-pointer"
              onClick={toggle}
              onKeyDown={(e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                  e.preventDefault();
                  toggle();
                }
              }}
            >
              <title>
                {g.label}
                {g.count > 1 ? ` (${g.count} nodes)` : ''}
                {g.description ? ` — ${g.description}` : ''}
                {summary ? `\n${summary}` : ''}
              </title>
              <rect
                x={p.x}
                y={p.y}
                width={DAG_BOX_W}
                height={DAG_BOX_H}
                rx={4}
                strokeWidth={isSelected ? 2.5 : 1}
                className={
                  dominant ? dagStateShape(dominant) : 'fill-white stroke-gray-300'
                }
              />
              <text
                x={p.x + 10}
                y={p.y + 19}
                className="fill-gray-900 text-[11px] font-medium"
              >
                {truncateLabel(g.label, 20)}
              </text>
              {g.count > 1 && (
                <text
                  x={p.x + DAG_BOX_W - 10}
                  y={p.y + 19}
                  textAnchor="end"
                  className="fill-gray-600 text-[11px] tabular-nums"
                >
                  ×{g.count}
                </text>
              )}
              <text
                x={p.x + 10}
                y={p.y + 34}
                className="fill-gray-600 text-[10px]"
              >
                {truncateLabel(summary, 28)}
              </text>
              {total > 0 &&
                entries.map((e) => {
                  // Clamp each slice to a visible minimum so a single
                  // failed node among a thousand does not round away,
                  // and to whatever width is left so the clamping
                  // cannot push the bar out of its box.
                  const w = Math.min(
                    barLeft,
                    Math.max(2, (e.count / total) * (DAG_BOX_W - 20)),
                  );
                  const x = barX;
                  barX += w;
                  barLeft -= w;
                  if (w <= 0) return null;
                  return (
                    <rect
                      key={e.state}
                      x={x}
                      y={p.y + 42}
                      width={w}
                      height={5}
                      rx={1}
                      strokeWidth={0.5}
                      className={dagStateShape(e.state)}
                    />
                  );
                })}
            </g>
          );
        })}
      </svg>
    </div>
  );
}

// DagTooWide is what happens instead of a drawing nobody could read.
// Saying "too wide" and handing over the list is more useful than a
// picture scaled until its labels are grey smears -- and a general
// layout that would fix it is a graph library, which this panel
// deliberately is not.
function DagTooWide({
  groups,
  widest,
}: {
  groups: DagGraphGroup[];
  widest: number;
}) {
  return (
    <DagNote>
      This workflow collapsed to{' '}
      <span className="tabular-nums">{groups.length.toLocaleString()}</span>{' '}
      groups, {widest > DAG_MAX_LAYER ? 'with ' : ''}
      {widest > DAG_MAX_LAYER && (
        <>
          <span className="tabular-nums">{widest.toLocaleString()}</span> of them
          side by side in one layer,{' '}
        </>
      )}
      which is wider than a readable drawing. The group list is below
      instead.
    </DagNote>
  );
}

// DagGroupList is the drawing's fallback: the same groups, same colours,
// same click target, no geometry.
function DagGroupList({
  groups,
  selected,
  onSelect,
}: {
  groups: DagGraphGroup[];
  selected: string | null;
  onSelect: (id: string | null) => void;
}) {
  return (
    <ul className="max-h-96 space-y-1 overflow-auto rounded-sm border border-gray-200 bg-white p-2">
      {groups.map((g) => {
        const dominant = dominantDagState(g.status);
        const isSelected = selected === g.id;
        return (
          <li key={g.id}>
            <button
              type="button"
              onClick={() => onSelect(isSelected ? null : g.id)}
              className={`flex w-full items-center gap-2 rounded-sm px-2 py-1 text-left text-xs hover:bg-gray-50 ${
                isSelected ? 'bg-gray-100' : ''
              }`}
            >
              <span
                className={`inline-flex rounded-full px-2 py-0.5 text-[10px] font-medium ${dagStatePill(dominant ?? 'unready')}`}
              >
                {dominant ?? '—'}
              </span>
              <span className="font-mono text-gray-900">{g.label}</span>
              {g.count > 1 && (
                <span className="tabular-nums text-gray-500">×{g.count}</span>
              )}
              <span className="ml-auto text-gray-500">
                {dagStatusSummary(g.status)}
              </span>
            </button>
          </li>
        );
      })}
    </ul>
  );
}

// How many members to list before we stop. The server already caps what
// it sends (nodes_omitted / nodes_omitted_reason); this is the second
// cap, for a group that is under the server's limit but still far past
// what anyone scrolls.
const DAG_MAX_MEMBERS_SHOWN = 300;

// DagGroupDetail shows what a group actually contains. This is where
// the some-to-some collapse is undone: the box says "10 nodes, 1
// failed", and the answer to "which one" is only here.
function DagGroupDetail({
  data,
  group,
}: {
  data: DagGraphResponse;
  group: DagGraphGroup;
}) {
  const members = useMemo(
    () =>
      (data.nodes ?? [])
        .filter((n) => n.group_id === group.id)
        .sort(
          (a, b) =>
            dagStateRank(a.state) - dagStateRank(b.state) ||
            a.name.localeCompare(b.name),
        ),
    [data, group.id],
  );
  const shown = members.slice(0, DAG_MAX_MEMBERS_SHOWN);

  return (
    <div className="space-y-2 rounded-sm border border-gray-300 bg-gray-50 p-3">
      <div className="flex flex-wrap items-center gap-2">
        <h3 className="font-mono text-sm font-medium text-gray-900">
          {group.label}
        </h3>
        {group.count > 1 && (
          <span className="tabular-nums text-xs text-gray-500">
            {group.count.toLocaleString()} nodes
          </span>
        )}
        <span className="ml-auto flex flex-wrap gap-1">
          {dagStatusEntries(group.status).map((e) => (
            <span
              key={e.state}
              className={`inline-flex rounded-full px-2 py-0.5 text-[10px] font-medium ${dagStatePill(e.state)}`}
            >
              {e.count} {e.state}
            </span>
          ))}
        </span>
      </div>

      {group.description && (
        <p className="font-mono text-xs break-all text-gray-600">
          {group.description}
        </p>
      )}

      {data.nodes_omitted ? (
        // The server dropped the per-node overlay for size. Say its
        // reason rather than rendering an empty list, which would read
        // as "this group has no members".
        <p className="text-xs text-gray-600">
          {data.nodes_omitted_reason ??
            'This workflow is too large for the server to list node by node, so its members are not in this response.'}
        </p>
      ) : members.length === 0 ? (
        <p className="text-xs text-gray-600">
          The response lists no individual nodes for this group.
        </p>
      ) : (
        <>
          <ul className="max-h-96 space-y-1 overflow-auto">
            {shown.map((n) => (
              <li
                key={n.name}
                className="space-y-1 rounded-sm border border-gray-200 bg-white p-2 text-xs"
              >
                <div className="flex flex-wrap items-center gap-2">
                  <span
                    className={`inline-flex rounded-full px-2 py-0.5 text-[10px] font-medium ${dagStatePill(n.state)}`}
                  >
                    {n.state}
                  </span>
                  <span className="font-mono break-all text-gray-900">
                    {n.name}
                  </span>
                  {n.job_id && (
                    <Link
                      href={`/jobs/${n.job_id}`}
                      className="text-brand-700 hover:underline"
                    >
                      job {n.job_id}
                    </Link>
                  )}
                  {n.exit_code !== undefined && (
                    <span className="tabular-nums text-gray-600">
                      exit {n.exit_code}
                    </span>
                  )}
                  <span className="ml-auto text-[10px] text-gray-400">
                    from {n.source}
                  </span>
                </div>
                {n.detail && <p className="text-gray-600">{n.detail}</p>}
                {n.hold_reason && (
                  <p className="text-red-700">{n.hold_reason}</p>
                )}
              </li>
            ))}
          </ul>
          {members.length > shown.length && (
            <p className="text-xs text-gray-500">
              Showing{' '}
              <span className="tabular-nums">{shown.length.toLocaleString()}</span>{' '}
              of{' '}
              <span className="tabular-nums">
                {members.length.toLocaleString()}
              </span>{' '}
              members.
            </p>
          )}
        </>
      )}

      <DagNodeConstraint cluster={data.cluster} />
    </div>
  );
}

// DagNodeConstraint hands over the ClassAd constraint that finds the
// workflow's node jobs in the queue. It is the answer to "where are
// these in the jobs list", and it is not guessable: DAGMan stamps
// DAGManJobId on every node job it submits, and nothing on this page
// spells that attribute out otherwise.
function DagNodeConstraint({ cluster }: { cluster: number }) {
  const constraint = `DAGManJobId == ${cluster}`;
  const [copied, setCopied] = useState(false);
  return (
    <div className="flex flex-wrap items-center gap-2 border-t border-gray-200 pt-2 text-xs">
      <span className="text-gray-500">Node jobs in the queue:</span>
      <code className="rounded-sm border border-gray-300 bg-white px-2 py-0.5 font-mono text-gray-800">
        {constraint}
      </code>
      <button
        type="button"
        onClick={() => {
          navigator.clipboard?.writeText(constraint);
          setCopied(true);
          setTimeout(() => setCopied(false), 2000);
        }}
        className="rounded-sm border border-gray-300 bg-white px-2 py-0.5 text-gray-700 hover:bg-gray-50"
      >
        {copied ? 'Copied' : 'Copy'}
      </button>
      <Link
        href={`/jobs?constraint=${encodeURIComponent(constraint)}`}
        className="text-brand-700 hover:underline"
      >
        Open in jobs
      </Link>
    </div>
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
    <section className="rounded-sm border border-gray-200 bg-white">
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
        className="mb-2 w-full rounded-sm border border-gray-300 px-2 py-1 text-xs"
        aria-label="Filter ClassAd attributes"
      />
      <div className="overflow-hidden rounded-sm border border-gray-200">
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
            className="text-[11px] rounded-sm border border-gray-300 bg-white px-2 py-0.5 text-gray-700 hover:bg-gray-50"
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
          className="w-full rounded-sm border border-gray-300 bg-white px-1 py-0.5 text-[11px]"
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
            className="w-full rounded-sm border border-gray-300 bg-white px-2 py-0.5 font-mono text-xs"
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
            className="w-full rounded-sm border border-gray-300 bg-white px-2 py-0.5 font-mono text-xs"
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
            className="text-[11px] rounded-sm border border-brand-600 bg-brand-600 px-2 py-0.5 font-medium text-white hover:bg-brand-700 disabled:opacity-50"
          >
            {editMut.isPending ? '…' : 'save'}
          </button>
          <button
            type="button"
            onClick={onCancel}
            disabled={editMut.isPending}
            className="text-[11px] rounded-sm border border-gray-300 bg-white px-2 py-0.5 text-gray-700 hover:bg-gray-50 disabled:opacity-50"
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
  // Each row carries the formatted strings AND the two raw numbers, so
  // the bar can be drawn from the same values the text reports rather
  // than from a second reading of the ad.
  const rows: {
    label: string;
    requested: string;
    used: string;
    // Raw numbers in one unit, for the proportion. Undefined where the
    // ad does not say, which draws no bar.
    reqN?: number;
    usedN?: number;
  }[] = [
    {
      label: 'CPUs',
      requested: fmtRequested(job.RequestCpus),
      used: fmtUsage(job.CpusUsage ?? job.CumulativeRemoteSysCpu),
      reqN: num(job.RequestCpus),
      usedN: num(job.CpusUsage),
    },
    {
      label: 'Memory',
      requested: fmtMiB(job.RequestMemory),
      used: fmtMemoryUsed(job),
      reqN: num(job.RequestMemory),
      usedN: memoryUsedMiB(job),
    },
    {
      label: 'Disk',
      requested: fmtKiBAsMiB(job.RequestDisk),
      used: fmtKiBAsMiB(job.DiskUsage ?? job.DiskUsage_RAW),
      // Both sides are KiB on the wire, so the ratio needs no
      // conversion -- only the display does.
      reqN: num(job.RequestDisk),
      usedN: num(job.DiskUsage ?? job.DiskUsage_RAW),
    },
    {
      // HTCondor capitalises this acronym: the attributes are
      // RequestGPUs and GPUsUsage, not RequestGpus/GpusUsage. ClassAd
      // attribute names are case-insensitive, a JSON object's keys are
      // not, so the misspelled lookups were always undefined and the
      // row was dropped from every job -- including the GPU ones.
      label: 'GPUs',
      requested: fmtRequested(job.RequestGPUs),
      used: fmtUsage(job.GPUsUsage),
      reqN: num(job.RequestGPUs),
      usedN: num(job.GPUsUsage),
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
      <div className="overflow-hidden rounded-sm border border-gray-200">
        <table className="min-w-full text-sm">
          <thead className="bg-gray-50 text-left text-xs uppercase tracking-wide text-gray-500">
            <tr>
              <th className="px-3 py-1.5 w-32">Resource</th>
              <th className="px-3 py-1.5">Requested</th>
              <th className="px-3 py-1.5">Used</th>
              <th className="px-3 py-1.5 w-40">Used of requested</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-100">
            {visible.map((r) => (
              <tr key={r.label}>
                <td className="px-3 py-1.5 font-medium text-gray-700">{r.label}</td>
                <td className="px-3 py-1.5 text-gray-900 tabular-nums">{r.requested}</td>
                <td className="px-3 py-1.5 text-gray-900 tabular-nums">{r.used}</td>
                <td className="px-3 py-1.5">
                  <UsageBar requested={r.reqN} used={r.usedN} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// memoryUsedMiB is fmtMemoryUsed's number, in the same unit as
// RequestMemory. ResidentSetSize is KiB on the wire where MemoryUsage is
// already MiB, and dividing the wrong one by 1024 is how a job using
// half its request comes to look like it used none of it.
function memoryUsedMiB(job: ClassAd): number | undefined {
  const direct = num(job.MemoryUsage);
  if (direct !== undefined) return direct;
  const kib = num(job.ResidentSetSize ?? job.ResidentSetSize_RAW);
  return kib === undefined ? undefined : kib / 1024;
}

// UsageBar is the "did I ask for the right amount" glance.
//
// A number beside a number makes the reader do the division; the point
// of this column is that they should not have to. The bar is filled to
// used/requested and coloured by band: comfortable, most of it, and
// over -- the last being the interesting one, because a job over its
// request is the one about to be held for going over it.
//
// Drawn only when both numbers are real. A missing usage attribute is
// the normal state of a job that has not run, and inventing a zero-width
// bar for it would read as "used nothing" rather than "nothing measured
// yet".
export function UsageBar({
  requested,
  used,
}: {
  requested?: number;
  used?: number;
}) {
  if (requested === undefined || used === undefined || requested <= 0) {
    return <span className="text-xs text-gray-400">—</span>;
  }
  const ratio = used / requested;
  const pct = ratio * 100;
  // The bar is clamped so an over-request stays inside the column; the
  // percentage beside it is not, because "112%" is the fact worth
  // reading and a full bar alone would hide it.
  const width = Math.max(0, Math.min(ratio, 1)) * 100;
  const tone =
    ratio > 1
      ? { bar: 'bg-red-500', text: 'text-red-700' }
      : ratio >= 0.9
        ? { bar: 'bg-amber-500', text: 'text-amber-700' }
        : { bar: 'bg-green-500', text: 'text-green-700' };
  const label = `${pct.toLocaleString(undefined, {
    maximumFractionDigits: pct < 10 ? 1 : 0,
  })}%`;

  return (
    <div className="flex items-center gap-2" title={`${label} of requested`}>
      <div
        className="h-1.5 w-20 shrink-0 overflow-hidden rounded-full bg-gray-200"
        role="img"
        aria-label={`${label} of requested`}
      >
        <div className={`h-full ${tone.bar}`} style={{ width: `${width}%` }} />
      </div>
      <span className={`text-xs tabular-nums ${tone.text}`}>{label}</span>
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
      <div className="overflow-hidden rounded-sm border border-gray-200">
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
    <details className="rounded-sm border border-gray-200">
      <summary className="cursor-pointer flex items-center px-3 py-1.5 text-xs font-medium text-gray-700 hover:bg-gray-50">
        <span>Raw ClassAd</span>
        <button
          type="button"
          onClick={(e) => {
            e.preventDefault();
            e.stopPropagation();
            handleCopy();
          }}
          className="ml-auto rounded-sm border border-gray-300 bg-white px-2 py-0.5 text-[11px] text-gray-700 hover:bg-gray-50"
          title="Copy raw ClassAd to clipboard"
        >
          {copied ? 'Copied' : 'Copy'}
        </button>
      </summary>
      <pre className="px-3 py-2 text-[11px] bg-gray-50 overflow-auto font-mono max-h-128">
        {text}
      </pre>
    </details>
  );
}

// --- Tiny formatting helpers -----------------------------------------

// everRan reports whether the job has executed at least once.
//
// JobStartDate is the load-bearing one: the schedd writes it into the
// job queue when it spawns the shadow, so it is durable and survives the
// job going back to idle or held. NumJobStarts is accepted too but not
// relied on alone -- the shadow updates it lazily, so it can lag or, if
// the shadow dies first, never be written.
export function everRan(job: ClassAd): boolean {
  for (const attr of ['JobStartDate', 'JobCurrentStartDate', 'NumJobStarts']) {
    const n = num(job[attr]);
    if (n !== undefined && n > 0) return true;
  }
  return false;
}

// outputReadiness decides whether the Output Files panel may offer the
// download, and what it should say about what the user will get.
//
// It exists because everRan() alone is not that answer. everRan is true
// for the run happening RIGHT NOW -- the schedd writes JobStartDate
// when it spawns the shadow, not when the job ends -- so a job on its
// first attempt satisfied the old gate and got a live download button
// labelled "From an earlier run attempt", which is both wrong and, for
// most universes, empty: nothing transfers back until the job finishes.
//
// Two states earn the download before the job is over:
//
//   - a PRIOR attempt: the job ran and is back in the queue (idle,
//     held, whatever). There may be a sandbox from the attempt that
//     ended, and greying the button out here hides exactly what
//     somebody investigating a failed attempt came for.
//   - a SPOOLED SCHEDULER-universe job: it runs on the access point
//     under the schedd with Iwd rewritten to its spool directory, so
//     its files are written in place as it runs (schedd.cpp:12601) and
//     the schedd serves them for a running job with no status check
//     (schedd.cpp:6825). There is no transfer to wait for; the
//     download is a live snapshot and must stay offered.
//
//     Spooled is the load-bearing word. A scheduler-universe job
//     submitted from a shell on the access point (plain
//     condor_submit_dag) keeps the user's directory as its Iwd and
//     writes there, where nothing reachable from here can read it --
//     so it gets the ordinary "wait for it to finish" treatment
//     rather than a download that would come back empty.
export function outputReadiness(
  job: ClassAd | undefined,
  status: number | undefined,
): { ready: boolean; hint: string | null } {
  // 3 = Removed, 4 = Completed. Both terminal; both have had their
  // chance to leave files behind.
  const finished = status === 3 || status === 4;
  // 2 = Running, 6 = Transferring Output, 7 = Suspended. In all three
  // the job is inside an attempt, so everRan is describing that
  // attempt rather than an earlier one.
  const running = status === 2 || status === 6 || status === 7;
  const priorAttempt = !running && !!job && everRan(job);
  const spoolLive = !!job && num(job.JobUniverse) === 7 && isSpooledJob(job);
  const ready = finished || priorAttempt || spoolLive;

  const hint = finished
    ? null
    : spoolLive && running
      ? 'Scheduler-universe job: its files are written in the spool while it runs, so this is a live snapshot.'
      : running
        ? 'Job is running; output files appear once it completes.'
        : priorAttempt
          ? 'From an earlier run attempt; may be empty or partial.'
          : status === 1
            ? 'Job is idle and has not run yet; output files appear once it runs.'
            : status === 5
              ? // Not "has not run yet": a job held after an attempt
                // reaches priorAttempt above, so this branch is only
                // for one held before it ever started -- but saying so
                // was wrong for every held job the old wording covered.
                'Job is held; output files appear once it runs.'
              : 'Output files appear once the job runs.';

  return { ready, hint };
}

// supportsRemoteAccess reports whether condor_tail / condor_ssh_to_job
// can reach this job at all.
//
// Both go through the schedd's GET_JOB_CONNECT_INFO, whose universe
// switch (condor_schedd.V6/schedd.cpp:18673) answers "Job N.M does not
// support remote access." for SCHEDULER (7) and GRID (9): the first
// runs on the access point as a child of the schedd, the second on
// somebody else's batch system, and neither has a starter to connect
// to. Every other universe it handles is reachable -- LOCAL (12)
// included, which does run under a starter even though it runs on the
// access point, so it must not be swept in with scheduler universe.
//
// An ad without JobUniverse reads as supported: the panels below gate
// on the job also being in a running state, and guessing "unsupported"
// from a missing attribute would hide a working terminal.
export function supportsRemoteAccess(job: ClassAd): boolean {
  const u = num(job.JobUniverse);
  return u !== 7 && u !== 9;
}

// dagmanLogName returns the name of the DAGMan workflow log for a
// DAGMan manager job, or undefined when the job is not one.
//
// The name is not derivable from the DAG file alone, because the two
// things that submit a manager here disagree about it: condor_submit_dag
// writes <dagfile>.dagman.out (diamond.dag.dagman.out), while this
// project's submit_dag writes <base>.dagman.out (diamond.dagman.out).
// Both, however, set _CONDOR_DAGMAN_LOG in the job's environment to the
// name they actually used, so that is the authoritative source and the
// -Dag argument is only the fallback.
export function dagmanLogName(job: ClassAd): string | undefined {
  const cmd = str(job.Cmd) ?? '';
  const args = str(job.Arguments) ?? str(job.Args) ?? '';
  const isManager = /(^|\/)condor_dagman$/.test(cmd) || /(^|\s)-[Dd]ag(\s|$)/.test(args);
  if (!isManager) return undefined;

  // Environment is HTCondor's space-separated name=value form; values
  // containing spaces are single-quoted. A log file name with a space
  // in it is not worth the parser, so stop at whitespace or a quote.
  const env = str(job.Environment) ?? str(job.Env) ?? '';
  const fromEnv = env.match(/_CONDOR_DAGMAN_LOG=([^\s'"]+)/);
  if (fromEnv) return fromEnv[1];

  const dagFile = args.match(/-[Dd]ag\s+(\S+)/);
  if (dagFile) {
    // condor_submit_dag's convention: append, don't replace.
    const base = dagFile[1].split('/').pop();
    if (base) return `${base}.dagman.out`;
  }
  return undefined;
}

// isSpooledJob reports whether the schedd moved this job's files into
// its spool directory at submit time (condor_submit -spool, and
// anything built on it).
//
// SUBMIT_Iwd is the signal, and it is an exact one: the schedd's
// rewriteSpooledJobAd (qmgmt.cpp ~8788) backs the submit-time Iwd up
// into SUBMIT_Iwd precisely when it rewrites Iwd to point at the
// spool. Its presence therefore means "Iwd IS the spool directory",
// which is the whole reason this server can read the job's files at
// all; its absence means the files are in a directory on the access
// point that nothing here can reach.
export function isSpooledJob(job: ClassAd): boolean {
  return typeof job.SUBMIT_Iwd === 'string' && job.SUBMIT_Iwd !== '';
}

// workflowLogAvailability answers whether the Workflow log panel can
// actually show a DAGMan manager's log, and if not, what to tell the
// user instead. Returning the reason rather than hiding the panel is
// deliberate: "where is my DAG's log" is the question the panel exists
// to answer, and going silent answers it worse than a sentence naming
// the directory the log is in.
export function workflowLogAvailability(job: ClassAd): {
  available: boolean;
  name?: string;
  reason?: string;
} {
  const name = dagmanLogName(job);
  if (!name) return { available: false };
  if (isSpooledJob(job)) return { available: true, name };
  return {
    available: false,
    name,
    reason:
      `This workflow was submitted from a shell on the access point, so its log (${name}) is in ` +
      `${str(job.Iwd) ?? 'the submit directory'} and is not readable through this server. ` +
      `Use condor_q -better-analyze / the access point directly.`,
  };
}

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
// fmtMemoryUsed renders the memory a job actually used.
//
// MemoryUsage is the attribute to prefer, but it needs two guards. The schedd
// stores it as an expression over ResidentSetSize, and an expression the server
// could not evaluate arrives as the string "/Expr(...)/" -- num() rejects that,
// but `MemoryUsage ?? ResidentSetSize` would not, because ?? only falls back on
// null and undefined. A present-but-unusable value would silently win.
//
// And the units differ: MemoryUsage is MB while ResidentSetSize is KB, so the
// old fallback rendered "64,380 MiB" for a job using 63. Convert rather than
// pass it straight to fmtMiB.
function fmtMemoryUsed(job: ClassAd): string {
  const direct = num(job.MemoryUsage);
  if (direct !== undefined) return `${direct.toLocaleString()} MiB`;
  return fmtKiBAsMiB(job.ResidentSetSize ?? job.ResidentSetSize_RAW);
}

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
        } wrap-break-word`}
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
    // A ClassAd expression the server did not evaluate serialises as
    // "/Expr(...)/". Number() would return NaN and we would fall through
    // anyway, but rejecting it by name says what it is, and keeps a future
    // Number("...") quirk from turning an expression into a plausible value.
    if (v.startsWith('/Expr(')) return undefined;
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
