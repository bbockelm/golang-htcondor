'use client';

// Archive detail page — read-only view of a single completed /
// removed job from the schedd's history.
//
// Reuses the read-only display components exported by
// JobDetailClient.tsx (StatusBadge, Field, JobDetailsSection,
// AttributesTable in editable=false mode, useNowTick, humanDuration).
// Same identifier across both pages → no drift on what the user sees.
//
// Skips on purpose:
//   - LiveTail / Terminal panels: no live job to attach to.
//   - OutputFilesPanel: archived jobs have already had their output
//     transferred or it's gone — the schedd doesn't keep a tarball
//     waiting in the spool.
//   - LogViewer: no userlog to fetch.
//   - Hold / Release / Remove: terminal-state jobs.
//   - 10s refetch: archive records are immutable; staleTime Infinity.
//
// The "would this match the current pool?" affordance uses
// MatchAnalysisPanel with source="archive" — the archived ad still
// carries the Requirements expression and the analyzer doesn't care
// that the job no longer exists in the queue.

import { useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import Link from 'next/link';
import {
  api,
  ApiError,
  type ClassAd,
  type HistoryListResponse,
} from '@/lib/api';
import { useResolvedParams } from '@/lib/useResolvedParams';
import {
  Field,
  StatusBadge,
  JobDetailsSection,
  humanDuration,
  useNowTick,
} from '@/app/jobs/[id]/JobDetailClient';
import { MatchAnalysisPanel } from '@/components/MatchAnalysisPanel';

export default function ArchiveDetailClient() {
  const { id } = useResolvedParams<{ id: string }>('/archive/[id]');
  // Pull the single ad from history. We use `projection=*` so the
  // AttributesTable on the page can render the full ad — same UX as
  // the live detail page. The archive listing's per-row projection
  // is narrower; pulling everything for the detail view is fine.
  const { data, isLoading, error } = useQuery<ClassAd | null, Error>({
    queryKey: ['archive-job', id],
    enabled: !!id && id !== '_',
    // Archive records are immutable; never refetch automatically.
    staleTime: Infinity,
    queryFn: async () => {
      const [clusterStr, procStr] = id.split('.');
      const cluster = Number.parseInt(clusterStr, 10);
      const proc = Number.parseInt(procStr ?? '0', 10);
      if (!Number.isFinite(cluster) || !Number.isFinite(proc)) {
        throw new ApiError(400, `Invalid job id: ${id}`);
      }
      const resp: HistoryListResponse = await api.jobs.archive({
        constraint: `ClusterId == ${cluster} && ProcId == ${proc}`,
        projection: '*',
        limit: 1,
      });
      const ads = resp.ads ?? [];
      return ads.length > 0 ? ads[0] : null;
    },
  });

  const [batchID, jobIdx] = id.split('.');

  return (
    <div className="space-y-6 max-w-4xl">
      <div className="flex items-center gap-3 flex-wrap">
        <Link
          href="/archive"
          className="text-sm text-gray-500 hover:text-gray-700"
        >
          ← Archive
        </Link>
        <h1 className="text-2xl font-bold text-gray-900">
          Job {jobIdx ?? '?'}
          <span className="ml-2 text-base font-normal text-gray-500">
            in batch {batchID ?? '?'}
          </span>
        </h1>
        <span className="ml-2 inline-flex items-center rounded-full bg-gray-200 px-2 py-0.5 text-xs font-medium text-gray-700">
          archived
        </span>
      </div>

      {isLoading && <p className="text-gray-400">Loading…</p>}

      {error && (
        <div className="rounded border border-red-200 bg-red-50 p-3 text-sm text-red-700">
          {error.message}
        </div>
      )}

      {!isLoading && !error && !data && (
        <p className="text-gray-500 text-sm">
          No archive record for {id}. The job may still be in the live
          queue —{' '}
          <Link
            href={`/jobs/${id}`}
            className="text-brand-700 hover:underline"
          >
            check the live detail page
          </Link>
          .
        </p>
      )}

      {data && <ArchiveJobDetail jobID={id} job={data} />}
    </div>
  );
}

// ArchiveJobDetail composes the read-only sections. Loosely models
// the live JobDetail layout but skips everything that requires a
// live starter / spool / userlog.
function ArchiveJobDetail({
  jobID,
  job,
}: {
  jobID: string;
  job: ClassAd;
}) {
  const owner = str(job.Owner);
  const cmd = str(job.Cmd);
  const args = str(job.Args);
  const qdate = num(job.QDate);
  const startDate =
    num(job.JobStartDate) ?? num(job.JobCurrentStartDate);
  const completionDate = num(job.CompletionDate);
  const wallClock = num(job.RemoteWallClockTime);
  const jobStatus = num(job.JobStatus);
  const exitCode = num(job.ExitCode);
  const exitBySignal =
    job.ExitBySignal === true || job.ExitBySignal === 'true';
  const batchName = str(job.JobBatchName);

  // Same useNowTick the live detail uses for "X ago" relative
  // labels. Even though archive records are immutable the wall-clock
  // labels still need to update so "ran 2 minutes ago" → "3 minutes
  // ago" without a refresh.
  const now = useNowTick(60_000);

  // Synthesize a DisplayStatusInfo. Archive records are always
  // terminal (Removed=3, Completed=4) so the status pill is one of
  // a small set; we lean on the same StatusBadge component the live
  // page uses by hand-building the DisplayStatusInfo here. This
  // keeps the visual style consistent.
  const display = archiveDisplayStatus(jobStatus, exitCode, exitBySignal);

  const showExitCode = exitCode !== undefined || exitBySignal;

  return (
    <div className="space-y-6">
      <div className="rounded border border-gray-200 bg-white p-4 grid grid-cols-2 gap-3 text-sm">
        <Field label="Status" value={<StatusBadge display={display} />} />
        <Field label="Owner" value={owner ?? '—'} />
        <Field
          label="Submitted"
          value={qdate ? new Date(qdate * 1000).toLocaleString() : '—'}
          sub={qdate ? `${humanDuration(now - qdate)} ago` : undefined}
        />
        <Field
          label="Last Started"
          value={
            startDate ? new Date(startDate * 1000).toLocaleString() : '—'
          }
          sub={
            startDate && completionDate
              ? `ran for ${humanDuration(completionDate - startDate)}`
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
            completionDate
              ? `${humanDuration(now - completionDate)} ago`
              : undefined
          }
        />
        <Field
          label="Wall Clock"
          value={wallClock ? humanDuration(wallClock) : '—'}
        />
        {batchName && <Field label="Batch" value={batchName} />}
        {showExitCode && (
          <Field
            label="Exit"
            value={
              exitBySignal
                ? `signal${exitCode !== undefined ? ` (${exitCode})` : ''}`
                : exitCode === 0
                  ? 'success (0)'
                  : `failure (${exitCode ?? '?'})`
            }
            warn={exitBySignal || (exitCode !== undefined && exitCode !== 0)}
          />
        )}
        <Field label="Command" value={cmd ?? '—'} mono full />
        {args && <Field label="Arguments" value={args} mono full />}
      </div>

      {/* "Would this job match the current pool?" — uses the same
          analyzer the live page does, but pulls the ad from the
          history database via source="archive". The archived ad's
          Requirements expression is preserved so this answers
          retrospectively even for jobs no longer in the queue.

          We deliberately do NOT pass jobStatus — the panel's gating
          would otherwise grey out the Run button (it only allows
          'idle' / 'held'). Leaving it undefined falls through to
          the "host didn't pass status" allow-path.

          We also deliberately do NOT pass jobQDate — that drives
          the panel's "this job is only Xs old, give it a minute"
          banner, which is meaningless for an archived record (the
          job already ran to completion; we're asking a
          retrospective hypothetical). The panel skips the banner
          entirely when QDate is absent. */}
      <MatchAnalysisPanel
        jobID={jobID}
        source="archive"
        title="Match against current pool"
        helperText="Re-evaluate this archived job's Requirements against the slots in the pool right now. Useful for asking 'would I get matched if I resubmitted this exactly as-is?'"
        defaultOpen={false}
      />

      <JobDetailsSection jobID={jobID} job={job} editable={false} />
    </div>
  );
}

// archiveDisplayStatus derives a DisplayStatusInfo for an archived
// job. Live JobDetail uses lib/api.ts's displayJobStatus, which
// supports the "Uploading Inputs" pseudo-status that doesn't apply
// to terminal-state archive records — keeping a tighter local
// version makes the failure modes (Failed N / Killed by signal /
// Removed) more directly readable.
function archiveDisplayStatus(
  status: number | undefined,
  exitCode: number | undefined,
  bySignal: boolean,
): { key: 'completed' | 'removed' | 'unknown'; label: string } {
  if (status === 3) return { key: 'removed', label: 'Removed' };
  if (status === 4) {
    if (bySignal) return { key: 'completed', label: 'Killed' };
    if (exitCode !== undefined && exitCode !== 0) {
      return { key: 'completed', label: `Failed (${exitCode})` };
    }
    return { key: 'completed', label: 'Completed' };
  }
  return { key: 'unknown', label: 'Unknown' };
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
  if (typeof v === 'string' && v !== '') return v;
  if (v === undefined || v === null) return undefined;
  if (typeof v === 'string') return undefined;
  return String(v);
}
