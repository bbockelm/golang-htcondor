'use client';

import { useEffect, useState } from 'react';
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

  const removeMut = useMutation({
    mutationFn: () => api.jobs.remove(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['jobs'] });
      router.push('/jobs');
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
        <div className="ml-auto">
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

      <TerminalPanel jobID={jobID} status={status} />

      <LogViewerPanel jobID={jobID} />

      {/* Match analysis is most useful for Idle (1) and Held (5) jobs —
          it answers "why isn't this running?". We expose it for all
          statuses anyway because a Completed job that took forever to
          start may also benefit from understanding which predicate was
          narrow. defaultOpen={false} so the page stays tidy and the
          user has to expand to see the (still-explicit) Run button. */}
      <MatchAnalysisPanel
        jobID={jobID}
        defaultOpen={status === 1 || status === 5}
        helperText={
          status === 1
            ? 'Job is idle. Run the analysis to see which requirement is excluding the most slots in the pool.'
            : status === 5
              ? 'Job is held. The hold reason is shown above; the analysis below explains which slots could in principle match the requirements.'
              : undefined
        }
      />

      <JobDetailsSection job={job} />
    </div>
  );
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
function JobDetailsSection({ job }: { job: ClassAd }) {
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
        <RawClassAd job={job} />
      </div>
    </section>
  );
}

function ResourceTable({ job }: { job: ClassAd }) {
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

function ExecutionTable({ job }: { job: ClassAd }) {
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

function RawClassAd({ job }: { job: ClassAd }) {
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

function Field({
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

function StatusBadge({
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
function useNowTick(intervalMs: number): number {
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
function humanDuration(seconds: number): string {
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
