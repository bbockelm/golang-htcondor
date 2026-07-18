'use client';

// /interactive is the landing page for "interactive" job types — things
// the user attaches to in real time rather than batch-submits and walks
// away from. Two types currently:
//
//   - JupyterLab (managed via the jupytertunnel registry)
//   - Terminal  (vanilla-universe shell + heartbeat watchdog; the user
//                attaches via the existing /jobs/{id}/ssh WebSocket)
//
// Each section lists the user's current sessions and provides a launch
// form. Per-session detail pages live at /interactive/jupyter/[id] and
// /interactive/terminal/[id].

import { useState } from 'react';
import {
  useMutation,
  useQuery,
  useQueryClient,
  type QueryClient,
} from '@tanstack/react-query';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import {
  api,
  ApiError,
  type InteractiveTerminalSummary,
  type JupyterInstanceSummary,
} from '@/lib/api';
import {
  interpretJobStatus,
  statusLabel,
  statusPillStyle,
  visualStatus,
  type Status,
} from '@/lib/jobStatus';
import { useJupyterReadyProbe } from '@/lib/useJupyterReadyProbe';
import {
  ResourceRequestPanel,
  DEFAULT_RESOURCE_REQUEST,
  type ResourceRequest,
} from '@/components/ResourceRequest';

const DEFAULT_JUPYTER_IMAGE = 'quay.io/jupyter/scipy-notebook:latest';

export default function InteractivePage() {
  return (
    <div className="space-y-8 max-w-4xl">
      <div className="flex items-center gap-3">
        <h1 className="text-2xl font-bold text-gray-900">Interactive</h1>
        <span className="text-sm text-gray-500">
          Sessions you attach to in real time. Resources are released when
          the session ends or goes idle.
        </span>
      </div>

      <JupyterSection />
      <TerminalSection />
    </div>
  );
}

// ----------------------------------------------------------------------
// JupyterLab
// ----------------------------------------------------------------------

function JupyterSection() {
  const router = useRouter();
  const queryClient = useQueryClient();

  const { data, isLoading, error } = useQuery({
    queryKey: ['jupyter', 'instances'],
    queryFn: api.jupyter.list,
    refetchInterval: 5_000,
  });

  const [image, setImage] = useState(DEFAULT_JUPYTER_IMAGE);
  // Jupyter defaults to 2 CPU / 4 GB / 4 GB (matches the server-side
  // applyDefaults) so the form opens preconfigured for a notebook
  // instead of a 1-cpu watchdog.
  const [resources, setResources] = useState<ResourceRequest>({
    ...DEFAULT_RESOURCE_REQUEST,
    cpus: 2,
    memoryMB: 4096,
    diskMB: 4096,
  });
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const submit = useMutation({
    mutationFn: () =>
      api.jupyter.create({
        image,
        ...resourceRequestToApi(resources),
      }),
    onMutate: () => setErrorMsg(null),
    onSuccess: (resp) => {
      queryClient.invalidateQueries({ queryKey: ['jupyter', 'instances'] });
      router.push(`/interactive/jupyter/${resp.instance_id}`);
    },
    onError: (err) => {
      setErrorMsg(err instanceof ApiError ? err.message : String(err));
    },
  });

  const instances = data?.instances ?? [];

  return (
    <SectionCard
      title="JupyterLab"
      hint="Run a notebook server inside the pool. macOS API hosts use vanilla universe + on-the-fly conda; Linux hosts use Docker."
    >
      {isLoading && <p className="text-gray-400 text-sm">Loading sessions…</p>}
      {error && (
        <p className="text-red-600 text-sm">
          Could not load sessions: {(error as Error).message}
        </p>
      )}
      {!isLoading && instances.length === 0 && (
        <p className="text-gray-500 text-sm">
          No JupyterLab sessions. Sessions live in API-server memory and
          reset on restart.
        </p>
      )}
      {instances.length > 0 && <JupyterTable instances={instances} />}

      <div className="rounded border border-gray-200 bg-white p-4 space-y-4 mt-3">
        <div className="text-sm font-medium text-gray-700">Launch new</div>
        <Field label="Docker image">
          <input
            type="text"
            value={image}
            onChange={(e) => setImage(e.target.value)}
            className="w-full rounded border border-gray-300 px-3 py-1.5 font-mono text-sm"
            placeholder={DEFAULT_JUPYTER_IMAGE}
          />
          <p className="mt-1 text-xs text-gray-500">
            Ignored on macOS API hosts (vanilla universe + on-the-fly
            conda env instead).
          </p>
        </Field>
        <ResourceRequestPanel value={resources} onChange={setResources} />
        {errorMsg && <ErrorBanner>{errorMsg}</ErrorBanner>}
        <button
          onClick={() => submit.mutate()}
          disabled={submit.isPending}
          className="rounded bg-brand-600 px-4 py-2 text-sm font-medium text-white hover:bg-brand-700 disabled:opacity-60"
        >
          {submit.isPending ? 'Submitting…' : 'Launch JupyterLab'}
        </button>
      </div>
    </SectionCard>
  );
}

function JupyterTable({ instances }: { instances: JupyterInstanceSummary[] }) {
  return (
    <div className="overflow-x-auto rounded-lg border border-gray-200 bg-white">
      <table className="min-w-full text-sm">
        <thead className="bg-gray-50 text-left text-xs uppercase tracking-wide text-gray-500">
          <tr>
            <th className="px-3 py-2">Instance</th>
            <th className="px-3 py-2">Job</th>
            <th className="px-3 py-2">Image</th>
            <th className="px-3 py-2">Status</th>
            <th className="px-3 py-2">Created</th>
            <th className="px-3 py-2"></th>
          </tr>
        </thead>
        <tbody className="divide-y divide-gray-100">
          {instances.map((inst) => (
            <JupyterRow key={inst.instance_id} inst={inst} />
          ))}
        </tbody>
      </table>
    </div>
  );
}

// JupyterRow is its own component so each row can host its own probe
// state via useJupyterReadyProbe. The probe runs once the helper is
// connected and flips this row's pill from "Launching" (amber) to
// "Ready" (green) the same way the detail page does — without that,
// the list and detail page disagreed on what "ready" means.
function JupyterRow({ inst }: { inst: JupyterInstanceSummary }) {
  const labReady = useJupyterReadyProbe({
    proxyPath: inst.proxy_path,
    instanceID: inst.instance_id,
    helperConnected: inst.connected === true,
  });
  // Compute the underlying job status, then upgrade to 'ready' iff the
  // probe confirms JupyterLab is serving. This mirrors the detail
  // page's logic exactly so the two views land on the same state.
  let status = jupyterRowStatus(inst);
  if (status === 'launching' && labReady) {
    status = 'ready';
  }
  return (
    <tr className="hover:bg-gray-50">
      <td className="px-3 py-2 font-mono text-xs">
        <Link
          href={`/interactive/jupyter/${inst.instance_id}`}
          className="text-brand-700 hover:underline"
        >
          {inst.instance_id}
        </Link>
      </td>
      <td className="px-3 py-2 font-mono text-xs text-gray-700">
        {inst.cluster_id ? `${inst.cluster_id}.0` : '—'}
      </td>
      <td className="px-3 py-2 font-mono text-xs text-gray-700 max-w-xs truncate">
        {inst.image ?? '—'}
      </td>
      <td className="px-3 py-2">
        <SharedStatusPill status={status} />
      </td>
      <td className="px-3 py-2 text-xs text-gray-500 whitespace-nowrap">
        {new Date(inst.created_at).toLocaleString()}
      </td>
      <td className="px-3 py-2 text-right">
        <Link
          href={`/interactive/jupyter/${inst.instance_id}`}
          className="text-xs text-gray-500 hover:text-gray-700"
        >
          Open ↗
        </Link>
      </td>
    </tr>
  );
}

// jupyterRowStatus turns a JupyterInstanceSummary into the shared
// Status used everywhere else. Synthesizes a pseudo-ad from the
// summary's job_* fields so the same interpretJobStatus path applies.
function jupyterRowStatus(inst: JupyterInstanceSummary): Status {
  const fakeAd: Record<string, unknown> = {};
  if (inst.job_status !== undefined) fakeAd.JobStatus = inst.job_status;
  if (inst.job_current_start_executing_date !== undefined)
    fakeAd.JobCurrentStartExecutingDate = inst.job_current_start_executing_date;
  if (inst.hold_reason_code !== undefined) fakeAd.HoldReasonCode = inst.hold_reason_code;
  if (inst.hold_reason !== undefined) fakeAd.HoldReason = inst.hold_reason;
  return interpretJobStatus({
    job: inst.job_status !== undefined ? fakeAd : undefined,
    helperConnected: inst.connected,
  });
}

// ----------------------------------------------------------------------
// Terminal
// ----------------------------------------------------------------------

function TerminalSection() {
  const router = useRouter();
  const queryClient = useQueryClient();

  // Server-side list. The handler enumerates the user's queue and
  // filters by the JobBatchName prefix in Go — see
  // httpserver/handlers_interactive.go. We previously tried a
  // schedd-side regexp constraint and it silently returned zero rows
  // in the macOS demo pool; doing the filtering in Go is portable.
  const termsQuery = useQuery({
    queryKey: ['interactive', 'terminals'],
    queryFn: api.interactive.listTerminals,
    refetchInterval: 5_000,
  });

  const [resources, setResources] = useState<ResourceRequest>(DEFAULT_RESOURCE_REQUEST);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const submit = useMutation({
    mutationFn: () =>
      api.interactive.createTerminal(resourceRequestToApi(resources)),
    onMutate: () => setErrorMsg(null),
    onSuccess: (resp) => {
      invalidateInteractiveLists(queryClient);
      router.push(`/interactive/terminal/${resp.job_id}`);
    },
    onError: (err) => {
      setErrorMsg(err instanceof ApiError ? err.message : String(err));
    },
  });

  const terminals = termsQuery.data?.terminals ?? [];

  return (
    <SectionCard
      title="Terminal"
      hint="An interactive shell inside the pool. The session ends if you stop typing for ~2 minutes (the watchdog gates lifetime on browser activity)."
    >
      {termsQuery.isLoading && (
        <p className="text-gray-400 text-sm">Loading sessions…</p>
      )}
      {termsQuery.error && (
        <p className="text-red-600 text-sm">
          Could not load sessions: {(termsQuery.error as Error).message}
        </p>
      )}
      {!termsQuery.isLoading && terminals.length === 0 && (
        <p className="text-gray-500 text-sm">
          No active terminal sessions.
        </p>
      )}
      {terminals.length > 0 && (
        <TerminalTable
          terminals={terminals}
          onChange={() => termsQuery.refetch()}
        />
      )}

      <div className="rounded border border-gray-200 bg-white p-4 space-y-4 mt-3">
        <div className="text-sm font-medium text-gray-700">Launch new</div>
        <ResourceRequestPanel value={resources} onChange={setResources} />
        {errorMsg && <ErrorBanner>{errorMsg}</ErrorBanner>}
        <button
          onClick={() => submit.mutate()}
          disabled={submit.isPending}
          className="rounded bg-brand-600 px-4 py-2 text-sm font-medium text-white hover:bg-brand-700 disabled:opacity-60"
        >
          {submit.isPending ? 'Submitting…' : 'Launch terminal'}
        </button>
      </div>
    </SectionCard>
  );
}

// resourceRequestToApi flattens a ResourceRequest into the optional-
// field shape both interactive endpoints accept. GPU-related fields are
// omitted when the user requested 0 GPUs so the JSON stays tidy.
function resourceRequestToApi(r: ResourceRequest): {
  cpus: number;
  memory_mb: number;
  disk_mb: number;
  gpus?: number;
  gpus_minimum_capability?: string;
  gpus_minimum_memory?: number;
  gpus_minimum_runtime?: string;
  cuda_version?: string;
  require_gpus?: string;
} {
  const out: ReturnType<typeof resourceRequestToApi> = {
    cpus: r.cpus,
    memory_mb: r.memoryMB,
    disk_mb: r.diskMB,
  };
  if (r.gpus > 0) {
    out.gpus = r.gpus;
    if (r.gpuMinCapability) out.gpus_minimum_capability = r.gpuMinCapability;
    if (r.gpuMinMemoryMB > 0) out.gpus_minimum_memory = r.gpuMinMemoryMB;
    if (r.gpuMinRuntime) out.gpus_minimum_runtime = r.gpuMinRuntime;
    if (r.cudaVersion) out.cuda_version = r.cudaVersion;
    if (r.requireGpus) out.require_gpus = r.requireGpus;
  }
  return out;
}

// terminalRowStatus turns an InteractiveTerminalSummary into the
// shared Status. Same trick as jupyterRowStatus — build a pseudo-ad
// from the summary so we can run the same interpretJobStatus path.
function terminalRowStatus(t: InteractiveTerminalSummary): Status {
  const fakeAd: Record<string, unknown> = {
    JobStatus: t.job_status,
  };
  if (t.job_current_start_executing_date !== undefined)
    fakeAd.JobCurrentStartExecutingDate = t.job_current_start_executing_date;
  if (t.hold_reason_code !== undefined) fakeAd.HoldReasonCode = t.hold_reason_code;
  if (t.hold_reason !== undefined) fakeAd.HoldReason = t.hold_reason;
  return interpretJobStatus({ job: fakeAd });
}

function TerminalTable({
  terminals,
  onChange,
}: {
  terminals: InteractiveTerminalSummary[];
  onChange: () => void;
}) {
  const queryClient = useQueryClient();

  const removeMut = useMutation({
    mutationFn: (jobID: string) => api.jobs.remove(jobID),
    onSuccess: () => {
      invalidateInteractiveLists(queryClient);
      onChange();
    },
  });

  return (
    <div className="overflow-x-auto rounded-lg border border-gray-200 bg-white">
      <table className="min-w-full text-sm">
        <thead className="bg-gray-50 text-left text-xs uppercase tracking-wide text-gray-500">
          <tr>
            <th className="px-3 py-2">Job</th>
            <th className="px-3 py-2">Status</th>
            <th className="px-3 py-2">Submitted</th>
            <th className="px-3 py-2"></th>
          </tr>
        </thead>
        <tbody className="divide-y divide-gray-100">
          {terminals.map((t) => (
            <tr key={t.job_id} className="hover:bg-gray-50">
              <td className="px-3 py-2 font-mono text-xs">
                <Link
                  href={`/interactive/terminal/${t.job_id}`}
                  className="text-brand-700 hover:underline"
                >
                  {t.job_id}
                </Link>
              </td>
              <td className="px-3 py-2">
                {/* visualStatus remaps terminal 'executing' → 'ready'
                    so the pill is green/Ready once the SSH bridge can
                    actually attach (= the executable is running).
                    Without this, the list reports a yellow
                    "Executing" pill even though the session is fully
                    usable — inconsistent with how Jupyter's flow
                    surfaces "Ready" once usable. */}
                <SharedStatusPill status={visualStatus(terminalRowStatus(t), 'terminal')} />
              </td>
              <td className="px-3 py-2 text-xs text-gray-500 whitespace-nowrap">
                {t.submitted_at
                  ? new Date(t.submitted_at).toLocaleString()
                  : '—'}
              </td>
              <td className="px-3 py-2 text-right whitespace-nowrap">
                <Link
                  href={`/interactive/terminal/${t.job_id}`}
                  className="text-xs text-gray-500 hover:text-gray-700 mr-3"
                >
                  Open ↗
                </Link>
                <button
                  onClick={() => {
                    if (confirm(`Remove job ${t.job_id}?`)) {
                      removeMut.mutate(t.job_id);
                    }
                  }}
                  disabled={
                    removeMut.isPending && removeMut.variables === t.job_id
                  }
                  className="text-xs text-red-600 hover:text-red-800 disabled:opacity-50"
                >
                  Remove
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ----------------------------------------------------------------------
// Shared bits
// ----------------------------------------------------------------------

function SectionCard({
  title,
  hint,
  children,
}: {
  title: string;
  hint?: string;
  children: React.ReactNode;
}) {
  return (
    <section className="space-y-3">
      <div>
        <h2 className="text-sm font-semibold text-gray-800">{title}</h2>
        {hint && <p className="text-xs text-gray-500">{hint}</p>}
      </div>
      {children}
    </section>
  );
}

function Field({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <label className="block">
      <span className="text-sm font-medium text-gray-700">{label}</span>
      <div className="mt-1">{children}</div>
    </label>
  );
}

function ErrorBanner({ children }: { children: React.ReactNode }) {
  return (
    <div className="rounded border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">
      {children}
    </div>
  );
}

// SharedStatusPill renders a Status (from lib/jobStatus.ts) as a
// labeled pill. Used by both the Jupyter and Terminal list rows so
// the visual treatment matches the detail pages.
function SharedStatusPill({ status }: { status: Status }) {
  const style = statusPillStyle(status);
  return (
    <span className={style.badge}>
      {style.dot && <span className={style.dot} />}
      {statusLabel(status)}
    </span>
  );
}

// invalidateInteractiveLists nudges every cache entry the launcher /
// row actions might have stale data for. Pulled out so the same set
// is used in both Jupyter and Terminal flows.
function invalidateInteractiveLists(queryClient: QueryClient) {
  queryClient.invalidateQueries({ queryKey: ['jobs'] });
  queryClient.invalidateQueries({ queryKey: ['dashboard'] });
  queryClient.invalidateQueries({ queryKey: ['interactive', 'terminals'] });
  queryClient.invalidateQueries({ queryKey: ['jupyter', 'instances'] });
}
