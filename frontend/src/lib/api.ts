// Typed client for the htcondor-api HTTP server.
//
// Mirrors the convention used by the Go side (cookie-based session auth for
// the SPA; bearer tokens for programmatic use). All fetches include
// credentials so the session cookie is sent with every request.

const BASE = '/api/v1';

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

// fetchTextWithCap streams a text/plain endpoint and stops after `cap`
// bytes. Returns the (possibly truncated) text along with a flag the
// caller can render to make truncation visible. We deliberately avoid
// `res.text()` so a 500 MB stdout doesn't materialize into the
// browser's heap before we slice it down to 1 MB.
export async function fetchTextWithCap(
  url: string,
  cap: number,
): Promise<{ text: string; truncated: boolean }> {
  const res = await fetch(url, {
    credentials: 'include',
    headers: { Accept: 'text/plain' },
  });
  if (res.status === 401) {
    if (typeof window !== 'undefined') {
      const returnTo = window.location.pathname + window.location.search;
      window.location.href = `/login?return_to=${encodeURIComponent(returnTo)}`;
    }
    throw new ApiError(401, 'Unauthorized');
  }
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = body.message || body.error || detail;
    } catch {
      /* not JSON; fall back to statusText */
    }
    throw new ApiError(res.status, detail);
  }
  if (!res.body) {
    const text = await res.text();
    return { text: text.slice(0, cap), truncated: text.length > cap };
  }

  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buf = '';
  let bytesRead = 0;
  let truncated = false;
  // eslint-disable-next-line no-constant-condition
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    if (bytesRead + value.byteLength > cap) {
      const remaining = cap - bytesRead;
      // Decode just the bytes we still want, end the stream.
      buf += decoder.decode(value.slice(0, remaining), { stream: false });
      truncated = true;
      try {
        await reader.cancel();
      } catch {
        /* ignore cancel errors */
      }
      break;
    }
    bytesRead += value.byteLength;
    buf += decoder.decode(value, { stream: true });
  }
  if (!truncated) buf += decoder.decode();
  return { text: buf, truncated };
}

async function fetchJSON<T>(url: string, opts?: RequestInit): Promise<T> {
  const res = await fetch(url, {
    ...opts,
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
      ...opts?.headers,
    },
  });
  if (res.status === 401) {
    // Unauthenticated: bounce to /login (the Go-side OAuth2 SSO redirect),
    // preserving where the user was so we can return them after login.
    if (typeof window !== 'undefined') {
      const returnTo = window.location.pathname + window.location.search;
      window.location.href = `/login?return_to=${encodeURIComponent(returnTo)}`;
    }
    throw new ApiError(401, 'Unauthorized');
  }
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    // The Go side returns { error: "<status text>", message: "<detail>",
    // code: <int> }. Prefer the detail; fall back to the short status
    // text and finally to the HTTP status line so the user always sees
    // *something* more specific than "500".
    const detail = body.message || body.error || res.statusText;
    throw new ApiError(res.status, detail);
  }
  if (res.status === 204) return undefined as T;
  return res.json();
}

// --- Types ---

export interface Session {
  authenticated: boolean;
  username?: string;
  groups?: string[];
  is_admin: boolean;
}

export interface DashboardStats {
  username: string;
  jobs_by_status: Record<string, number>;
  jobs_total: number;
}

// HTCondor returns ClassAds as JSON objects with arbitrary attributes.
// We model them loosely and pull common fields out at the call site.
export type ClassAd = Record<string, unknown>;

export interface JobListResponse {
  jobs: ClassAd[];
  // page_token / error fields may appear; omitted here until needed.
}

export interface VersionInfo {
  version: string;
  commit: string;
}

export interface SubmitResponse {
  cluster_id: number;
  job_ids: string[];
}

export interface ShareOutputResponse {
  url: string;
  expires_at: string;
  ttl_seconds: number;
  owner: string;
}

// TemplateColumn is one variable on a template. `description` is
// optional and surfaces as help text on the batch-table column
// header. The Go side accepts a bare string or this object shape on
// input; the API always returns the object form.
export interface TemplateColumn {
  name: string;
  description?: string;
}

// TemplateInputFile is an optional default attachment that ships
// with a template. `content` is base64-encoded bytes (encoding/json's
// default for Go's []byte). The submit page merges these with any
// per-batch files the user drops; the per-file ceiling is 1 MiB.
export interface TemplateInputFile {
  name: string;
  content: string; // base64
}

// Template is one entry in the batch-submission template library.
// `source` indicates whether it's read-only (built-in / global) or
// user-saved (and therefore deletable).
export interface Template {
  id: string;
  name: string;
  description?: string;
  columns: TemplateColumn[];
  contents: string;
  source: 'builtin' | 'global' | 'user';
  input_files?: TemplateInputFile[];
}

export interface TemplateSaveRequest {
  // Empty id triggers server-side slugification from name.
  id?: string;
  name: string;
  description?: string;
  columns: TemplateColumn[];
  contents: string;
  input_files?: TemplateInputFile[];
}

// MAX_TEMPLATE_INPUT_FILE_BYTES mirrors templates.MaxInputFileBytes
// on the Go side. The save UI rejects oversized files client-side
// before encoding to base64; the server enforces the same cap.
export const MAX_TEMPLATE_INPUT_FILE_BYTES = 1 << 20; // 1 MiB

export interface JupyterCreateRequest {
  // All optional; the server fills sensible defaults.
  image?: string;
  cpus?: number;
  memory_mb?: number;
  disk_mb?: number;
  // GPU fields are passed through verbatim to request_gpus and the
  // gpus_minimum_* / cuda_version / require_gpus submit lines. Omit
  // (or pass 0 for gpus) to skip the GPU section entirely.
  gpus?: number;
  gpus_minimum_capability?: string;
  gpus_minimum_memory?: number;
  gpus_minimum_runtime?: string;
  cuda_version?: string;
  require_gpus?: string;
}

export interface JupyterCreateResponse {
  instance_id: string;
  cluster_id: string;
  proxy_path: string;
}

// JupyterInstanceSummary mirrors the Go-side struct in handlers_jupyter.go.
// Returned by GET /jupyter/instances and GET /jupyter/instances/{id}.
//
// The job_* fields are populated by a single bulk schedd query the
// list handler runs, so the list view can use the same shared status
// interpretation as the detail page (lib/jobStatus.ts) without an
// extra round-trip per row.
export interface JupyterInstanceSummary {
  instance_id: string;
  cluster_id?: string;
  image?: string;
  owner: string;
  created_at: string;
  connected: boolean;
  proxy_path: string;
  events_path: string;
  job_status?: number;
  job_current_start_executing_date?: number;
  hold_reason_code?: number;
  hold_reason?: string;
}

// InteractiveTerminalCreateRequest is the optional JSON body of
// POST /api/v1/interactive/terminal. All fields are optional; the
// server fills sensible defaults (1 CPU / 1 GB / 1 GB).
export interface InteractiveTerminalCreateRequest {
  cpus?: number;
  memory_mb?: number;
  disk_mb?: number;
  // GPU fields. See JupyterCreateRequest for semantics.
  gpus?: number;
  gpus_minimum_capability?: string;
  gpus_minimum_memory?: number;
  gpus_minimum_runtime?: string;
  cuda_version?: string;
  require_gpus?: string;
}

export interface InteractiveTerminalCreateResponse {
  instance_id: string;
  cluster_id: number;
  proc_id: number;
  job_id: string; // "cluster.proc"
  batch_name: string;
}

// InteractiveTerminalSummary mirrors the Go-side struct returned by
// GET /api/v1/interactive/terminal. The list endpoint enumerates the
// user's queue server-side and filters by the JobBatchName prefix in
// Go (rather than passing a regexp constraint string through the
// schedd, which silently matched zero rows in some pool configs).
export interface InteractiveTerminalSummary {
  instance_id: string;
  job_id: string;
  cluster_id: number;
  proc_id: number;
  batch_name: string;
  job_status: number;
  job_current_start_executing_date?: number;
  hold_reason_code?: number;
  hold_reason?: string;
  submitted_at?: string;
}

// JobBatchName prefix used by interactive terminal jobs. Mirrored from
// handlers_interactive.go's interactiveTerminalBatchPrefix; the SPA
// uses it to filter the global /jobs list down to the user's terminal
// sessions without a dedicated list endpoint.
export const INTERACTIVE_TERMINAL_BATCH_PREFIX =
  'htcondor-api-interactive-terminal-';

// JobLogEvent mirrors userlog.Event on the Go side. Field names match the
// snake_case JSON tags. Fields are mostly optional because the parser
// only sets well-known ones for known event kinds; everything else
// lands in `attributes` as raw key/value pairs from the body block.
export interface JobLogEvent {
  kind: string;
  event_number: number;
  event_time: string; // RFC 3339
  cluster_id: number;
  proc_id: number;
  sub_proc_id: number;
  description: string;
  body?: string;
  attributes?: Record<string, string>;
  submit_host?: string;
  execute_host?: string;
  terminated_normally?: boolean;
  return_value?: number | null;
  terminated_by_signal?: number | null;
  hold_reason?: string;
  hold_reason_code?: number | null;
  hold_reason_sub_code?: number | null;
  abort_reason?: string;
}

// JobLogResponse is the JSON returned by GET /api/v1/jobs/{id}/log. The
// outer keys are camelCase because the Go side uses default-tagged
// struct fields without explicit json: tags on the response wrapper.
export interface JobLogResponse {
  jobId: string;
  filename: string;
  truncated: boolean;
  events: JobLogEvent[];
  parseError?: string;
}

// MatchAnalysisResponse is the JSON returned by
// GET /api/v1/jobs/{id}/match-analysis. The Go side wraps the analyzer's
// Result struct in an envelope that also surfaces the raw Requirements
// expression and slot-cache state — both useful for the debug UI.
export interface MatchAnalysisResponse {
  job_id: string;
  requirements: string;
  result: MatchAnalysisResult;
  slot_cache: {
    fetched_at?: string;
    age_seconds?: number;
    ad_count?: number;
    all_attrs?: boolean;
    projection?: string[];
  };
}

// MatchAnalysisResult mirrors matchanalyzer.Result. Field names match the
// JSON tags on the Go side; renames there must update this in lockstep.
export interface MatchAnalysisResult {
  job_references?: string[];
  total_slots: number;
  full_matches: number;
  predicates: MatchAnalysisPredicate[];
  // -1 means "no single predicate is uniquely narrowing". The widget
  // renders that as a different message — there's no predicate to
  // highlight in the per-predicate breakdown.
  narrowing_predicate_index: number;
}

export interface MatchAnalysisPredicate {
  index: number;
  source: string;
  matched: number;
  not_matched: number;
  undefined: number;
  // Go field name is `error` (json: "error"); we use error_count in TS
  // so we don't shadow the global Error constructor.
  error: number;
  // narrowing_score: how many slots this predicate (alone) is keeping
  // out of the match set — i.e., the additional matches the operator
  // would gain by removing this predicate. The widget sorts by this
  // descending so the highest-impact predicates appear first.
  narrowing_score: number;
  sample_matched_hosts?: string[];
  sample_not_matched_hosts?: string[];
  attribute_distributions?: MatchAnalysisAttributeDistribution[];
  // resource_suggestion is populated for narrowing predicates of the
  // form `TARGET.X op MY.Request*` — the analyzer turns the raw
  // expression into a concrete "lower RequestMemory to 4096 to unlock
  // 12 slots" hint that operators can act on directly.
  resource_suggestion?: MatchAnalysisResourceSuggestion;
}

export interface MatchAnalysisResourceSuggestion {
  job_attribute: string;   // e.g., "RequestMemory"
  slot_attribute: string;  // e.g., "Memory"
  current_value?: string;  // e.g., "8192" — current value of job_attribute
  operator: string;        // e.g., ">="
  options: { new_value: string; additional_matches: number }[];
}

export interface MatchAnalysisAttributeDistribution {
  attribute: string;
  values: { value: string; count: number; example?: string }[];
  // absent: slot ad doesn't contain this attribute at all (Lookup miss).
  // undefined: ad has the attribute but the value resolves to undefined.
  // Distinguishing them helps operators understand "but I see it in the
  // ad!" surprises — `Arch = NotPublished` looks defined structurally
  // but evaluates to undefined.
  absent?: number;
  undefined?: number;
  error?: number;
  // *_example: name of one slot in each non-value bucket, for
  // click-through to a representative slot.
  absent_example?: string;
  undefined_example?: string;
  error_example?: string;
}

export interface AdminClient {
  id: string;
  redirect_uris?: string[];
  grant_types?: string[];
  response_types?: string[];
  scopes?: string[];
  public: boolean;
  created_at: string;
}

export interface AdminToken {
  kind: 'access' | 'refresh';
  signature_prefix: string;
  client_id: string;
  subject?: string;
  scopes?: string[];
  active: boolean;
  requested_at: string;
  expires_at?: string;
}

export interface LogEntry {
  time: string;
  level: string;
  destination?: string;
  message: string;
  fields?: Record<string, string>;
}

export interface AdminLogsResponse {
  enabled: boolean;
  entries: LogEntry[] | null;
}

// --- Client ---

export const api = {
  auth: {
    me: (): Promise<Session> => fetchJSON(`${BASE}/auth/me`),
    logout: (): Promise<void> =>
      fetchJSON(`${BASE}/auth/logout`, { method: 'POST' }),
  },

  // owned_by_me: server defaults to true. Admin sessions may pass
  // false for a pool-wide count; the server enforces the boundary
  // for non-admin sessions.
  dashboard: (params?: { owned_by_me?: boolean }): Promise<DashboardStats> => {
    const qs = new URLSearchParams();
    if (params?.owned_by_me !== undefined) {
      qs.set('owned_by_me', String(params.owned_by_me));
    }
    const q = qs.toString();
    return fetchJSON(`${BASE}/dashboard${q ? '?' + q : ''}`);
  },

  version: (): Promise<VersionInfo> => fetchJSON(`${BASE}/version`),

  jobs: {
    // limit accepts a number or '*' (unlimited). projection is a CSV.
    list: (params?: {
      constraint?: string;
      limit?: number | '*';
      projection?: string;
      page_token?: string;
      owned_by_me?: boolean;
    }): Promise<JobListResponse> => {
      const qs = new URLSearchParams();
      if (params?.constraint) qs.set('constraint', params.constraint);
      if (params?.limit !== undefined) qs.set('limit', String(params.limit));
      if (params?.projection) qs.set('projection', params.projection);
      if (params?.page_token) qs.set('page_token', params.page_token);
      if (params?.owned_by_me !== undefined)
        qs.set('owned_by_me', String(params.owned_by_me));
      const query = qs.toString();
      return fetchJSON(`${BASE}/jobs${query ? '?' + query : ''}`);
    },

    // GET /api/v1/jobs/{id} returns the ClassAd JSON directly.
    get: (id: string): Promise<ClassAd> =>
      fetchJSON(`${BASE}/jobs/${encodeURIComponent(id)}`),

    // Remove a single job (cluster.proc).
    remove: (id: string): Promise<unknown> =>
      fetchJSON(`${BASE}/jobs/${encodeURIComponent(id)}`, {
        method: 'DELETE',
      }),

    // Remove every job matching a ClassAd constraint expression. Used by
    // the batch listing's "Remove batch" action with `ClusterId == N`.
    removeByConstraint: (constraint: string, reason?: string): Promise<unknown> =>
      fetchJSON(`${BASE}/jobs`, {
        method: 'DELETE',
        body: JSON.stringify({ constraint, reason }),
      }),

    // Release a single held job. The Go side maps this to
    // condor_release for the matching cluster.proc; the queue moves
    // the job from JobStatus=5 (Held) back to Idle.
    release: (id: string, reason?: string): Promise<unknown> =>
      fetchJSON(`${BASE}/jobs/${encodeURIComponent(id)}/release`, {
        method: 'POST',
        body: JSON.stringify(reason ? { reason } : {}),
      }),

    submit: (submitFile: string): Promise<SubmitResponse> =>
      fetchJSON(`${BASE}/jobs`, {
        method: 'POST',
        body: JSON.stringify({ submit_file: submitFile }),
      }),

    // Upload input files for a previously-submitted job using multipart.
    // The Go side maps field name "executable" to mode 0755; everything
    // else to 0644 — match that convention here.
    uploadInputs: async (
      id: string,
      files: { name: string; file: File; executable?: boolean }[],
    ): Promise<void> => {
      const form = new FormData();
      for (const f of files) {
        form.append(f.executable ? 'executable' : 'input', f.file, f.name);
      }
      const res = await fetch(
        `${BASE}/jobs/${encodeURIComponent(id)}/input/multipart`,
        { method: 'POST', body: form, credentials: 'include' },
      );
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        const detail = body.message || body.error || res.statusText;
        throw new ApiError(res.status, detail);
      }
    },

    // URL for the authenticated tar download (uses session cookie).
    outputDownloadUrl: (id: string): string =>
      `${BASE}/jobs/${encodeURIComponent(id)}/output`,

    // Fetch up to `cap` bytes of the job's stdout / stderr as plain
    // text. Used by the Output Files preview on the detail page.
    stdoutText: (id: string, cap = 1 << 20) =>
      fetchTextWithCap(`${BASE}/jobs/${encodeURIComponent(id)}/stdout`, cap),
    stderrText: (id: string, cap = 1 << 20) =>
      fetchTextWithCap(`${BASE}/jobs/${encodeURIComponent(id)}/stderr`, cap),

    // Fetch the parsed user log. The server reads the UserLog file from
    // the sandbox, runs userlog.Parse, and returns the structured event
    // list. Explicit fetch only — the panel shows a "Load log" button.
    log: (id: string): Promise<JobLogResponse> =>
      fetchJSON(`${BASE}/jobs/${encodeURIComponent(id)}/log`),

    // Run condor_q -better-analyze-style match analysis for a job. This
    // is a heavy call (collector slot dump on first invocation, ~30s
    // cache after) so the UI MUST gate it behind a user gesture rather
    // than auto-firing on page load.
    matchAnalysis: (id: string): Promise<MatchAnalysisResponse> =>
      fetchJSON(`${BASE}/jobs/${encodeURIComponent(id)}/match-analysis`),

    // Mint a short-lived public URL to share with someone else.
    shareOutput: (
      id: string,
      ttlSeconds?: number,
    ): Promise<ShareOutputResponse> =>
      fetchJSON(`${BASE}/jobs/${encodeURIComponent(id)}/output/share`, {
        method: 'POST',
        body: JSON.stringify(ttlSeconds ? { ttl_seconds: ttlSeconds } : {}),
      }),

    // Build the WebSocket URL for the SSH-to-job terminal endpoint. The
    // browser must be on the same origin (or have a session cookie that
    // counts as same-origin) for the upgrade to authenticate.
    sshWebSocketUrl: (id: string, cols?: number, rows?: number): string => {
      const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const qs = new URLSearchParams();
      if (cols && cols > 0) qs.set('cols', String(cols));
      if (rows && rows > 0) qs.set('rows', String(rows));
      const path = `/api/v1/jobs/${encodeURIComponent(id)}/ssh`;
      const query = qs.toString();
      return `${proto}//${window.location.host}${path}${query ? '?' + query : ''}`;
    },
  },

  jupyter: {
    create: (req: JupyterCreateRequest): Promise<JupyterCreateResponse> =>
      fetchJSON(`${BASE}/jupyter/instances`, {
        method: 'POST',
        body: JSON.stringify(req),
      }),

    list: (): Promise<{ instances: JupyterInstanceSummary[] }> =>
      fetchJSON(`${BASE}/jupyter/instances`),

    get: (id: string): Promise<JupyterInstanceSummary> =>
      fetchJSON(`${BASE}/jupyter/instances/${encodeURIComponent(id)}`),

    // EventSource URL for instance lifecycle events. EventSource sends the
    // session cookie automatically when same-origin.
    eventsUrl: (id: string): string =>
      `${BASE}/jupyter/instances/${encodeURIComponent(id)}/events`,

    // Iframe target — the path the proxy serves Jupyter at.
    proxyUrl: (id: string): string =>
      `${BASE}/jupyter/instances/${encodeURIComponent(id)}/proxy/`,
  },

  interactive: {
    // POST /api/v1/interactive/terminal — submits a vanilla-universe
    // job whose executable is a small POSIX watchdog. The user
    // attaches via the existing /jobs/{id}/ssh WebSocket; the SSH
    // bridge multiplexes a heartbeat session over the same client to
    // keep the watchdog happy.
    createTerminal: (
      req: InteractiveTerminalCreateRequest,
    ): Promise<InteractiveTerminalCreateResponse> =>
      fetchJSON(`${BASE}/interactive/terminal`, {
        method: 'POST',
        body: JSON.stringify(req),
      }),

    // GET /api/v1/interactive/terminal — list the caller's terminal
    // sessions. Server filters by JobBatchName prefix; we don't have
    // to round-trip a regexp constraint through the schedd.
    listTerminals: (): Promise<{ terminals: InteractiveTerminalSummary[] }> =>
      fetchJSON(`${BASE}/interactive/terminal`),
  },

  templates: {
    list: (): Promise<{ templates: Template[] }> =>
      fetchJSON(`${BASE}/templates`),
    save: (t: TemplateSaveRequest): Promise<Template> =>
      fetchJSON(`${BASE}/templates`, {
        method: 'POST',
        body: JSON.stringify(t),
      }),
    remove: (id: string): Promise<unknown> =>
      fetchJSON(`${BASE}/templates/${encodeURIComponent(id)}`, {
        method: 'DELETE',
      }),
  },

  admin: {
    listClients: (): Promise<{ clients: AdminClient[] }> =>
      fetchJSON(`${BASE}/admin/oauth2/clients`),
    deleteClient: (id: string): Promise<void> =>
      fetchJSON(`${BASE}/admin/oauth2/clients/${encodeURIComponent(id)}`, {
        method: 'DELETE',
      }),
    listTokens: (params?: {
      client_id?: string;
      active_only?: boolean;
      limit?: number;
    }): Promise<{ tokens: AdminToken[] }> => {
      const qs = new URLSearchParams();
      if (params?.client_id) qs.set('client_id', params.client_id);
      if (params?.active_only !== undefined)
        qs.set('active_only', String(params.active_only));
      if (params?.limit !== undefined) qs.set('limit', String(params.limit));
      const q = qs.toString();
      return fetchJSON(`${BASE}/admin/oauth2/tokens${q ? '?' + q : ''}`);
    },
    logs: (limit?: number): Promise<AdminLogsResponse> =>
      fetchJSON(`${BASE}/admin/logs${limit ? `?limit=${limit}` : ''}`),
  },

  chat: {
    // Probe the chat feature. Returns enabled=false (with a reason)
    // when the operator hasn't configured an LLM key, MCP isn't on,
    // or anything else upstream of the engine is missing. The SPA
    // hides the chat surface entirely on enabled=false.
    info: (): Promise<{ enabled: boolean; reason?: string }> =>
      fetch(`${BASE}/chat/info`, { credentials: 'include' }).then(
        async (r) => {
          if (r.status === 503) return r.json(); // returns {enabled:false,...}
          if (!r.ok) throw new ApiError(r.status, r.statusText);
          return r.json();
        },
      ),
    // The streaming endpoint is consumed by the AI SDK's useChat
    // hook (see ChatPanel). We don't expose a typed wrapper here —
    // useChat handles the request shape and stream parsing.
    streamURL: `${BASE}/chat`,
  },
};

// --- Helpers ---

// HTCondor JobStatus codes. Keep this in sync with handlers_webui.go.
export const JOB_STATUS_LABEL: Record<number, string> = {
  1: 'Idle',
  2: 'Running',
  3: 'Removed',
  4: 'Completed',
  5: 'Held',
  6: 'Transferring Output',
  7: 'Suspended',
};

export function jobStatusLabel(code: unknown): string {
  if (typeof code === 'number' && JOB_STATUS_LABEL[code]) {
    return JOB_STATUS_LABEL[code];
  }
  return 'Unknown';
}

// HTCondor uses HoldReasonCode 16 to mean "the job is held while the
// schedd waits for the submitter's spool-input upload to finish". To
// new users this state is genuinely just "uploading" — the held status
// is an HTCondor implementation detail. We surface it as a pseudo
// status so the UI tells a more honest story.
//
// Reference: condor_holdcodes.h, CONDOR_HOLD_CODE_SpoolingInput == 16.
const HOLD_REASON_CODE_SPOOLING_INPUT = 16;

// DisplayStatus is a UI-flavored job status: the seven stock
// JobStatus values plus the "uploading" pseudo-status for spool
// holds. Used so detail/listing pages share the same label and
// pill colour table.
export type DisplayStatus =
  | 'idle'
  | 'running'
  | 'removed'
  | 'completed'
  | 'held'
  | 'transferring'
  | 'suspended'
  | 'uploading'
  | 'unknown';

export interface DisplayStatusInfo {
  key: DisplayStatus;
  label: string;
}

// jobStatusFields is the shape we read; either ClassAd attributes
// pulled directly off the wire, or a numeric pair we build ourselves.
interface JobStatusFields {
  status?: number | string | null;
  holdReasonCode?: number | string | null;
}

// displayJobStatus maps an HTCondor (JobStatus, HoldReasonCode) tuple
// to a UI status. The hold-reason override is pure presentation; the
// underlying JobStatus is unchanged on the wire.
export function displayJobStatus(j: JobStatusFields): DisplayStatusInfo {
  const status = numLike(j.status);
  const holdCode = numLike(j.holdReasonCode);
  if (status === 5 && holdCode === HOLD_REASON_CODE_SPOOLING_INPUT) {
    return { key: 'uploading', label: 'Uploading Inputs' };
  }
  switch (status) {
    case 1:
      return { key: 'idle', label: 'Idle' };
    case 2:
      return { key: 'running', label: 'Running' };
    case 3:
      return { key: 'removed', label: 'Removed' };
    case 4:
      return { key: 'completed', label: 'Completed' };
    case 5:
      return { key: 'held', label: 'Held' };
    case 6:
      return { key: 'transferring', label: 'Transferring Output' };
    case 7:
      return { key: 'suspended', label: 'Suspended' };
    default:
      return { key: 'unknown', label: 'Unknown' };
  }
}

function numLike(v: unknown): number | undefined {
  if (typeof v === 'number') return v;
  if (typeof v === 'string') {
    const n = Number(v);
    if (!Number.isNaN(n)) return n;
  }
  return undefined;
}
