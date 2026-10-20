// Client for the placementd directory endpoints (/api/v1/placement/admin).
//
// These exist only when the placementd advertises API version 2 or later;
// PlacementStatus.api_version says so. Kept apart from api.ts because the
// error bodies carry fields (owned_by, cascade_required, per-operation
// results) the generic client drops.

import { ApiError } from "./api";

const BASE = "/api/v1/placement/admin";

export type PlacementKind = "identities" | "accounts" | "projects" | "authorizations";
export type PlacementTargetType = "Identity" | "Account" | "Project" | "Authorization";
export type PlacementSource = "mapfile" | "internal";

export const KIND_TARGET: Record<PlacementKind, PlacementTargetType> = {
  identities: "Identity",
  accounts: "Account",
  projects: "Project",
  authorizations: "Authorization",
};

export interface PlacementEntityMeta {
  id: string;
  source?: PlacementSource | string;
  version: number;
  created_at?: string;
  updated_at?: string;
  modified_by?: string;
  modification_id?: number;
}

export interface DirIdentity extends PlacementEntityMeta {
  identity: string;
  account_id?: string;
  account?: string;
  expires_at?: string;
  expired: boolean;
  display_name?: string;
  comment?: string;
  authorizations: string[];
  projects: string[];
  default_project?: string;
  last_token_expiration?: string;
}

export interface DirAccount extends PlacementEntityMeta {
  name: string;
  authorizations: string[];
  projects: string[];
  default_project?: string;
  identities: string[];
}

export interface DirProject extends PlacementEntityMeta {
  name: string;
  description?: string;
  accounts: string[];
}

export interface DirAuthorization extends PlacementEntityMeta {
  name: string;
  label?: string;
  color?: string;
  description?: string;
  requestable: boolean;
}

export interface DirEntityByKind {
  identities: DirIdentity;
  accounts: DirAccount;
  projects: DirProject;
  authorizations: DirAuthorization;
}

export interface MapfileProblem {
  kind?: string;
  file?: string;
  line?: number;
  key?: string;
  message?: string;
}

export interface MapfileStatus {
  load_time?: string;
  load_attempt_time?: string;
  ok: boolean;
  quarantined: number;
  conflicts: number;
  user_mapfile?: string;
  authorizations_mapfile?: string;
  problems: MapfileProblem[];
}

// One history entry: one entity changed by one batch or map file reload.
export type ModificationChannel = "cedar" | "mapfile" | "migration";
export type ModificationOperation = "create" | "update" | "delete" | "adopt" | "reclaim" | "handoff";
export type FieldValue = string | number | boolean | null | FieldValue[];

export interface Modification {
  id: number;
  changeset_id: number;
  time?: string;
  channel: ModificationChannel | string;
  actor: string;
  on_behalf_of?: string;
  peer_address?: string;
  comment?: string;
  operation: ModificationOperation | string;
  entity_type: string;
  entity_id: string;
  changes: Record<string, { old: FieldValue; new: FieldValue }>;
}

export interface EditResult {
  index: number;
  id?: string;
  version?: number;
  warning?: string;
  error_code?: number;
  error?: string;
}

export interface EditResponse {
  committed: boolean;
  dry_run: boolean;
  results: EditResult[];
}

// Fields are keyed by their JSON names. null clears a field on update.
export type EntityFields = Record<string, string | boolean | string[] | null>;

export interface BatchOperation {
  operation: "Create" | "Update" | "Delete" | "Adopt";
  target_type: PlacementTargetType | "All";
  id?: string;
  // Selector when id is absent: identity for an Identity, name otherwise.
  name?: string;
  identity?: string;
  expected_version?: number;
  cascade?: boolean;
  fields?: EntityFields;
}

// One access request, as administrators see it. Display name, email and
// note are what the requester's provider and the requester gave: render
// them as text only. The email is present only when the provider marked it
// verified.
// "approving" is a request whose approval is being applied.
export type AccessRequestStatus = "pending" | "approving" | "approved" | "denied" | "withdrawn";

export interface AccessRequest {
  id: number;
  identity: string;
  idp_subject?: string;
  display_name?: string;
  email?: string;
  projects: string[];
  note?: string;
  status: AccessRequestStatus;
  created_at: string;
  updated_at: string;
  decided_by?: string;
  decided_at?: string;
  decision_note?: string;
  account?: string;
  changeset_id?: number;
  // The identity's part before its last "@", in UID_DOMAIN: what a map
  // file line with "*" would give it.
  suggested_account?: string;
}

export interface AccessRequestList {
  requests: AccessRequest[];
  // Every pending request, whatever the filter.
  pending: number;
  // Whether approving is possible: the placementd serves directory edits.
  can_approve: boolean;
}

export interface ApproveInput {
  account: string;
  authorizations: string[];
  projects: string[];
  default_project: string;
  expires_at?: string | null;
  display_name?: string;
  comment?: string;
  // Map the identity to an account that already exists, leaving the
  // account as it is.
  attach_to_existing?: boolean;
}

export interface ApproveResponse extends EditResponse {
  request?: AccessRequest;
}

// PlacementAdminError is an ApiError with the directory's refusal details.
export class PlacementAdminError extends ApiError {
  placementCode?: number;
  ownedBy?: string;
  cascadeRequired: boolean;
  results: EditResult[];
  // An approval found the identity already in the directory.
  identityExists: boolean;
  constructor(
    status: number,
    message: string,
    body: {
      placement_code?: number;
      owned_by?: string;
      cascade_required?: boolean;
      results?: EditResult[];
      identity_exists?: boolean;
    },
  ) {
    super(status, message);
    this.placementCode = body.placement_code;
    this.ownedBy = body.owned_by;
    this.cascadeRequired = body.cascade_required === true;
    this.results = body.results ?? [];
    this.identityExists = body.identity_exists === true;
  }

  // A version mismatch: someone else changed the row first.
  get isVersionConflict(): boolean {
    return this.placementCode === 14;
  }
}

async function request<T>(url: string, init?: RequestInit): Promise<T> {
  const res = await fetch(url, {
    ...init,
    credentials: "include",
    headers: { "Content-Type": "application/json", ...init?.headers },
  });
  if (res.status === 401) {
    if (typeof window !== "undefined") {
      const returnTo = window.location.pathname + window.location.search;
      // Same redirect as api.ts's fetchJSON: /login is served by the Go
      // side, not a Next.js route.
      // eslint-disable-next-line @next/next/no-location-assign-relative-destination
      window.location.href = `/login?return_to=${encodeURIComponent(returnTo)}`;
    }
    throw new ApiError(401, "Unauthorized");
  }
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new PlacementAdminError(res.status, body.message || body.error || res.statusText, body);
  }
  return res.json();
}

function qs(params: Record<string, string | number | boolean | undefined>): string {
  const q = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v === undefined || v === "" || v === false) continue;
    q.set(k, String(v));
  }
  const s = q.toString();
  return s ? `?${s}` : "";
}

export const placementAdmin = {
  list: async <K extends PlacementKind>(
    kind: K,
    params?: { name?: string; constraint?: string; limit?: number },
  ): Promise<DirEntityByKind[K][]> => {
    const body = await request<Record<string, DirEntityByKind[K][]>>(
      `${BASE}/${kind}${qs({ ...params })}`,
    );
    return body[kind] ?? [];
  },
  get: <K extends PlacementKind>(kind: K, id: string): Promise<DirEntityByKind[K]> =>
    request(`${BASE}/${kind}/${encodeURIComponent(id)}`),
  // changeComment, on every write, is recorded in the history with the
  // change. The server records the signed-in admin as who made it.
  create: (
    kind: PlacementKind,
    fields: EntityFields,
    opts: { dryRun?: boolean; changeComment?: string } = {},
  ): Promise<EditResponse> =>
    request(`${BASE}/${kind}${qs({ dry_run: opts.dryRun })}`, {
      method: "POST",
      body: JSON.stringify(withComment(fields, opts.changeComment)),
    }),
  update: (
    kind: PlacementKind,
    id: string,
    expectedVersion: number,
    fields: EntityFields,
    changeComment?: string,
  ): Promise<EditResponse> =>
    request(`${BASE}/${kind}/${encodeURIComponent(id)}`, {
      method: "PATCH",
      body: JSON.stringify(withComment({ ...fields, expected_version: expectedVersion }, changeComment)),
    }),
  remove: (
    kind: PlacementKind,
    id: string,
    opts: { cascade?: boolean; expectedVersion?: number; changeComment?: string } = {},
  ): Promise<EditResponse> =>
    request(
      `${BASE}/${kind}/${encodeURIComponent(id)}${qs({
        cascade: opts.cascade,
        expected_version: opts.expectedVersion,
      })}`,
      { method: "DELETE", body: JSON.stringify(withComment({}, opts.changeComment)) },
    ),
  adopt: (
    kind: PlacementKind,
    id: string,
    expectedVersion?: number,
    changeComment?: string,
  ): Promise<EditResponse> =>
    request(`${BASE}/${kind}/${encodeURIComponent(id)}/adopt`, {
      method: "POST",
      body: JSON.stringify(
        withComment(expectedVersion ? { expected_version: expectedVersion } : {}, changeComment),
      ),
    }),
  adoptAll: (changeComment?: string): Promise<EditResponse> =>
    request(`${BASE}/adopt-all`, {
      method: "POST",
      body: JSON.stringify(withComment({}, changeComment)),
    }),
  batch: (
    operations: BatchOperation[],
    dryRun = false,
    changeComment?: string,
  ): Promise<EditResponse> =>
    request(`${BASE}/batch`, {
      method: "POST",
      body: JSON.stringify(withComment({ dry_run: dryRun, operations }, changeComment)),
    }),
  // history lists changes newest first: one entity's when kind and id are
  // given, otherwise the whole directory's.
  history: async (target?: { kind: PlacementKind; id: string }, limit?: number): Promise<Modification[]> => {
    const url = target
      ? `${BASE}/${target.kind}/${encodeURIComponent(target.id)}/history${qs({ limit })}`
      : `${BASE}/history${qs({ limit })}`;
    const body = await request<{ history?: Modification[] }>(url);
    return body.history ?? [];
  },
  mapfileStatus: (): Promise<MapfileStatus> => request(`${BASE}/mapfile-status`),

  // Access requests from people the placementd does not map.
  requests: (status: AccessRequestStatus | "all" = "pending"): Promise<AccessRequestList> =>
    request(`${BASE}/requests${qs({ status })}`),
  pendingRequests: async (): Promise<number> =>
    (await request<{ pending: number }>(`${BASE}/requests/count`)).pending,
  // approve onboards the request's identity in one batch, recorded as the
  // signed-in admin's change.
  approveRequest: (id: number, input: ApproveInput, dryRun = false): Promise<ApproveResponse> =>
    request(`${BASE}/requests/${id}/approve`, {
      method: "POST",
      body: JSON.stringify({ ...input, dry_run: dryRun }),
    }),
  denyRequest: (id: number, reason: string): Promise<AccessRequest> =>
    request(`${BASE}/requests/${id}/deny`, { method: "POST", body: JSON.stringify({ reason }) }),
  // resolve marks a request approved for an identity given access some
  // other way.
  resolveRequest: (id: number, comment?: string): Promise<AccessRequest> =>
    request(`${BASE}/requests/${id}/resolve`, {
      method: "POST",
      body: JSON.stringify(comment?.trim() ? { comment: comment.trim() } : {}),
    }),
};

function withComment<T extends object>(body: T, changeComment?: string): T & { change_comment?: string } {
  const c = changeComment?.trim();
  return c ? { ...body, change_comment: c } : body;
}

// describeBatchError is describeEditError for a batch: the sentence, led by
// the 1-based step that failed. The placementd names the step as a 0-based
// "operation N:" inside its message; that is replaced, not repeated.
export function describeBatchError(err: unknown): string {
  let text = describeEditError(err);
  let index: number | undefined;
  const daemon = /(?:placementd edit: )?operation (\d+): /i.exec(text);
  if (daemon) {
    index = Number(daemon[1]);
    text = text.slice(0, daemon.index) + text.slice(daemon.index + daemon[0].length);
  }
  if (err instanceof PlacementAdminError) {
    const failed = err.results.find((r) => r.error_code);
    if (failed) index = failed.index;
  }
  return index === undefined ? text : `Step ${index + 1}: ${text}`;
}

// describeEditError turns a refusal into the sentence an admin acts on.
export function describeEditError(err: unknown): string {
  if (err instanceof PlacementAdminError) {
    if (err.isVersionConflict) {
      return "This entry changed since you loaded it. Reload and try again.";
    }
    if (err.ownedBy === "mapfile") {
      return "This entry comes from the map file. Adopt it before editing.";
    }
    if (err.cascadeRequired) {
      return `${err.message} Delete with its references to proceed.`;
    }
    return err.message;
  }
  return err instanceof Error ? err.message : String(err);
}
