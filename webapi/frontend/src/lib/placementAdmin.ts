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
}

export interface DirIdentity extends PlacementEntityMeta {
  // The sign-in identity.
  name: string;
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
  name?: string;
  expected_version?: number;
  cascade?: boolean;
  fields?: EntityFields;
}

// PlacementAdminError is an ApiError with the directory's refusal details.
export class PlacementAdminError extends ApiError {
  placementCode?: number;
  ownedBy?: string;
  cascadeRequired: boolean;
  results: EditResult[];
  constructor(
    status: number,
    message: string,
    body: {
      placement_code?: number;
      owned_by?: string;
      cascade_required?: boolean;
      results?: EditResult[];
    },
  ) {
    super(status, message);
    this.placementCode = body.placement_code;
    this.ownedBy = body.owned_by;
    this.cascadeRequired = body.cascade_required === true;
    this.results = body.results ?? [];
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
  create: (kind: PlacementKind, fields: EntityFields, dryRun = false): Promise<EditResponse> =>
    request(`${BASE}/${kind}${qs({ dry_run: dryRun })}`, {
      method: "POST",
      body: JSON.stringify(fields),
    }),
  update: (
    kind: PlacementKind,
    id: string,
    expectedVersion: number,
    fields: EntityFields,
  ): Promise<EditResponse> =>
    request(`${BASE}/${kind}/${encodeURIComponent(id)}`, {
      method: "PATCH",
      body: JSON.stringify({ ...fields, expected_version: expectedVersion }),
    }),
  remove: (
    kind: PlacementKind,
    id: string,
    opts: { cascade?: boolean; expectedVersion?: number } = {},
  ): Promise<EditResponse> =>
    request(
      `${BASE}/${kind}/${encodeURIComponent(id)}${qs({
        cascade: opts.cascade,
        expected_version: opts.expectedVersion,
      })}`,
      { method: "DELETE" },
    ),
  adopt: (kind: PlacementKind, id: string, expectedVersion?: number): Promise<EditResponse> =>
    request(`${BASE}/${kind}/${encodeURIComponent(id)}/adopt`, {
      method: "POST",
      body: JSON.stringify(expectedVersion ? { expected_version: expectedVersion } : {}),
    }),
  adoptAll: (): Promise<EditResponse> => request(`${BASE}/adopt-all`, { method: "POST" }),
  batch: (operations: BatchOperation[], dryRun = false): Promise<EditResponse> =>
    request(`${BASE}/batch`, {
      method: "POST",
      body: JSON.stringify({ dry_run: dryRun, operations }),
    }),
  mapfileStatus: (): Promise<MapfileStatus> => request(`${BASE}/mapfile-status`),
};

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
