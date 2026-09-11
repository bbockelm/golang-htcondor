"use client";

// OAuth2 client list.
//
// A dynamically registered client's id is "client_<unixnano>", which
// tells an admin nothing about what the client is or where it came
// from. The list therefore leads with whatever identity we can recover,
// in order of trustworthiness: the name the client registered under,
// then the operator's own note, and only then the generated id.
//
// Three provenance signals sit next to each other on purpose:
//   - origin  — how the client came to exist (registered itself, or we
//               seeded it). Absent means UNKNOWN, which is rendered as
//               its own state rather than as "not dynamic".
//   - last used — whether anyone still gets tokens through it. A client
//               that registered once and never came back is the churn
//               worth deleting.
//   - recent users — who it acts for.
//
// List-valued columns render through ChipList, which also keeps them
// readable now that the server hands back real arrays rather than
// comma-split JSON fragments.

import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { api, type AdminClient } from "@/lib/api";
import { ChipList } from "@/components/ChipList";
import { ConfirmButton } from "@/components/ConfirmButton";

export default function AdminClientsPage() {
  const qc = useQueryClient();
  const { data, isLoading, error } = useQuery({
    queryKey: ["admin", "clients"],
    queryFn: api.admin.listClients,
  });

  const remove = useMutation({
    mutationFn: (id: string) => api.admin.deleteClient(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["admin", "clients"] });
      qc.invalidateQueries({ queryKey: ["admin", "tokens"] });
    },
  });

  const annotate = useMutation({
    mutationFn: ({ id, notes }: { id: string; notes: string }) =>
      api.admin.updateClientNotes(id, notes),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['admin', 'clients'] }),
  });

  const editPolicy = useMutation({
    mutationFn: ({ id, grant_types, service_subject }: {
      id: string;
      grant_types: string[];
      service_subject: string;
    }) => api.admin.updateClient(id, { grant_types, service_subject }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['admin', 'clients'] }),
  });

  return (
    <div className="space-y-4 max-w-6xl">
      <div>
        <h1 className="text-2xl font-bold text-gray-900">OAuth2 Clients</h1>
        <p className="text-sm text-gray-500">
          Registered clients, including those created by dynamic
          registration. A client that has never obtained a token is
          registration churn and is safe to delete; deleting revokes all of
          its tokens.
        </p>
      </div>

      {isLoading && <p className="text-gray-400">Loading...</p>}
      {error && (
        <p className="text-red-600 text-sm">{(error as Error).message}</p>
      )}

      {data && data.clients.length === 0 && (
        <p className="text-gray-500 text-sm">No clients registered.</p>
      )}

      {data && data.clients.length > 0 && (
        <div className="overflow-x-auto rounded-lg border border-gray-200 bg-white">
          <table className="min-w-full text-sm">
            <thead className="bg-gray-50 text-left text-xs uppercase tracking-wide text-gray-500">
              <tr>
                <th className="px-3 py-2">Client</th>
                <th className="px-3 py-2">Type</th>
                <th className="px-3 py-2">Grants</th>
                <th className="px-3 py-2">Last used</th>
                <th className="px-3 py-2">Recent users</th>
                <th className="px-3 py-2">Scopes</th>
                <th className="px-3 py-2">Created</th>
                <th className="px-3 py-2"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {data.clients.map((c) => (
                <ClientRow
                  key={c.id}
                  client={c}
                  onDelete={() => remove.mutate(c.id)}
                  onSaveNotes={(notes) => annotate.mutate({ id: c.id, notes })}
                  savingNotes={
                    annotate.isPending && annotate.variables?.id === c.id
                  }
                  onSavePolicy={(grant_types, service_subject) =>
                    editPolicy.mutate({ id: c.id, grant_types, service_subject })
                  }
                  savingPolicy={
                    editPolicy.isPending && editPolicy.variables?.id === c.id
                  }
                  policyError={
                    editPolicy.variables?.id === c.id && editPolicy.isError
                      ? (editPolicy.error as Error).message
                      : undefined
                  }
                  busy={remove.isPending && remove.variables === c.id}
                />
              ))}
            </tbody>
          </table>
        </div>
      )}

      {remove.isError && (
        <p className="text-red-600 text-sm">
          Failed to delete: {(remove.error as Error).message}
        </p>
      )}
      {annotate.isError && (
        <p className="text-red-600 text-sm">
          Failed to save notes: {(annotate.error as Error).message}
        </p>
      )}
    </div>
  );
}

// clientLabel is the best available human name, in descending order of
// trustworthiness. Falls back to the id, which is at least unique.
function clientLabel(client: AdminClient): string {
  return client.name?.trim() || client.notes?.trim().split('\n')[0] || client.id;
}

function ClientRow({
  client,
  onDelete,
  onSaveNotes,
  savingNotes,
  onSavePolicy,
  savingPolicy,
  policyError,
  busy,
}: {
  client: AdminClient;
  onDelete: () => void;
  onSaveNotes: (notes: string) => void;
  savingNotes: boolean;
  onSavePolicy: (grantTypes: string[], serviceSubject: string) => void;
  savingPolicy: boolean;
  policyError?: string;
  busy: boolean;
}) {
  const named = !!client.name?.trim();
  return (
    <tr className="align-top hover:bg-gray-50">
      <td className="px-3 py-2">
        {named ? (
          <>
            <div className="font-medium text-gray-900">{client.name}</div>
            <div className="font-mono text-xs text-gray-500">{client.id}</div>
          </>
        ) : (
          <div className="font-mono text-xs text-gray-700">{client.id}</div>
        )}
        <NotesEditor
          notes={client.notes ?? ''}
          saving={savingNotes}
          onSave={onSaveNotes}
        />
      </td>
      <td className="px-3 py-2">
        <div className="flex flex-col items-start gap-1">
          <Chip
            tone={client.public ? 'amber' : 'gray'}
            title={
              client.public
                ? 'No client secret; relies on PKCE and the redirect URI.'
                : 'Authenticates with a client secret.'
            }
          >
            {client.public ? 'public' : 'confidential'}
          </Chip>
          <OriginChip origin={client.origin} />
        </div>
      </td>
      {/* Grant types decide what the client can actually do, and one
          absence in particular is worth being able to see: a client
          without refresh_token gets access tokens only, so its users
          are sent through a full re-authorization every time one
          expires. That shows up as "why does this app keep asking me to
          sign in?", and this column is the evidence. */}
      <td className="px-3 py-2 text-xs text-gray-700">
        <GrantsEditor
          client={client}
          saving={savingPolicy}
          error={policyError}
          onSave={onSavePolicy}
        />
        <RefreshWarning blockedBy={client.refresh_blocked_by} />
      </td>
      <td className="px-3 py-2 text-xs">
        {client.last_used_at ? (
          <span
            className="text-gray-700"
            title={new Date(client.last_used_at).toLocaleString()}
          >
            {relativeTime(client.last_used_at)}
          </span>
        ) : (
          <span className="text-gray-400" title="No token has ever been issued to this client.">
            never
          </span>
        )}
      </td>
      <td className="px-3 py-2 text-xs">
        {client.recent_users && client.recent_users.length > 0 ? (
          <ul className="space-y-0.5">
            {client.recent_users.map((u) => (
              <li
                key={u.subject}
                className="font-mono text-gray-700"
                title={`Last token ${new Date(u.at).toLocaleString()}`}
              >
                {u.subject}
              </li>
            ))}
          </ul>
        ) : (
          <span className="text-gray-400">—</span>
        )}
      </td>
      <td className="px-3 py-2 text-xs text-gray-700">
        <ChipList items={client.scopes} tone="blue" />
      </td>
      <td className="px-3 py-2 text-xs text-gray-500">
        {new Date(client.created_at).toLocaleString()}
      </td>
      <td className="px-3 py-2 text-right">
        <ConfirmButton
          compact
          label="Delete"
          confirmLabel="Delete"
          onConfirm={onDelete}
          pending={busy}
          title={`Delete client "${clientLabel(client)}" — this revokes all of its tokens`}
        />
      </td>
    </tr>
  );
}

// RefreshWarning surfaces a client that can never hold a refresh token.
//
// Nothing errors when this is misconfigured -- the client simply never
// receives a refresh token, and its users get sent through a full
// re-authorization every time an access token expires. That reaches an
// operator as "why does this app keep asking me to sign in?", with
// nothing in the logs to point at. The server works out the reason (it
// owns the OAuth semantics); this renders it.
function RefreshWarning({ blockedBy }: { blockedBy?: string[] }) {
  if (!blockedBy || blockedBy.length === 0) return null;
  return (
    <span
      className="mt-1 inline-flex rounded-full bg-amber-100 px-2 py-0.5 text-xs font-medium text-amber-900"
      title={`This client is missing ${blockedBy.join(" and ")}, so it never receives a refresh token. Its users re-authorize every time an access token expires.`}
    >
      cannot refresh
    </span>
  );
}

// OriginChip renders how the client came to exist. An absent origin is
// its own state: the row predates the field, so calling it "not
// dynamically registered" would assert something nobody recorded.
function OriginChip({ origin }: { origin?: string }) {
  if (origin === 'dynamic') {
    return (
      <Chip tone="blue" title="Registered itself through /mcp/oauth2/register (RFC 7591).">
        dynamic
      </Chip>
    );
  }
  if (origin === 'seeded') {
    return (
      <Chip tone="gray" title="Created by this server at startup.">
        built-in
      </Chip>
    );
  }
  return (
    <Chip
      tone="dashed"
      title="Registered before this server recorded client provenance. Not a claim that it was NOT dynamically registered — just that nobody wrote it down. Use notes to record what it is."
    >
      unknown
    </Chip>
  );
}

function Chip({
  tone,
  title,
  children,
}: {
  tone: 'gray' | 'amber' | 'blue' | 'dashed';
  title?: string;
  children: React.ReactNode;
}) {
  const cls =
    tone === 'amber'
      ? 'bg-amber-100 text-amber-800'
      : tone === 'blue'
        ? 'bg-blue-100 text-blue-800'
        : tone === 'dashed'
          ? 'border border-dashed border-gray-300 text-gray-500'
          : 'bg-gray-100 text-gray-700';
  return (
    <span
      title={title}
      className={`inline-flex rounded-full px-2 py-0.5 text-xs font-medium ${cls}`}
    >
      {children}
    </span>
  );
}

// EDITABLE_GRANTS is the set an admin may toggle here — the grants this server
// implements. device_code is a manual grant that is not per-client toggled, so
// it does not appear.
const EDITABLE_GRANTS: { value: string; label: string }[] = [
  { value: 'authorization_code', label: 'authorization_code' },
  { value: 'refresh_token', label: 'refresh_token' },
  { value: 'client_credentials', label: 'client_credentials' },
  { value: 'urn:ietf:params:oauth:grant-type:token-exchange', label: 'token_exchange' },
];

// CONFIDENTIAL_ONLY_GRANTS may not be given to a public client — they either
// authenticate with a secret or act on another principal's behalf. Kept in sync
// with the server's confidentialOnlyGrants.
const CONFIDENTIAL_ONLY_GRANTS = new Set([
  'client_credentials',
  'urn:ietf:params:oauth:grant-type:token-exchange',
]);

// GrantsEditor shows a client's permitted grant types and, on expand, lets an
// admin change them. client_credentials is disabled for a public client (it has
// no secret to authenticate the grant) and, when enabled, requires a service
// identity — the subject a client_credentials token asserts, which the schedd
// then authorizes. The server enforces the same rules; this just keeps the form
// from submitting an obviously-invalid combination.
function GrantsEditor({
  client,
  saving,
  error,
  onSave,
}: {
  client: AdminClient;
  saving: boolean;
  error?: string;
  onSave: (grantTypes: string[], serviceSubject: string) => void;
}) {
  const [editing, setEditing] = useState(false);
  const [grants, setGrants] = useState<string[]>([]);
  const [subject, setSubject] = useState('');

  if (!editing) {
    return (
      <button
        type="button"
        onClick={() => {
          // Seed drafts on entry (not via an effect syncing props — the row
          // re-renders after a save, and that cascade is what the lint rule
          // warns about).
          setGrants(client.grant_types ?? []);
          setSubject(client.service_subject ?? '');
          setEditing(true);
        }}
        className="block text-left"
        title="Edit permitted grant types"
      >
        <ChipList items={client.grant_types} max={4} />
        <span className="mt-0.5 block text-[11px] text-gray-400 hover:text-gray-600">
          edit grants
        </span>
      </button>
    );
  }

  const toggle = (g: string) =>
    setGrants((prev) => (prev.includes(g) ? prev.filter((x) => x !== g) : [...prev, g]));

  const hasClientCreds = grants.includes('client_credentials');
  const subjectMissing = hasClientCreds && subject.trim() === '';

  return (
    <div className="mt-1 max-w-xs space-y-1">
      {EDITABLE_GRANTS.map((g) => {
        const disabled = client.public && CONFIDENTIAL_ONLY_GRANTS.has(g.value);
        return (
          <label
            key={g.value}
            className={`flex items-center gap-1.5 text-xs ${disabled ? 'text-gray-300' : 'text-gray-700'}`}
            title={disabled ? `A public client cannot use ${g.label} (it has no secret to authenticate it).` : undefined}
          >
            <input
              type="checkbox"
              checked={grants.includes(g.value)}
              disabled={disabled}
              onChange={() => toggle(g.value)}
            />
            <span className="font-mono">{g.label}</span>
          </label>
        );
      })}

      {hasClientCreds && (
        <input
          type="text"
          value={subject}
          onChange={(e) => setSubject(e.target.value)}
          placeholder="service identity (IDTOKEN subject)"
          className="w-full rounded-sm border border-gray-300 px-2 py-1 text-xs focus:border-brand-400 focus:outline-hidden focus:ring-1 focus:ring-brand-400"
        />
      )}

      {error && <p className="text-[11px] text-red-600">{error}</p>}

      <div className="flex gap-2 pt-0.5">
        <button
          type="button"
          disabled={saving || grants.length === 0 || subjectMissing}
          onClick={() => {
            onSave(grants, subject.trim());
            setEditing(false);
          }}
          className="rounded-sm bg-brand-600 px-2 py-0.5 text-xs font-medium text-white hover:bg-brand-700 disabled:opacity-50"
          title={subjectMissing ? 'client_credentials needs a service identity' : undefined}
        >
          {saving ? 'Saving...' : 'Save'}
        </button>
        <button
          type="button"
          onClick={() => setEditing(false)}
          className="text-xs text-gray-500 hover:text-gray-800"
        >
          Cancel
        </button>
      </div>
    </div>
  );
}

// NotesEditor is an inline annotation field. Collapsed to a line of text
// (or an "add note" affordance) until clicked, so the common case of
// scanning the list is not a wall of textareas.
function NotesEditor({
  notes,
  saving,
  onSave,
}: {
  notes: string;
  saving: boolean;
  onSave: (notes: string) => void;
}) {
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState(notes);

  if (!editing) {
    return (
      <button
        type="button"
        onClick={() => {
          // Seed the draft on entry rather than tracking `notes` in an
          // effect: the row re-renders after a save, and syncing state
          // from props in an effect is exactly the cascade the lint
          // rule (and React) warn about.
          setDraft(notes);
          setEditing(true);
        }}
        className="mt-1 block max-w-xs text-left text-xs"
      >
        {notes ? (
          <span className="whitespace-pre-wrap text-gray-600 hover:text-gray-900">
            {notes}
          </span>
        ) : (
          <span className="text-gray-400 hover:text-gray-600">+ add note</span>
        )}
      </button>
    );
  }

  return (
    <div className="mt-1 max-w-xs">
      <textarea
        value={draft}
        onChange={(e) => setDraft(e.target.value)}
        rows={2}
        autoFocus
        placeholder="What is this client?"
        className="w-full rounded-sm border border-gray-300 px-2 py-1 text-xs focus:border-brand-400 focus:outline-hidden focus:ring-1 focus:ring-brand-400"
      />
      <div className="mt-1 flex gap-2">
        <button
          type="button"
          disabled={saving}
          onClick={() => {
            onSave(draft);
            setEditing(false);
          }}
          className="rounded-sm bg-brand-600 px-2 py-0.5 text-xs font-medium text-white hover:bg-brand-700 disabled:opacity-50"
        >
          {saving ? 'Saving...' : 'Save'}
        </button>
        <button
          type="button"
          onClick={() => setEditing(false)}
          className="text-xs text-gray-500 hover:text-gray-800"
        >
          Cancel
        </button>
      </div>
    </div>
  );
}

// relativeTime renders a coarse "how long ago". The underlying value is
// written on a debounced flush and is approximate by construction, so a
// precise timestamp would overstate what we know; the exact value is in
// the title attribute for anyone who wants it.
function relativeTime(iso: string): string {
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return iso;
  const secs = Math.round((Date.now() - then) / 1000);
  if (secs < 0) return 'just now';
  if (secs < 90) return 'just now';
  const mins = Math.round(secs / 60);
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.round(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.round(hours / 24);
  if (days < 30) return `${days}d ago`;
  return new Date(iso).toLocaleDateString();
}
