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
                  onDelete={() => {
                    if (
                      confirm(
                        `Delete client "${clientLabel(c)}"? This revokes all of its tokens.`,
                      )
                    ) {
                      remove.mutate(c.id);
                    }
                  }}
                  onSaveNotes={(notes) => annotate.mutate({ id: c.id, notes })}
                  savingNotes={
                    annotate.isPending && annotate.variables?.id === c.id
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
  busy,
}: {
  client: AdminClient;
  onDelete: () => void;
  onSaveNotes: (notes: string) => void;
  savingNotes: boolean;
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
        <button
          onClick={onDelete}
          disabled={busy}
          className="text-xs text-red-600 hover:text-red-800 disabled:opacity-50"
        >
          {busy ? "Deleting..." : "Delete"}
        </button>
      </td>
    </tr>
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
        className="w-full rounded border border-gray-300 px-2 py-1 text-xs focus:border-brand-400 focus:outline-none focus:ring-1 focus:ring-brand-400"
      />
      <div className="mt-1 flex gap-2">
        <button
          type="button"
          disabled={saving}
          onClick={() => {
            onSave(draft);
            setEditing(false);
          }}
          className="rounded bg-brand-600 px-2 py-0.5 text-xs font-medium text-white hover:bg-brand-700 disabled:opacity-50"
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
