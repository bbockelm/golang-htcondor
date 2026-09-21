"use client";

import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, type AdminToken } from "@/lib/api";
import { ConfirmButton } from "@/components/ConfirmButton";
import {
  ScrollableTable,
  SortableHeader,
  useSortState,
  useSortedRows,
} from "@/components/SortableTable";

export default function AdminTokensPage() {
  const [activeOnly, setActiveOnly] = useState(true);
  const [clientFilter, setClientFilter] = useState("");
  const [sort, setSort] = useSortState<TokenSortKey>("issued");
  const qc = useQueryClient();

  const revoke = useMutation({
    mutationFn: (t: AdminToken) =>
      api.admin.revokeToken({ kind: t.kind, fingerprint: t.signature_prefix }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["admin", "tokens"] }),
  });

  // Narrowing sends the scopes to KEEP. The server refuses anything the
  // grant does not already hold, so this cannot widen; see
  // handleAdminSetTokenScopes.
  const setScopes = useMutation({
    mutationFn: ({ token, scope, enable }: { token: AdminToken; scope: string; enable: boolean }) => {
      const active = new Set(token.scopes ?? []);
      if (enable) {
        active.add(scope);
      } else {
        active.delete(scope);
      }
      // Send the whole set that should be in force, ordered as the
      // authorization had it so the request reads the same way twice.
      const order = token.authorized_scopes?.length ? token.authorized_scopes : (token.scopes ?? []);
      return api.admin.setTokenScopes({
        kind: token.kind,
        fingerprint: token.signature_prefix,
        scopes: order.filter((s) => active.has(s)),
      });
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ["admin", "tokens"] }),
  });

  const { data, isLoading, error } = useQuery({
    queryKey: ["admin", "tokens", { activeOnly, clientFilter }],
    queryFn: () =>
      api.admin.listTokens({
        active_only: activeOnly,
        limit: 500,
      }),
    refetchInterval: 30_000,
  });

  // Filtered here rather than by the server's client_id parameter: that
  // matches an exact id, and what somebody types is usually part of the
  // name they saw on the clients page.
  const needle = clientFilter.trim().toLowerCase();
  const matching = (data?.tokens ?? []).filter((t) =>
    needle === ""
      ? true
      : [t.client_id, t.client_name, t.notes, t.subject]
          .filter(Boolean)
          .some((field) => String(field).toLowerCase().includes(needle)),
  );
  const tokens = useSortedRows(matching, sort, tokenSortValue);

  return (
    <div className="space-y-4 max-w-5xl">
      <div>
        <h1 className="text-2xl font-bold text-gray-900">OAuth2 Tokens</h1>
        <p className="text-sm text-gray-500">
          Active access and refresh tokens. Signatures are redacted to a
          fingerprint; deleting a client (in OAuth2 Clients) revokes its
          tokens. Revoking one row here revokes the whole grant — the access
          token and the refresh token issued with it — because revoking an
          access token on its own only lasts until the client refreshes.
          Scopes shown are the ones this authorization ended with; struck-out
          ones are switched off. Click a scope to switch it off or back on —
          that applies to the whole grant, for the same reason. A scope the
          authorization never included cannot be added here, because it would
          have neither the user&rsquo;s consent nor the group policy behind it.
        </p>
      </div>

      <div className="flex flex-wrap items-center gap-4 text-sm">
        <label className="flex items-center gap-2">
          <input
            type="checkbox"
            checked={activeOnly}
            onChange={(e) => setActiveOnly(e.target.checked)}
          />
          Active only
        </label>
        <input
          type="text"
          placeholder="Filter by client, note or user"
          value={clientFilter}
          onChange={(e) => setClientFilter(e.target.value)}
          className="rounded-sm border border-gray-300 px-2 py-1 text-sm w-72"
        />
      </div>

      {isLoading && <p className="text-gray-400">Loading...</p>}
      {error && (
        <p className="text-red-600 text-sm">{(error as Error).message}</p>
      )}

      {data && tokens.length === 0 && (
        <p className="text-gray-500 text-sm">No tokens match.</p>
      )}

      {data && tokens.length > 0 && (
        <ScrollableTable>
          <table className="min-w-full text-sm">
            <thead className="bg-gray-50 text-left text-xs uppercase tracking-wide text-gray-500">
              <tr>
                <SortableHeader label="Kind" sortKey="kind" sort={sort} onSort={setSort} />
                <th className="px-3 py-2">Fingerprint</th>
                <SortableHeader label="Client" sortKey="client" sort={sort} onSort={setSort} />
                <SortableHeader label="Subject" sortKey="subject" sort={sort} onSort={setSort} />
                <th className="px-3 py-2">Scopes</th>
                <SortableHeader label="Issued" sortKey="issued" sort={sort} onSort={setSort} />
                <SortableHeader label="Expires" sortKey="expires" sort={sort} onSort={setSort} />
                <th className="px-3 py-2 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {tokens.map((t, i) => (
                <TokenRow
                  key={`${t.kind}-${t.signature_prefix}-${i}`}
                  token={t}
                  onRevoke={() => revoke.mutate(t)}
                  onToggleScope={(scope, enable) => setScopes.mutate({ token: t, scope, enable })}
                  busy={revoke.isPending || setScopes.isPending}
                />
              ))}
            </tbody>
          </table>
        </ScrollableTable>
      )}
    </div>
  );
}

// privilegedScopes act on other people's jobs rather than the holder's
// own. Marked so an operator scanning this page can see at a glance which
// agent is carrying one, which is the reason the page is worth reading.
const privilegedScopes = new Set(["mcp:admin", "mcp:superuser"]);

function ScopeChips({
  token,
  onToggleScope,
  busy,
}: {
  token: AdminToken;
  onToggleScope: (scope: string, enable: boolean) => void;
  busy: boolean;
}) {
  // Every scope the authorization ended with, whether or not it is in
  // force. Showing only the ones in force is what made switching a scope
  // off look like deleting it, with no way back.
  const active = new Set(token.scopes ?? []);
  const all = token.authorized_scopes?.length ? token.authorized_scopes : (token.scopes ?? []);
  if (all.length === 0) {
    return <span className="text-gray-400">—</span>;
  }
  return (
    <div className="flex flex-wrap gap-1">
      {all.map((scope) => {
        const on = active.has(scope);
        const privileged = privilegedScopes.has(scope);
        const tone = !on
          ? "bg-gray-100 text-gray-400 line-through ring-1 ring-gray-300"
          : privileged
            ? "bg-amber-100 text-amber-900 ring-1 ring-amber-300"
            : "bg-blue-100 text-blue-800";
        const label = on
          ? `Switch ${scope} off for this grant and its paired token`
          : `Switch ${scope} back on`;
        return (
          <button
            key={scope}
            type="button"
            onClick={() => onToggleScope(scope, !on)}
            disabled={busy || !token.active}
            aria-pressed={on}
            title={token.active ? label : scope}
            className={`inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-xs ${tone} ${
              token.active ? "cursor-pointer hover:brightness-95" : "cursor-default"
            } disabled:opacity-60`}
          >
            {scope}
            {privileged && on && (
              <span className="text-[10px] font-semibold uppercase tracking-wide">
                other users
              </span>
            )}
          </button>
        );
      })}
    </div>
  );
}

type TokenSortKey = "kind" | "client" | "subject" | "issued" | "expires";

// Sorted on the underlying value, not the rendered cell: "Issued" renders
// as a locale string, and ordering that text puts April before January.
function tokenSortValue(t: AdminToken, key: TokenSortKey) {
  switch (key) {
    case "kind":
      return t.kind;
    case "client":
      // By the label somebody reads, falling back to the id when there is
      // none -- sorting by id would scatter a client's rows under a
      // generated string nobody recognises.
      return t.client_name || t.client_id;
    case "subject":
      return t.subject;
    case "issued":
      return new Date(t.requested_at);
    case "expires":
      return t.expires_at ? new Date(t.expires_at) : undefined;
  }
}

function TokenRow({
  token,
  onRevoke,
  onToggleScope,
  busy,
}: {
  token: AdminToken;
  onRevoke: () => void;
  onToggleScope: (scope: string, enable: boolean) => void;
  busy: boolean;
}) {
  return (
    <tr
      className={
        token.active ? "hover:bg-gray-50" : "bg-gray-50/40 text-gray-400"
      }
    >
      <td className="px-3 py-2">
        <span
          className={`inline-flex rounded-full px-2 py-0.5 text-xs font-medium ${
            token.kind === "access"
              ? "bg-blue-100 text-blue-800"
              : "bg-purple-100 text-purple-800"
          }`}
        >
          {token.kind}
        </span>
      </td>
      <td className="px-3 py-2 font-mono text-xs">{token.signature_prefix}</td>
      <td className="px-3 py-2 text-xs">
        {token.client_name ? (
          <>
            <div className="font-medium text-gray-900">{token.client_name}</div>
            <div className="font-mono text-[11px] text-gray-500">{token.client_id}</div>
          </>
        ) : (
          <span className="font-mono">{token.client_id}</span>
        )}
        {token.notes && <div className="mt-0.5 text-[11px] text-gray-500">{token.notes}</div>}
      </td>
      <td className="px-3 py-2 text-xs">{token.subject || "—"}</td>
      <td className="px-3 py-2 text-xs">
        <ScopeChips token={token} onToggleScope={onToggleScope} busy={busy} />
      </td>
      <td className="px-3 py-2 text-xs">
        {new Date(token.requested_at).toLocaleString()}
      </td>
      <td className="px-3 py-2 text-xs">
        {token.expires_at ? new Date(token.expires_at).toLocaleString() : "—"}
      </td>
      <td className="px-3 py-2 text-right">
        {token.active ? (
          <ConfirmButton
            compact
            label="Revoke"
            confirmLabel="Revoke"
            onConfirm={onRevoke}
            pending={busy}
            title={`Revoke this grant for ${token.subject || token.client_id} — the paired refresh token goes with it`}
          />
        ) : (
          <span className="text-xs text-gray-400">revoked</span>
        )}
      </td>
    </tr>
  );
}
