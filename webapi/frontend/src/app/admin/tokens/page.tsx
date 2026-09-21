"use client";

import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, type AdminToken } from "@/lib/api";
import { ConfirmButton } from "@/components/ConfirmButton";

export default function AdminTokensPage() {
  const [activeOnly, setActiveOnly] = useState(true);
  const [clientFilter, setClientFilter] = useState("");
  const qc = useQueryClient();

  const revoke = useMutation({
    mutationFn: (t: AdminToken) =>
      api.admin.revokeToken({ kind: t.kind, fingerprint: t.signature_prefix }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["admin", "tokens"] }),
  });

  // Narrowing sends the scopes to KEEP. The server refuses anything the
  // grant does not already hold, so this cannot widen; see
  // handleAdminSetTokenScopes.
  const narrow = useMutation({
    mutationFn: ({ token, drop }: { token: AdminToken; drop: string }) =>
      api.admin.setTokenScopes({
        kind: token.kind,
        fingerprint: token.signature_prefix,
        scopes: (token.scopes ?? []).filter((s) => s !== drop),
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["admin", "tokens"] }),
  });

  const { data, isLoading, error } = useQuery({
    queryKey: ["admin", "tokens", { activeOnly, clientFilter }],
    queryFn: () =>
      api.admin.listTokens({
        active_only: activeOnly,
        client_id: clientFilter || undefined,
        limit: 500,
      }),
    refetchInterval: 30_000,
  });

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
          Scopes shown are what each grant was actually GRANTED, which can be
          less than the client asked for. Removing one applies to the whole
          grant for the same reason; scopes cannot be added here, because
          adding one would have neither the user&rsquo;s consent nor the group
          policy behind it.
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
          placeholder="Filter by client ID"
          value={clientFilter}
          onChange={(e) => setClientFilter(e.target.value)}
          className="rounded-sm border border-gray-300 px-2 py-1 text-sm font-mono w-72"
        />
      </div>

      {isLoading && <p className="text-gray-400">Loading...</p>}
      {error && (
        <p className="text-red-600 text-sm">{(error as Error).message}</p>
      )}

      {data && data.tokens.length === 0 && (
        <p className="text-gray-500 text-sm">No tokens match.</p>
      )}

      {data && data.tokens.length > 0 && (
        <div className="overflow-x-auto rounded-lg border border-gray-200 bg-white">
          <table className="min-w-full text-sm">
            <thead className="bg-gray-50 text-left text-xs uppercase tracking-wide text-gray-500">
              <tr>
                <th className="px-3 py-2">Kind</th>
                <th className="px-3 py-2">Fingerprint</th>
                <th className="px-3 py-2">Client</th>
                <th className="px-3 py-2">Subject</th>
                <th className="px-3 py-2">Scopes</th>
                <th className="px-3 py-2">Issued</th>
                <th className="px-3 py-2">Expires</th>
                <th className="px-3 py-2 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {data.tokens.map((t, i) => (
                <TokenRow
                  key={`${t.kind}-${t.signature_prefix}-${i}`}
                  token={t}
                  onRevoke={() => revoke.mutate(t)}
                  onDropScope={(scope) => narrow.mutate({ token: t, drop: scope })}
                  busy={revoke.isPending || narrow.isPending}
                />
              ))}
            </tbody>
          </table>
        </div>
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
  onDropScope,
  busy,
}: {
  token: AdminToken;
  onDropScope: (scope: string) => void;
  busy: boolean;
}) {
  const scopes = token.scopes ?? [];
  if (scopes.length === 0) {
    return <span className="text-gray-400">—</span>;
  }
  return (
    <div className="flex flex-wrap gap-1">
      {scopes.map((scope) => {
        const privileged = privilegedScopes.has(scope);
        return (
          <span
            key={scope}
            className={`inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-xs ${
              privileged
                ? "bg-amber-100 text-amber-900 ring-1 ring-amber-300"
                : "bg-blue-100 text-blue-800"
            }`}
            title={privileged ? `${scope} — acts on other users' jobs` : scope}
          >
            {scope}
            {token.active && (
              <button
                type="button"
                onClick={() => onDropScope(scope)}
                disabled={busy}
                aria-label={`Remove ${scope} from this grant`}
                title={`Remove ${scope} from this grant and its paired token`}
                className="leading-none text-current/60 hover:text-current disabled:opacity-40"
              >
                ×
              </button>
            )}
          </span>
        );
      })}
    </div>
  );
}

function TokenRow({
  token,
  onRevoke,
  onDropScope,
  busy,
}: {
  token: AdminToken;
  onRevoke: () => void;
  onDropScope: (scope: string) => void;
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
      <td className="px-3 py-2 font-mono text-xs">{token.client_id}</td>
      <td className="px-3 py-2 text-xs">{token.subject || "—"}</td>
      <td className="px-3 py-2 text-xs">
        <ScopeChips token={token} onDropScope={onDropScope} busy={busy} />
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
