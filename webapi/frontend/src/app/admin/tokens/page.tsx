"use client";

import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, type AdminToken } from "@/lib/api";
import { ChipList } from "@/components/ChipList";
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
                  busy={revoke.isPending}
                />
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function TokenRow({
  token,
  onRevoke,
  busy,
}: {
  token: AdminToken;
  onRevoke: () => void;
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
        <ChipList items={token.scopes} tone="blue" />
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
