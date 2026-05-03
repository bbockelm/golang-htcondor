'use client';

import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { api, type AdminToken } from '@/lib/api';

export default function AdminTokensPage() {
  const [activeOnly, setActiveOnly] = useState(true);
  const [clientFilter, setClientFilter] = useState('');

  const { data, isLoading, error } = useQuery({
    queryKey: ['admin', 'tokens', { activeOnly, clientFilter }],
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
          tokens.
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
          className="rounded border border-gray-300 px-2 py-1 text-sm font-mono w-72"
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
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {data.tokens.map((t, i) => (
                <TokenRow key={`${t.kind}-${t.signature_prefix}-${i}`} token={t} />
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function TokenRow({ token }: { token: AdminToken }) {
  return (
    <tr className={token.active ? 'hover:bg-gray-50' : 'bg-gray-50/40 text-gray-400'}>
      <td className="px-3 py-2">
        <span
          className={`inline-flex rounded-full px-2 py-0.5 text-xs font-medium ${
            token.kind === 'access'
              ? 'bg-blue-100 text-blue-800'
              : 'bg-purple-100 text-purple-800'
          }`}
        >
          {token.kind}
        </span>
      </td>
      <td className="px-3 py-2 font-mono text-xs">{token.signature_prefix}</td>
      <td className="px-3 py-2 font-mono text-xs">{token.client_id}</td>
      <td className="px-3 py-2 text-xs">{token.subject || '—'}</td>
      <td className="px-3 py-2 text-xs">{token.scopes?.join(' ') || '—'}</td>
      <td className="px-3 py-2 text-xs">
        {new Date(token.requested_at).toLocaleString()}
      </td>
      <td className="px-3 py-2 text-xs">
        {token.expires_at ? new Date(token.expires_at).toLocaleString() : '—'}
      </td>
    </tr>
  );
}
