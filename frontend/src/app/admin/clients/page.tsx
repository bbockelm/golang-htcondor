'use client';

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { api, type AdminClient } from '@/lib/api';

export default function AdminClientsPage() {
  const qc = useQueryClient();
  const { data, isLoading, error } = useQuery({
    queryKey: ['admin', 'clients'],
    queryFn: api.admin.listClients,
  });

  const remove = useMutation({
    mutationFn: (id: string) => api.admin.deleteClient(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['admin', 'clients'] });
      qc.invalidateQueries({ queryKey: ['admin', 'tokens'] });
    },
  });

  return (
    <div className="space-y-4 max-w-5xl">
      <div>
        <h1 className="text-2xl font-bold text-gray-900">OAuth2 Clients</h1>
        <p className="text-sm text-gray-500">
          Registered clients including those auto-created via dynamic
          registration. Deleting a client revokes all of its tokens.
        </p>
      </div>

      {isLoading && <p className="text-gray-400">Loading...</p>}
      {error && (
        <p className="text-red-600 text-sm">
          {(error as Error).message}
        </p>
      )}

      {data && data.clients.length === 0 && (
        <p className="text-gray-500 text-sm">No clients registered.</p>
      )}

      {data && data.clients.length > 0 && (
        <div className="overflow-x-auto rounded-lg border border-gray-200 bg-white">
          <table className="min-w-full text-sm">
            <thead className="bg-gray-50 text-left text-xs uppercase tracking-wide text-gray-500">
              <tr>
                <th className="px-3 py-2">Client ID</th>
                <th className="px-3 py-2">Type</th>
                <th className="px-3 py-2">Grants</th>
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
                    if (confirm(`Delete client "${c.id}"? This revokes all tokens.`)) {
                      remove.mutate(c.id);
                    }
                  }}
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
    </div>
  );
}

function ClientRow({
  client,
  onDelete,
  busy,
}: {
  client: AdminClient;
  onDelete: () => void;
  busy: boolean;
}) {
  return (
    <tr className="hover:bg-gray-50">
      <td className="px-3 py-2 font-mono text-xs">{client.id}</td>
      <td className="px-3 py-2">
        <span
          className={`inline-flex rounded-full px-2 py-0.5 text-xs font-medium ${
            client.public
              ? 'bg-amber-100 text-amber-800'
              : 'bg-gray-100 text-gray-700'
          }`}
        >
          {client.public ? 'public' : 'confidential'}
        </span>
      </td>
      <td className="px-3 py-2 text-xs text-gray-700">
        {client.grant_types?.join(', ') || '—'}
      </td>
      <td className="px-3 py-2 text-xs text-gray-700">
        {client.scopes?.join(' ') || '—'}
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
          {busy ? 'Deleting...' : 'Delete'}
        </button>
      </td>
    </tr>
  );
}
