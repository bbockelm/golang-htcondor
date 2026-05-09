'use client';

// API key management page.
//
// Admins mint keys for non-interactive callers (Prometheus, scripts,
// CI). The full wire-format key (`htca-v1-...`) is shown EXACTLY ONCE
// in a one-time-display modal — there is no recovery path. List and
// delete operations only ever see metadata.
//
// Soft-deleted keys remain in the list with a "Revoked" badge so a
// fat-finger delete can still be audited. The server enforces
// "creator can only delete their own keys"; the UI gives no way to
// see other admins' keys at all.

import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  api,
  type AdminAPIKey,
  type AdminAPIKeyCreateResponse,
} from '@/lib/api';

export default function AdminAPIKeysPage() {
  const qc = useQueryClient();
  const list = useQuery({
    queryKey: ['admin', 'api-keys'],
    queryFn: api.admin.listAPIKeys,
  });

  // Just-minted key kept in component state so we can show it once.
  // Cleared on dismiss; we never persist this to any storage.
  const [justMinted, setJustMinted] =
    useState<AdminAPIKeyCreateResponse | null>(null);

  const create = useMutation({
    mutationFn: api.admin.createAPIKey,
    onSuccess: (resp) => {
      setJustMinted(resp);
      qc.invalidateQueries({ queryKey: ['admin', 'api-keys'] });
    },
  });

  const remove = useMutation({
    mutationFn: (keyID: string) => api.admin.deleteAPIKey(keyID),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['admin', 'api-keys'] }),
  });

  const validScopes = list.data?.valid_scopes ?? {};

  return (
    <div className="space-y-4 max-w-5xl">
      <div>
        <h1 className="text-2xl font-bold text-gray-900">API Keys</h1>
        <p className="text-sm text-gray-500">
          Long-lived bearer tokens for non-interactive callers (Prometheus,
          scripts, CI). The full key is shown once at creation; subsequent
          views only show metadata. Deleting is a soft-delete — the key
          stops authenticating immediately and the row stays for audit.
        </p>
      </div>

      <NewKeyForm
        validScopes={validScopes}
        busy={create.isPending}
        error={create.error as Error | null}
        onSubmit={(req) => create.mutate(req)}
      />

      {justMinted && (
        <NewKeyShown
          minted={justMinted}
          onDismiss={() => setJustMinted(null)}
        />
      )}

      {list.isLoading && <p className="text-gray-400">Loading…</p>}
      {list.error && (
        <p className="text-red-600 text-sm">
          {(list.error as Error).message}
        </p>
      )}

      {list.data && list.data.api_keys.length === 0 && (
        <p className="text-gray-500 text-sm">No API keys yet.</p>
      )}

      {list.data && list.data.api_keys.length > 0 && (
        <div className="overflow-x-auto rounded-lg border border-gray-200 bg-white">
          <table className="min-w-full text-sm">
            <thead className="bg-gray-50 text-left text-xs uppercase tracking-wide text-gray-500">
              <tr>
                <th className="px-3 py-2">Name</th>
                <th className="px-3 py-2">Key prefix</th>
                <th className="px-3 py-2">Scopes</th>
                <th className="px-3 py-2">Created</th>
                <th className="px-3 py-2">Expires</th>
                <th className="px-3 py-2">Last used</th>
                <th className="px-3 py-2">Status</th>
                <th className="px-3 py-2"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {list.data.api_keys.map((k) => (
                <APIKeyRow
                  key={k.key_id}
                  apiKey={k}
                  onDelete={() => {
                    if (
                      confirm(
                        `Revoke API key "${k.name}"? Existing users will get 401 immediately.`,
                      )
                    ) {
                      remove.mutate(k.key_id);
                    }
                  }}
                  busy={remove.isPending && remove.variables === k.key_id}
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

// NewKeyForm is the small inline form for minting a key. We
// deliberately don't pop a modal — the form is short enough that
// inline placement keeps the flow obvious.
function NewKeyForm({
  validScopes,
  busy,
  error,
  onSubmit,
}: {
  validScopes: Record<string, string>;
  busy: boolean;
  error: Error | null;
  onSubmit: (req: {
    name: string;
    scopes: string[];
    expires_at?: string;
  }) => void;
}) {
  const [name, setName] = useState('');
  const [scopes, setScopes] = useState<Set<string>>(new Set());
  const [expiresInDays, setExpiresInDays] = useState<string>('never');
  const scopeNames = Object.keys(validScopes);

  const submit = () => {
    const trimmed = name.trim();
    if (!trimmed || scopes.size === 0) return;
    let expires_at: string | undefined;
    if (expiresInDays !== 'never') {
      const days = parseInt(expiresInDays, 10);
      if (Number.isFinite(days) && days > 0) {
        // RFC 3339 — the server's JSON decoder accepts this for
        // *time.Time. We use UTC so the displayed timestamp matches
        // what the server stores.
        expires_at = new Date(
          Date.now() + days * 24 * 60 * 60 * 1000,
        ).toISOString();
      }
    }
    onSubmit({ name: trimmed, scopes: Array.from(scopes), expires_at });
  };

  return (
    <div className="rounded-lg border border-gray-200 bg-white p-4">
      <h2 className="text-sm font-semibold text-gray-900">Mint new key</h2>
      <div className="mt-3 grid gap-3 sm:grid-cols-3">
        <label className="block text-xs">
          <span className="block text-gray-700">Name</span>
          <input
            type="text"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="e.g. prom-scrape"
            className="mt-1 w-full rounded border border-gray-300 px-2 py-1 text-sm focus:border-brand-400 focus:outline-none focus:ring-1 focus:ring-brand-400"
          />
        </label>
        <label className="block text-xs">
          <span className="block text-gray-700">Expires</span>
          <select
            value={expiresInDays}
            onChange={(e) => setExpiresInDays(e.target.value)}
            className="mt-1 w-full rounded border border-gray-300 px-2 py-1 text-sm focus:border-brand-400 focus:outline-none focus:ring-1 focus:ring-brand-400"
          >
            <option value="never">Never</option>
            <option value="30">In 30 days</option>
            <option value="90">In 90 days</option>
            <option value="365">In 1 year</option>
          </select>
        </label>
        <div className="block text-xs">
          <span className="block text-gray-700">Scopes</span>
          <div className="mt-1 space-y-1">
            {scopeNames.length === 0 ? (
              <span className="text-gray-400">Loading…</span>
            ) : (
              scopeNames.map((s) => (
                <label key={s} className="flex items-start gap-2">
                  <input
                    type="checkbox"
                    checked={scopes.has(s)}
                    onChange={() =>
                      setScopes((prev) => {
                        const next = new Set(prev);
                        if (next.has(s)) next.delete(s);
                        else next.add(s);
                        return next;
                      })
                    }
                    className="mt-0.5 rounded border-gray-300"
                  />
                  <span>
                    <span className="font-mono">{s}</span>{' '}
                    <span className="text-gray-500">— {validScopes[s]}</span>
                  </span>
                </label>
              ))
            )}
          </div>
        </div>
      </div>
      <div className="mt-3 flex items-center gap-3">
        <button
          type="button"
          onClick={submit}
          disabled={busy || !name.trim() || scopes.size === 0}
          className="rounded bg-brand-600 px-3 py-1 text-sm font-medium text-white hover:bg-brand-700 disabled:opacity-50"
        >
          {busy ? 'Minting…' : 'Mint key'}
        </button>
        {error && (
          <span className="text-xs text-red-600">{error.message}</span>
        )}
      </div>
    </div>
  );
}

// NewKeyShown is the shown-once display. Wraps a full-width readonly
// input + a Copy button. We deliberately make the user dismiss this
// rather than auto-clearing on a timer — copying to clipboard is
// fast enough that there's no excuse for accidental discard, and a
// user who fumbles the copy can re-read it.
function NewKeyShown({
  minted,
  onDismiss,
}: {
  minted: AdminAPIKeyCreateResponse;
  onDismiss: () => void;
}) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(minted.key);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Clipboard API can refuse on insecure origins; the input is
      // still selectable so the user can copy by hand.
    }
  };
  return (
    <div className="rounded-lg border border-amber-300 bg-amber-50 p-4">
      <h2 className="text-sm font-semibold text-amber-900">
        New key minted: <span className="font-mono">{minted.api_key.name}</span>
      </h2>
      <p className="mt-1 text-xs text-amber-800">
        Copy this key now. It will NEVER be shown again — losing it means
        revoking and minting a new one.
      </p>
      <div className="mt-2 flex gap-2">
        <input
          type="text"
          readOnly
          value={minted.key}
          onFocus={(e) => e.currentTarget.select()}
          className="flex-1 rounded border border-amber-300 bg-white px-2 py-1 font-mono text-xs text-gray-900"
        />
        <button
          type="button"
          onClick={copy}
          className="rounded border border-amber-400 bg-white px-3 py-1 text-xs font-medium text-amber-900 hover:bg-amber-100"
        >
          {copied ? 'Copied!' : 'Copy'}
        </button>
        <button
          type="button"
          onClick={onDismiss}
          className="rounded bg-amber-600 px-3 py-1 text-xs font-medium text-white hover:bg-amber-700"
        >
          I&apos;ve saved it
        </button>
      </div>
    </div>
  );
}

function APIKeyRow({
  apiKey,
  onDelete,
  busy,
}: {
  apiKey: AdminAPIKey;
  onDelete: () => void;
  busy: boolean;
}) {
  const revoked = !!apiKey.deleted_at;
  return (
    <tr className={`hover:bg-gray-50 ${revoked ? 'opacity-50' : ''}`}>
      <td className="px-3 py-2">{apiKey.name}</td>
      <td className="px-3 py-2 font-mono text-xs text-gray-700">
        htca-v1-{apiKey.key_id}…
      </td>
      <td className="px-3 py-2 text-xs text-gray-700">
        {apiKey.scopes.join(', ') || '—'}
      </td>
      <td className="px-3 py-2 text-xs text-gray-500">
        {new Date(apiKey.created_at).toLocaleString()}
      </td>
      <td className="px-3 py-2 text-xs text-gray-500">
        {apiKey.expires_at
          ? new Date(apiKey.expires_at).toLocaleDateString()
          : 'Never'}
      </td>
      <td className="px-3 py-2 text-xs text-gray-500">
        {apiKey.last_used_at
          ? new Date(apiKey.last_used_at).toLocaleString()
          : '—'}
      </td>
      <td className="px-3 py-2">
        {revoked ? (
          <span className="inline-flex rounded-full bg-gray-100 px-2 py-0.5 text-xs font-medium text-gray-600">
            Revoked
          </span>
        ) : (
          <span className="inline-flex rounded-full bg-emerald-100 px-2 py-0.5 text-xs font-medium text-emerald-800">
            Active
          </span>
        )}
      </td>
      <td className="px-3 py-2 text-right">
        {!revoked && (
          <button
            type="button"
            onClick={onDelete}
            disabled={busy}
            className="text-xs text-red-600 hover:text-red-800 disabled:opacity-50"
          >
            {busy ? 'Revoking…' : 'Revoke'}
          </button>
        )}
      </td>
    </tr>
  );
}
