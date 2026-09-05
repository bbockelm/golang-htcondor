'use client';

// Placement page — the AP-side view of condor_placementd.
//
// The placementd maps "foreign" identities (a campus IdP account, a course
// roster entry) onto local AP accounts and mints IDTokens for them. This page
// mirrors the reference portal's shape: an authorization legend rendered with
// the operator's own labels and colors, a roster of mapped users, the tokens
// that have been issued, and a form that mints one.
//
// Two things drive the design:
//
//   * The token is shown EXACTLY ONCE. The daemon stores only the token's jti
//     and claims, never the token, so there is no recovery path — the same
//     one-time-display treatment the API keys page uses.
//   * Labels and colors come from the daemon's authorizations map file, not
//     from here. Rendering them is the whole point: an operator changes the
//     map file and this page changes with it.

import { useMemo, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  ApiError,
  api,
  type PlacementAuthorization,
  type PlacementToken,
  type PlacementUser,
} from '@/lib/api';

type Tab = 'users' | 'tokens' | 'authorizations';

export default function AdminPlacementPage() {
  const status = useQuery({
    queryKey: ['placement', 'status'],
    queryFn: api.placement.status,
  });

  const [tab, setTab] = useState<Tab>('users');
  // The issue form's username lives up here so a row's "Issue token" button
  // can fill it from an event handler. Syncing it into the child's own state
  // instead would mean a render-phase update, which React rightly complains
  // about.
  const [issueFor, setIssueFor] = useState('');

  const available = status.data?.available === true;

  const authorizations = useQuery({
    queryKey: ['placement', 'authorizations'],
    queryFn: () => api.placement.listAuthorizations(),
    enabled: available,
  });

  // Index authorizations by name so a user's bare authorization strings can
  // be rendered with the operator's label and color.
  const authzByName = useMemo(() => {
    const m = new Map<string, PlacementAuthorization>();
    for (const a of authorizations.data?.authorizations ?? []) {
      m.set(a.name.toUpperCase(), a);
    }
    return m;
  }, [authorizations.data]);

  return (
    <div className="max-w-6xl space-y-4">
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Placement</h1>
        <p className="text-sm text-gray-500">
          Issue and audit access-point credentials for identities that
          authenticate elsewhere. The placementd&apos;s map files decide who may
          log in, as which local account, with which authorizations, and against
          which projects.
        </p>
      </div>

      {status.isLoading && <p className="text-gray-400">Loading…</p>}
      {status.error && (
        <ErrorNote error={status.error as Error} what="check placement status" />
      )}

      {status.data && !available && (
        <div className="rounded-lg border border-gray-200 bg-white p-4">
          <h2 className="text-sm font-semibold text-gray-900">
            No placementd is available
          </h2>
          <p className="mt-1 text-sm text-gray-600">
            {status.data.reason ??
              'This access point is not configured to talk to a condor_placementd.'}
          </p>
        </div>
      )}

      {available && (
        <>
          <IssueTokenPanel
            authorizations={authorizations.data?.authorizations ?? []}
            username={issueFor}
            onUsernameChange={setIssueFor}
          />

          <div className="flex gap-1 border-b border-gray-200 text-sm">
            <TabButton active={tab === 'users'} onClick={() => setTab('users')}>
              Users
            </TabButton>
            <TabButton active={tab === 'tokens'} onClick={() => setTab('tokens')}>
              Tokens
            </TabButton>
            <TabButton
              active={tab === 'authorizations'}
              onClick={() => setTab('authorizations')}
            >
              Authorizations
            </TabButton>
          </div>

          {tab === 'users' && (
            <UsersTab
              authzByName={authzByName}
              onIssueFor={(u) => {
                setIssueFor(u.username);
                if (typeof window !== 'undefined') {
                  window.scrollTo({ top: 0, behavior: 'smooth' });
                }
              }}
            />
          )}
          {tab === 'tokens' && <TokensTab authzByName={authzByName} />}
          {tab === 'authorizations' && (
            <AuthorizationsTab
              authorizations={authorizations.data?.authorizations ?? []}
              loading={authorizations.isLoading}
              error={authorizations.error as Error | null}
            />
          )}
        </>
      )}
    </div>
  );
}

function TabButton({
  active,
  onClick,
  children,
}: {
  active: boolean;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`-mb-px border-b-2 px-3 py-2 font-medium ${
        active
          ? 'border-brand-600 text-brand-700'
          : 'border-transparent text-gray-500 hover:text-gray-800'
      }`}
    >
      {children}
    </button>
  );
}

// --- Issue token ---

function IssueTokenPanel({
  authorizations,
  username,
  onUsernameChange,
}: {
  authorizations: PlacementAuthorization[];
  // Owned by the page so the users table can target this form. The other
  // fields are local: a row button changes who the token is for and leaves
  // the rest of the operator's choices alone.
  username: string;
  onUsernameChange: (v: string) => void;
}) {
  const qc = useQueryClient();
  const [requester, setRequester] = useState('');
  const [project, setProject] = useState('');
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [issued, setIssued] = useState<{ token: string; username: string } | null>(
    null,
  );

  const login = useMutation({
    mutationFn: api.placement.login,
    onSuccess: (resp, vars) => {
      setIssued({ token: resp.token, username: vars.username });
      // A login creates the user (and project) record on the schedd and
      // adds a token row, so both lists are now stale.
      qc.invalidateQueries({ queryKey: ['placement', 'tokens'] });
      qc.invalidateQueries({ queryKey: ['placement', 'users'] });
    },
  });

  const submit = () => {
    const name = username.trim();
    if (!name) return;
    login.mutate({
      username: name,
      // An empty list means "everything this user is entitled to", which
      // is what an untouched form should ask for.
      authorizations: selected.size > 0 ? Array.from(selected) : undefined,
      project: project.trim() || undefined,
      requester: requester.trim() || undefined,
    });
  };

  return (
    <div className="space-y-3">
      <div className="rounded-lg border border-gray-200 bg-white p-4">
        <h2 className="text-sm font-semibold text-gray-900">Issue a token</h2>
        <p className="mt-1 text-xs text-gray-500">
          Mints an IDToken for a foreign identity and, if they have none yet,
          creates their user record on the schedd. A disabled user or project is
          refused rather than re-enabled.
        </p>

        <div className="mt-3 grid gap-3 sm:grid-cols-3">
          <label className="block text-xs">
            <span className="block text-gray-700">Username</span>
            <input
              type="text"
              value={username}
              onChange={(e) => onUsernameChange(e.target.value)}
              placeholder="student1@example.edu"
              className="mt-1 w-full rounded border border-gray-300 px-2 py-1 font-mono text-sm focus:border-brand-400 focus:outline-none focus:ring-1 focus:ring-brand-400"
            />
          </label>
          <label className="block text-xs">
            <span className="block text-gray-700">
              Project <span className="text-gray-400">(optional)</span>
            </span>
            <input
              type="text"
              value={project}
              onChange={(e) => setProject(e.target.value)}
              placeholder="Chem101"
              className="mt-1 w-full rounded border border-gray-300 px-2 py-1 text-sm focus:border-brand-400 focus:outline-none focus:ring-1 focus:ring-brand-400"
            />
          </label>
          <label className="block text-xs">
            <span className="block text-gray-700">
              Requester <span className="text-gray-400">(optional)</span>
            </span>
            <input
              type="text"
              value={requester}
              onChange={(e) => setRequester(e.target.value)}
              placeholder="instructor@example.edu"
              className="mt-1 w-full rounded border border-gray-300 px-2 py-1 font-mono text-sm focus:border-brand-400 focus:outline-none focus:ring-1 focus:ring-brand-400"
            />
          </label>
        </div>

        <div className="mt-3 text-xs">
          <span className="block text-gray-700">
            Authorizations{' '}
            <span className="text-gray-400">
              (none selected = everything this user is entitled to)
            </span>
          </span>
          {authorizations.length === 0 ? (
            <span className="mt-1 block text-gray-400">
              No authorizations are defined.
            </span>
          ) : (
            <div className="mt-1 flex flex-wrap gap-x-4 gap-y-1">
              {authorizations.map((a) => (
                <label key={a.name} className="flex items-center gap-2">
                  <input
                    type="checkbox"
                    checked={selected.has(a.name)}
                    onChange={() =>
                      setSelected((prev) => {
                        const next = new Set(prev);
                        if (next.has(a.name)) next.delete(a.name);
                        else next.add(a.name);
                        return next;
                      })
                    }
                    className="rounded border-gray-300"
                  />
                  <AuthzChip authz={a} />
                </label>
              ))}
            </div>
          )}
          <p className="mt-1 text-gray-400">
            Every authorization you pick must be one the user already has, or
            the whole request is refused.
          </p>
        </div>

        <div className="mt-3 flex items-center gap-3">
          <button
            type="button"
            onClick={submit}
            disabled={login.isPending || !username.trim()}
            className="rounded bg-brand-600 px-3 py-1 text-sm font-medium text-white hover:bg-brand-700 disabled:opacity-50"
          >
            {login.isPending ? 'Issuing…' : 'Issue token'}
          </button>
          {login.error && (
            <span className="text-xs text-red-600">
              {(login.error as Error).message}
            </span>
          )}
        </div>
      </div>

      {issued && (
        <IssuedToken
          token={issued.token}
          username={issued.username}
          onDismiss={() => setIssued(null)}
        />
      )}
    </div>
  );
}

// IssuedToken is the shown-once display. The placementd keeps only the jti, so
// this is genuinely the last time anyone sees the token.
function IssuedToken({
  token,
  username,
  onDismiss,
}: {
  token: string;
  username: string;
  onDismiss: () => void;
}) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(token);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // The clipboard API refuses on insecure origins; the textarea is
      // still selectable so the token can be copied by hand.
    }
  };
  return (
    <div className="rounded-lg border border-amber-300 bg-amber-50 p-4">
      <h2 className="text-sm font-semibold text-amber-900">
        Token issued for <span className="font-mono">{username}</span>
      </h2>
      <p className="mt-1 text-xs text-amber-800">
        Deliver this to the user now. It is not stored anywhere and will never be
        shown again — losing it means issuing another.
      </p>
      <textarea
        readOnly
        rows={3}
        value={token}
        onFocus={(e) => e.currentTarget.select()}
        className="mt-2 w-full break-all rounded border border-amber-300 bg-white px-2 py-1 font-mono text-xs text-gray-900"
      />
      <div className="mt-2 flex gap-2">
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
          I&apos;ve delivered it
        </button>
      </div>
    </div>
  );
}

// --- Users ---

function UsersTab({
  authzByName,
  onIssueFor,
}: {
  authzByName: Map<string, PlacementAuthorization>;
  onIssueFor: (u: PlacementUser) => void;
}) {
  const [filter, setFilter] = useState('');
  const users = useQuery({
    queryKey: ['placement', 'users'],
    queryFn: () => api.placement.listUsers(),
    refetchInterval: 60_000,
  });

  // Filtering is client-side: the daemon's username parameter is an exact
  // match, which is the wrong tool for a search box.
  const rows = (users.data?.users ?? []).filter((u) => {
    if (!filter.trim()) return true;
    const needle = filter.trim().toLowerCase();
    return (
      u.username.toLowerCase().includes(needle) ||
      (u.ap_user_id ?? '').toLowerCase().includes(needle) ||
      (u.projects ?? []).some((p) => p.toLowerCase().includes(needle))
    );
  });

  return (
    <div className="space-y-3">
      <input
        type="text"
        value={filter}
        onChange={(e) => setFilter(e.target.value)}
        placeholder="Filter by user, AP account, or project"
        className="w-80 rounded border border-gray-300 px-2 py-1 text-sm"
      />

      {users.isLoading && <p className="text-gray-400">Loading…</p>}
      {users.error && <ErrorNote error={users.error as Error} what="list users" />}
      {users.data && rows.length === 0 && (
        <p className="text-sm text-gray-500">No users match.</p>
      )}

      {rows.length > 0 && (
        <div className="overflow-x-auto rounded-lg border border-gray-200 bg-white">
          <table className="min-w-full text-sm">
            <thead className="bg-gray-50 text-left text-xs uppercase tracking-wide text-gray-500">
              <tr>
                <th className="px-3 py-2">User</th>
                <th className="px-3 py-2">AP account</th>
                <th className="px-3 py-2">Authorizations</th>
                <th className="px-3 py-2">Projects</th>
                <th className="px-3 py-2">Mapping expires</th>
                <th className="px-3 py-2">Token expires</th>
                <th className="px-3 py-2"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {rows.map((u) => (
                <tr
                  key={u.username}
                  className={u.authorized ? 'hover:bg-gray-50' : 'bg-gray-50/40'}
                >
                  <td className="px-3 py-2 font-mono text-xs">
                    {u.username}
                    {!u.authorized && (
                      <span
                        className="ml-2 rounded-full bg-gray-200 px-2 py-0.5 text-[10px] font-medium text-gray-600"
                        title="No longer in the map file. Existing tokens keep working until they expire; no new token can be issued."
                      >
                        unmapped
                      </span>
                    )}
                  </td>
                  <td className="px-3 py-2 font-mono text-xs text-gray-700">
                    {u.ap_user_id || '—'}
                  </td>
                  <td className="px-3 py-2">
                    <ChipList names={u.authorizations} authzByName={authzByName} />
                  </td>
                  <td className="px-3 py-2 text-xs text-gray-700">
                    {u.projects?.join(', ') || '—'}
                  </td>
                  <td className="px-3 py-2 text-xs text-gray-500">
                    {formatExpiry(u.mapping_expiration, 'Never')}
                  </td>
                  <td className="px-3 py-2 text-xs text-gray-500">
                    {formatExpiry(u.token_expiration, 'No live token')}
                  </td>
                  <td className="px-3 py-2 text-right">
                    <button
                      type="button"
                      onClick={() => onIssueFor(u)}
                      disabled={!u.authorized}
                      title={
                        u.authorized
                          ? undefined
                          : 'This identity is no longer in the map file'
                      }
                      className="rounded border border-gray-300 px-2 py-0.5 text-xs font-medium text-gray-700 hover:bg-gray-100 disabled:opacity-40"
                    >
                      Issue token
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

// --- Tokens ---

function TokensTab({
  authzByName,
}: {
  authzByName: Map<string, PlacementAuthorization>;
}) {
  const [validOnly, setValidOnly] = useState(true);
  const [username, setUsername] = useState('');
  const tokens = useQuery({
    queryKey: ['placement', 'tokens', { validOnly, username }],
    queryFn: () =>
      api.placement.listTokens({
        valid_only: validOnly,
        username: username.trim() || undefined,
      }),
    refetchInterval: 60_000,
  });

  const rows: PlacementToken[] = tokens.data?.tokens ?? [];

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-4 text-sm">
        <label className="flex items-center gap-2">
          <input
            type="checkbox"
            checked={validOnly}
            onChange={(e) => setValidOnly(e.target.checked)}
          />
          Unexpired only
        </label>
        <input
          type="text"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          placeholder="Exact username"
          className="w-72 rounded border border-gray-300 px-2 py-1 font-mono text-sm"
        />
      </div>

      {tokens.isLoading && <p className="text-gray-400">Loading…</p>}
      {tokens.error && (
        <ErrorNote error={tokens.error as Error} what="list tokens" />
      )}
      {tokens.data && rows.length === 0 && (
        <p className="text-sm text-gray-500">No tokens match.</p>
      )}

      {rows.length > 0 && (
        <div className="overflow-x-auto rounded-lg border border-gray-200 bg-white">
          <table className="min-w-full text-sm">
            <thead className="bg-gray-50 text-left text-xs uppercase tracking-wide text-gray-500">
              <tr>
                <th className="px-3 py-2">Token ID</th>
                <th className="px-3 py-2">User</th>
                <th className="px-3 py-2">AP account</th>
                <th className="px-3 py-2">Requested by</th>
                <th className="px-3 py-2">Authorizations</th>
                <th className="px-3 py-2">Project</th>
                <th className="px-3 py-2">Expires</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {rows.map((t) => (
                <tr
                  key={t.token_id}
                  className={t.expired ? 'bg-gray-50/40 text-gray-400' : 'hover:bg-gray-50'}
                >
                  <td className="px-3 py-2 font-mono text-xs">{t.token_id}</td>
                  <td className="px-3 py-2 font-mono text-xs">{t.username}</td>
                  <td className="px-3 py-2 font-mono text-xs">
                    {t.ap_user_id || '—'}
                  </td>
                  <td className="px-3 py-2 font-mono text-xs">
                    {t.requester && t.requester !== t.username ? t.requester : '—'}
                  </td>
                  <td className="px-3 py-2">
                    <ChipList names={t.authorizations} authzByName={authzByName} />
                  </td>
                  <td className="px-3 py-2 text-xs">{t.project || '—'}</td>
                  <td className="px-3 py-2 text-xs">
                    {t.expiration
                      ? new Date(t.expiration).toLocaleString()
                      : 'Never'}
                    {t.expired && (
                      <span className="ml-2 rounded-full bg-gray-200 px-2 py-0.5 text-[10px] font-medium text-gray-600">
                        expired
                      </span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

// --- Authorizations ---

function AuthorizationsTab({
  authorizations,
  loading,
  error,
}: {
  authorizations: PlacementAuthorization[];
  loading: boolean;
  error: Error | null;
}) {
  return (
    <div className="space-y-3">
      <p className="text-sm text-gray-500">
        Defined by the placementd&apos;s authorizations map file. The label,
        color, and description below are the operator&apos;s, not ours.
      </p>
      {loading && <p className="text-gray-400">Loading…</p>}
      {error && <ErrorNote error={error} what="list authorizations" />}
      {!loading && !error && authorizations.length === 0 && (
        <p className="text-sm text-gray-500">
          No authorizations are defined. Set PLACEMENTD_AUTHORIZATIONS_MAPFILE to
          give them labels and descriptions.
        </p>
      )}
      {authorizations.length > 0 && (
        <div className="overflow-x-auto rounded-lg border border-gray-200 bg-white">
          <table className="min-w-full text-sm">
            <thead className="bg-gray-50 text-left text-xs uppercase tracking-wide text-gray-500">
              <tr>
                <th className="px-3 py-2">Authorization</th>
                <th className="px-3 py-2">Name</th>
                <th className="px-3 py-2">Description</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {authorizations.map((a) => (
                <tr key={a.name} className="hover:bg-gray-50">
                  <td className="px-3 py-2">
                    <AuthzChip authz={a} />
                  </td>
                  <td className="px-3 py-2 font-mono text-xs text-gray-700">
                    {a.name}
                  </td>
                  <td className="px-3 py-2 text-xs text-gray-600">
                    {a.description || '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

// --- Shared bits ---

// safeColor gates the map file's color string before it reaches an inline
// style. The value is operator-controlled but still external data, and a
// narrow allowlist costs nothing: hex triplets, rgb()/hsl() functions, and
// bare CSS color keywords. Anything else falls back to the neutral chip.
const COLOR_RE = /^(#[0-9a-f]{3,8}|[a-z]+|(rgb|hsl)a?\([0-9.,%\s/]+\))$/i;

function safeColor(color?: string): string | undefined {
  if (!color) return undefined;
  const trimmed = color.trim();
  return COLOR_RE.test(trimmed) ? trimmed : undefined;
}

// AuthzChip renders one authorization the way the map file asks. The color is
// applied to the border and a leading dot rather than to a filled background:
// an arbitrary operator-chosen color has no contrast guarantee behind text, but
// it is perfectly readable as an accent.
function AuthzChip({ authz }: { authz: PlacementAuthorization }) {
  const color = safeColor(authz.color);
  return (
    <span
      className="inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 text-xs font-medium text-gray-800"
      style={{ borderColor: color ?? '#d1d5db' }}
      title={authz.description || authz.name}
    >
      <span
        aria-hidden="true"
        className="h-2 w-2 shrink-0 rounded-full"
        style={{ backgroundColor: color ?? '#9ca3af' }}
      />
      {authz.label || authz.name}
    </span>
  );
}

// ChipList renders a user's or token's authorization names. A name with no
// entry in the map file still gets a chip — dropping it silently would hide a
// live grant from the person auditing it.
function ChipList({
  names,
  authzByName,
}: {
  names?: string[];
  authzByName: Map<string, PlacementAuthorization>;
}) {
  if (!names || names.length === 0) {
    return <span className="text-xs text-gray-400">—</span>;
  }
  return (
    <span className="flex flex-wrap gap-1">
      {names.map((n) => (
        <AuthzChip key={n} authz={authzByName.get(n.toUpperCase()) ?? { name: n }} />
      ))}
    </span>
  );
}

// formatExpiry renders an optional timestamp, distinguishing "never" from
// "already gone" — both matter when auditing who can still log in.
function formatExpiry(value: string | undefined, absent: string): string {
  if (!value) return absent;
  const when = new Date(value);
  const label = when.toLocaleString();
  return when.getTime() < Date.now() ? `${label} (expired)` : label;
}

function ErrorNote({ error, what }: { error: Error; what: string }) {
  const status = error instanceof ApiError ? error.status : undefined;
  return (
    <p className="text-sm text-red-600">
      Failed to {what}
      {status ? ` (${status})` : ''}: {error.message}
    </p>
  );
}
