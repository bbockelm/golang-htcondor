'use client';

// The placement token request form, shared by /placement (the token comes
// back to this page) and /placement/device (it goes to a device request).

import { useState } from 'react';
import { useMutation, useQuery } from '@tanstack/react-query';
import {
  ApiError,
  api,
  type PlacementAuthorization,
  type PlacementIssued,
  type PlacementMe,
} from '@/lib/api';

// Map-file colors pdwebapp understood; anything else renders plain.
const LABEL_CLASS: Record<string, string> = {
  warning: 'text-amber-700',
  danger: 'text-red-700',
};
const CHECKBOX_CLASS: Record<string, string> = {
  warning: 'accent-amber-600',
  danger: 'accent-red-600',
};

export function placementTokenFileName(): string {
  return 'Placement.token';
}

export function PlacementTokenRequest({
  userCode,
  onIssued,
}: {
  // When set, the token is bound to this device request.
  userCode?: string;
  onIssued: (issued: PlacementIssued) => void;
}) {
  const me = useQuery({
    queryKey: ['placement', 'me'],
    queryFn: api.placement.me,
    retry: false,
  });

  if (me.isLoading) return <p className="text-gray-400">Loading…</p>;
  if (me.error) {
    const err = me.error as Error;
    const status = err instanceof ApiError ? err.status : undefined;
    return (
      <p className="text-sm text-red-600">
        {status === 503
          ? 'Placement tokens are not available on this access point.'
          : `Could not load your placement identity: ${err.message}`}
      </p>
    );
  }
  if (!me.data) return null;
  return <RequestForm me={me.data} userCode={userCode} onIssued={onIssued} />;
}

function RequestForm({
  me,
  userCode,
  onIssued,
}: {
  me: PlacementMe;
  userCode?: string;
  onIssued: (issued: PlacementIssued) => void;
}) {
  const enabledProjects = me.projects.filter((p) => p.enabled);
  const defaultProject =
    enabledProjects.find((p) => p.default)?.name ?? enabledProjects[0]?.name ?? '';
  const [project, setProject] = useState(defaultProject);
  const [selected, setSelected] = useState<Set<string>>(
    () => new Set(me.authorizations.map((a) => a.name)),
  );

  // A refetch that drops the chosen project falls back to the default
  // rather than submitting a stale choice.
  const chosen = enabledProjects.some((p) => p.name === project) ? project : defaultProject;

  const request = useMutation({
    mutationFn: () =>
      api.placement.requestToken({
        project: chosen,
        authorizations: Array.from(selected),
        ...(userCode ? { user_code: userCode } : {}),
      }),
    onSuccess: onIssued,
  });

  if (!me.foreign_id) {
    return (
      <Notice>
        Your sign-in did not include an identity that the placement service recognizes.
      </Notice>
    );
  }
  if (me.expired) {
    return (
      <Notice>
        Access for <span className="font-mono">{me.foreign_id}</span> has expired on this
        access point.
      </Notice>
    );
  }
  if (!me.authorized) {
    return (
      <Notice>
        <span className="font-mono">{me.foreign_id}</span> is not authorized to use this
        access point.
      </Notice>
    );
  }
  if (me.authorizations.length === 0) {
    return <Notice>You do not have any permissions on this access point.</Notice>;
  }
  if (me.projects.length === 0) {
    return <Notice>You are not in any projects on this access point.</Notice>;
  }

  return (
    <form
      className="space-y-4 rounded-lg border border-gray-200 bg-white p-4"
      onSubmit={(e) => {
        e.preventDefault();
        request.mutate();
      }}
    >
      <label className="block text-sm">
        <span className="block font-medium text-gray-800">Project</span>
        <select
          value={chosen}
          onChange={(e) => setProject(e.target.value)}
          className="mt-1 w-full max-w-sm rounded-sm border border-gray-300 px-2 py-1 text-sm"
        >
          {me.projects.map((p) => (
            <option key={p.name} value={p.name} disabled={!p.enabled}>
              {p.name}
              {p.enabled ? '' : ' (disabled)'}
            </option>
          ))}
        </select>
      </label>

      <fieldset className="text-sm">
        <legend className="font-medium text-gray-800">Permissions</legend>
        <div className="mt-1 space-y-1.5">
          {me.authorizations.map((a) => (
            <AuthorizationCheckbox
              key={a.name}
              authz={a}
              checked={selected.has(a.name)}
              onToggle={() =>
                setSelected((prev) => {
                  const next = new Set(prev);
                  if (next.has(a.name)) next.delete(a.name);
                  else next.add(a.name);
                  return next;
                })
              }
            />
          ))}
        </div>
      </fieldset>

      {!me.account_enabled && (
        <div role="alert" className="rounded-sm border border-amber-300 bg-amber-50 px-3 py-2 text-sm text-amber-900">
          Your account is not currently allowed to place jobs.
        </div>
      )}

      <div className="flex flex-wrap items-center gap-3">
        <button
          type="submit"
          disabled={request.isPending || !chosen || selected.size === 0}
          className="rounded-sm bg-brand-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-brand-700 disabled:opacity-50"
        >
          {request.isPending ? 'Requesting…' : 'Request token'}
        </button>
        {request.error && (
          <span className="text-sm text-red-600">{(request.error as Error).message}</span>
        )}
      </div>
    </form>
  );
}

function AuthorizationCheckbox({
  authz,
  checked,
  onToggle,
}: {
  authz: PlacementAuthorization;
  checked: boolean;
  onToggle: () => void;
}) {
  const style = (authz.color ?? '').toLowerCase();
  return (
    <label className="flex items-start gap-2">
      <input
        type="checkbox"
        checked={checked}
        onChange={onToggle}
        className={`mt-0.5 ${CHECKBOX_CLASS[style] ?? ''}`}
      />
      <span className={LABEL_CLASS[style] ?? 'text-gray-800'}>
        {authz.label || authz.name}
        {authz.description ? `: ${authz.description}` : ''}
      </span>
    </label>
  );
}

function Notice({ children }: { children: React.ReactNode }) {
  return (
    <div className="rounded-lg border border-gray-200 bg-white p-4 text-sm text-gray-700">
      {children}
    </div>
  );
}

// IssuedTokenDetails is pdwebapp's "Token Granted" table.
export function IssuedTokenDetails({
  issued,
  name,
}: {
  issued: PlacementIssued;
  name: string;
}) {
  const [apUser, apHost] = splitAPUserID(issued.ap_user_id);
  const rows: [string, React.ReactNode][] = [
    ['Name', name],
    ['AP identifier', apUser || '—'],
    ['AP host', apHost || '—'],
    ['Issued', formatTime(issued.issued_at, 'Unknown')],
    ['Expires', formatTime(issued.expires_at, 'Never')],
    ['Project', issued.project],
    ['Permissions', issued.authorizations.join(', ')],
  ];
  return (
    <dl className="grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1 text-sm">
      {rows.map(([k, v]) => (
        <div key={k} className="contents">
          <dt className="font-medium text-gray-600">{k}</dt>
          <dd className="break-all text-gray-900">{v}</dd>
        </div>
      ))}
    </dl>
  );
}

// UserConfigSnippet shows the ~/.condor/user_config lines with a copy button.
export function UserConfigSnippet({ text }: { text?: string }) {
  const [copied, setCopied] = useState<'idle' | 'ok' | 'failed'>('idle');
  if (!text) return null;
  return (
    <div className="space-y-2 text-sm">
      <p className="text-gray-700">
        To use the token, add these lines to <code>~/.condor/user_config</code>, creating it if
        necessary:
      </p>
      <pre className="inline-block rounded-sm border border-gray-200 bg-gray-50 px-3 py-2 font-mono text-xs">
        {text}
      </pre>
      <div>
        <button
          type="button"
          onClick={async () => {
            try {
              await navigator.clipboard.writeText(text);
              setCopied('ok');
            } catch {
              setCopied('failed');
            }
          }}
          className="rounded-sm border border-gray-300 px-2 py-1 text-xs font-medium text-gray-700 hover:bg-gray-100"
        >
          {copied === 'ok' ? 'Copied' : copied === 'failed' ? 'Copy failed' : 'Copy lines'}
        </button>
      </div>
    </div>
  );
}

// splitAPUserID splits "user@host" at the first @, as pdwebapp did.
export function splitAPUserID(id?: string): [string, string] {
  if (!id) return ['', ''];
  const at = id.indexOf('@');
  return at < 0 ? [id, ''] : [id.slice(0, at), id.slice(at + 1)];
}

function formatTime(value: string | undefined, absent: string): string {
  if (!value) return absent;
  return new Date(value).toLocaleString();
}
