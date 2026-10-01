'use client';

// /ssh/approve is where an `ssh you@gateway` login is approved.
//
// The device verification endpoint redirects here when the pending
// device code was started by the SSH gateway and names a workspace.
// The generic OAuth2 consent page still handles everything else; see
// httpserver/handlers_ssh_consent.go.
//
// Two shapes, decided by whether the user already has a workspace of
// that name:
//
//   exists      approve the login, and say what the workspace is doing
//   not yet     the interactive page's own resource form, and one
//               button that creates the workspace AND approves the
//               login
//
// The second is the reason this page exists. A user who has never
// started a session is otherwise offered a bare "allow this device",
// gets a workspace sized by whatever the operator defaulted to, and
// finds out it was the wrong size only after waiting for it to start.

import { useEffect, useMemo, useState } from 'react';
import { useSearchParams } from 'next/navigation';
import { useMutation, useQuery } from '@tanstack/react-query';
import {
  api,
  ApiError,
  type SSHConsentResult,
  type SSHConsentView,
} from '@/lib/api';
import {
  ResourceRequestPanel,
  DEFAULT_RESOURCE_REQUEST,
  resourceRequestToApi,
  type ResourceRequest,
} from '@/components/ResourceRequest';
import { SubmitLinesField } from '@/components/SubmitLinesField';

export default function SSHApprovePage() {
  const params = useSearchParams();
  const userCode = (params.get('user_code') ?? '').trim();

  if (!userCode) {
    return (
      <Card>
        <h1 className="text-xl font-bold text-gray-900">Approve an SSH login</h1>
        <p className="mt-2 text-sm text-gray-600">
          This page needs the code shown in your terminal. Follow the link
          printed there, or reconnect to get a new one.
        </p>
      </Card>
    );
  }
  return <Approve userCode={userCode} />;
}

function Approve({ userCode }: { userCode: string }) {
  // One fetch, never refetched. The server charges a rate-limit
  // attempt per call and hands back a single-purpose approval token;
  // a background refetch would spend the budget of somebody who only
  // left the tab open.
  const { data, isLoading, error } = useQuery({
    queryKey: ['ssh-consent', userCode],
    queryFn: () => api.sshConsent.read(userCode),
    refetchOnWindowFocus: false,
    refetchInterval: false,
    retry: false,
  });

  const [result, setResult] = useState<SSHConsentResult | null>(null);

  if (isLoading) {
    return (
      <Card>
        <p className="text-sm text-gray-400">Looking up that code…</p>
      </Card>
    );
  }
  if (error || !data) {
    return (
      <Card>
        <h1 className="text-xl font-bold text-gray-900">Approve an SSH login</h1>
        <p className="mt-2 text-sm text-red-600">
          {error instanceof ApiError ? error.message : String(error)}
        </p>
      </Card>
    );
  }
  if (result) {
    return <Outcome result={result} />;
  }
  return <ConsentForm view={data} onDone={setResult} />;
}

function ConsentForm({
  view,
  onDone,
}: {
  view: SSHConsentView;
  onDone: (r: SSHConsentResult) => void;
}) {
  // Opens on what this access point would submit by itself, so the
  // numbers on screen are the ones about to be used rather than a
  // house default the server will silently replace.
  const initial = useMemo<ResourceRequest>(
    () => ({
      ...DEFAULT_RESOURCE_REQUEST,
      cpus: view.defaults.cpus ?? DEFAULT_RESOURCE_REQUEST.cpus,
      memoryMB: view.defaults.memory_mb ?? DEFAULT_RESOURCE_REQUEST.memoryMB,
      diskMB: view.defaults.disk_mb ?? DEFAULT_RESOURCE_REQUEST.diskMB,
    }),
    [view.defaults],
  );
  const [resources, setResources] = useState<ResourceRequest>(initial);
  const [submitLines, setSubmitLines] = useState('');
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  // Offer the form only when there is something to create AND this
  // server can create it. A session that already exists is attached
  // to, not resized, so showing the fields would promise something
  // approving cannot deliver.
  const configuring = !view.session_exists && view.can_create;

  const decide = useMutation({
    mutationFn: (action: 'approve' | 'deny') =>
      api.sshConsent.decide({
        user_code: view.user_code,
        action,
        approval_token: view.approval_token,
        create:
          action === 'approve' && configuring
            ? {
                ...resourceRequestToApi(resources),
                submit_lines: submitLines.trim() || undefined,
              }
            : undefined,
      }),
    onMutate: () => setErrorMsg(null),
    onSuccess: onDone,
    onError: (err) =>
      setErrorMsg(err instanceof ApiError ? err.message : String(err)),
  });

  return (
    <Card>
      <h1 className="text-xl font-bold text-gray-900">
        Approve an SSH login
      </h1>

      {/* The code, first and largest. It is the only check a phished
          user has: a login they did not start shows a code that
          matches nothing in front of them. */}
      <div className="mt-4 rounded-sm border border-gray-200 bg-gray-50 p-4">
        <div className="text-xs uppercase tracking-wide text-gray-500">
          Code shown in your terminal
        </div>
        <div className="mt-1 font-mono text-2xl font-bold tracking-widest text-brand-700">
          {view.user_code}
        </div>
        <p className="mt-2 text-xs text-gray-600">
          Only continue if this matches the code printed by the{' '}
          <code className="font-mono">ssh</code> command you just ran. If it
          does not, refuse.
        </p>
      </div>

      <dl className="mt-4 grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm">
        <dt className="text-gray-500">Signing in as</dt>
        <dd className="font-medium text-gray-900">{view.username}</dd>
        <dt className="text-gray-500">Workspace</dt>
        <dd className="font-mono text-gray-900">{view.session}</dd>
        <dt className="text-gray-500">Grants</dt>
        <dd className="font-mono text-xs text-gray-700">
          {view.scopes.join(' ')}
        </dd>
      </dl>

      {view.session_exists && (
        <p className="mt-4 rounded-sm border border-gray-200 bg-white p-3 text-sm text-gray-700">
          You already have a workspace called{' '}
          <code className="font-mono">{view.session}</code>
          {view.job_id && <> (job {view.job_id})</>}
          {view.status && <>, {view.status.toLowerCase()}</>}. Approving
          attaches your terminal to it; nothing new is submitted.
          {view.hold_reason && (
            <span className="mt-2 block text-amber-700">
              It is held: {view.hold_reason}
            </span>
          )}
        </p>
      )}

      {!view.session_exists && !view.can_create && (
        <p className="mt-4 rounded-sm border border-amber-200 bg-amber-50 p-3 text-sm text-amber-800">
          This access point does not run interactive workspaces, so
          approving signs you in but there will be nothing to attach to.
        </p>
      )}

      {configuring && (
        <div className="mt-4 space-y-4 rounded-sm border border-gray-200 bg-white p-4">
          <div>
            <div className="text-sm font-medium text-gray-700">
              You have no workspace called{' '}
              <code className="font-mono">{view.session}</code> yet
            </div>
            <p className="mt-1 text-xs text-gray-500">
              Approving submits one as a job in your name, with these
              resources. It keeps running until you remove it.
            </p>
          </div>
          <ResourceRequestPanel value={resources} onChange={setResources} />
          <SubmitLinesField value={submitLines} onChange={setSubmitLines} />
        </div>
      )}

      {errorMsg && (
        <p className="mt-4 rounded-sm border border-red-200 bg-red-50 p-3 text-sm text-red-700">
          {errorMsg}
        </p>
      )}

      <div className="mt-5 flex items-center gap-3">
        <button
          type="button"
          onClick={() => decide.mutate('approve')}
          disabled={decide.isPending}
          className="rounded-sm bg-brand-600 px-4 py-2 text-sm font-medium text-white hover:bg-brand-700 disabled:opacity-60"
        >
          {decide.isPending
            ? 'Working…'
            : configuring
              ? 'Create workspace and sign in'
              : 'Approve sign-in'}
        </button>
        <button
          type="button"
          onClick={() => decide.mutate('deny')}
          disabled={decide.isPending}
          className="rounded-sm border border-gray-300 px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50 disabled:opacity-60"
        >
          Refuse
        </button>
      </div>
    </Card>
  );
}

function Outcome({ result }: { result: SSHConsentResult }) {
  // Close the loop in the terminal's own terms. The person is about to
  // switch back to it, and what they need to know is whether to expect
  // a prompt or a queue wait.
  useEffect(() => {
    document.title = result.approved
      ? 'Signed in — HTCondor'
      : 'Refused — HTCondor';
  }, [result.approved]);

  if (!result.approved) {
    return (
      <Card>
        <h1 className="text-xl font-bold text-gray-900">Login refused</h1>
        <p className="mt-2 text-sm text-gray-600">
          Nothing was signed in and nothing was submitted. You can close this
          tab.
        </p>
      </Card>
    );
  }
  return (
    <Card>
      <h1 className="text-xl font-bold text-gray-900">Signed in</h1>
      <p className="mt-2 text-sm text-gray-600">
        {result.created ? (
          <>
            Workspace <code className="font-mono">{result.session}</code> was
            submitted
            {result.job_id && <> as job {result.job_id}</>}. Your terminal
            will attach to it once it starts, which takes as long as the
            queue does.
          </>
        ) : (
          <>Return to your terminal; it should connect in a moment.</>
        )}
      </p>
      <p className="mt-2 text-sm text-gray-500">You can close this tab.</p>
    </Card>
  );
}

function Card({ children }: { children: React.ReactNode }) {
  return (
    <div className="mx-auto max-w-2xl rounded-sm border border-gray-200 bg-white p-6 shadow-sm">
      {children}
    </div>
  );
}
