'use client';

// Requests: access requests from people who signed in with an identity the
// placementd does not map. Approve opens the Onboard user form, pre-filled
// from the request; Deny takes a reason, which the requester sees.

import { useMemo, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  type AccessRequest,
  type AccessRequestStatus,
  type DirAccount,
  type DirAuthorization,
  type DirProject,
  type EditResponse,
  PlacementAdminError,
  placementAdmin,
} from '@/lib/placementAdmin';
import { ChipList } from '@/components/ChipList';
import { ScrollableTable } from '@/components/SortableTable';
import { OnboardWizard, type OnboardInput } from './OnboardWizard';
import { Field, Modal, formatWhen, inputClass } from './directoryShared';

type Filter = AccessRequestStatus | 'all';

const FILTERS: { value: Filter; label: string }[] = [
  { value: 'pending', label: 'Pending' },
  { value: 'approved', label: 'Approved' },
  { value: 'denied', label: 'Denied' },
  { value: 'withdrawn', label: 'Withdrawn' },
  { value: 'all', label: 'All' },
];

// The authorizations an approval starts with, when the directory has them.
const DEFAULT_AUTHORIZATIONS = ['READ', 'WRITE'];

const STATUS_CLASS: Record<AccessRequestStatus, string> = {
  pending: 'bg-amber-100 text-amber-800',
  approving: 'bg-sky-100 text-sky-800',
  approved: 'bg-emerald-100 text-emerald-800',
  denied: 'bg-red-100 text-red-800',
  withdrawn: 'bg-gray-200 text-gray-700',
};

// approvalStart is the Onboard user form's starting values for req: its
// identity and name, the suggested account, the requested projects that
// are in the directory (in the directory's spelling), and READ and WRITE.
// unknownProjects are the requested ones the directory does not have.
export function approvalStart(
  req: AccessRequest,
  directoryProjects: string[],
  authorizations: DirAuthorization[],
): { initial: OnboardInput; unknownProjects: string[] } {
  const byLower = new Map(directoryProjects.map((p) => [p.toLowerCase(), p]));
  const projects: string[] = [];
  const unknownProjects: string[] = [];
  for (const p of req.projects) {
    const found = byLower.get(p.toLowerCase());
    if (found) {
      if (!projects.includes(found)) projects.push(found);
    } else {
      unknownProjects.push(p);
    }
  }
  const authz = DEFAULT_AUTHORIZATIONS.flatMap((want) => {
    const a = authorizations.find((x) => x.name.toUpperCase() === want);
    return a ? [a.name] : [];
  });
  return {
    initial: {
      identity: req.identity,
      displayName: req.display_name ?? '',
      account: req.suggested_account ?? '',
      expiresAt: null,
      authorizations: authz,
      projects,
      defaultProject: projects[0] ?? '',
    },
    unknownProjects,
  };
}

export function Requests() {
  const qc = useQueryClient();
  const [filter, setFilter] = useState<Filter>('pending');
  const [approving, setApproving] = useState<AccessRequest | null>(null);
  const [denying, setDenying] = useState<AccessRequest | null>(null);
  const [notice, setNotice] = useState<{ tone: 'ok' | 'error'; text: string } | null>(null);

  const requests = useQuery({
    queryKey: ['placement', 'requests', filter],
    queryFn: () => placementAdmin.requests(filter),
  });
  const canApprove = requests.data?.can_approve === true;

  // The directory's pick lists, for the approval form.
  const authz = useQuery({
    queryKey: ['placement', 'directory', 'authorizations', ''],
    queryFn: () => placementAdmin.list('authorizations'),
    enabled: canApprove,
  });
  const projects = useQuery({
    queryKey: ['placement', 'directory', 'projects', ''],
    queryFn: () => placementAdmin.list('projects'),
    enabled: canApprove,
  });
  const accounts = useQuery({
    queryKey: ['placement', 'directory', 'accounts', ''],
    queryFn: () => placementAdmin.list('accounts'),
    enabled: canApprove,
  });
  const authzList = useMemo(() => (authz.data ?? []) as DirAuthorization[], [authz.data]);
  const projectNames = useMemo(() => ((projects.data ?? []) as DirProject[]).map((p) => p.name), [projects.data]);
  const accountList = useMemo(() => (accounts.data ?? []) as DirAccount[], [accounts.data]);
  const formReady = authz.isSuccess && projects.isSuccess && accounts.isSuccess;

  const done = (text: string) => {
    setNotice({ tone: 'ok', text });
    setApproving(null);
    setDenying(null);
    void qc.invalidateQueries({ queryKey: ['placement'] });
  };

  const resolve = useMutation({
    mutationFn: (id: number) => placementAdmin.resolveRequest(id),
    onSuccess: () => done('Request marked resolved.'),
    onError: (err) => {
      setApproving(null);
      setNotice({ tone: 'error', text: (err as Error).message });
    },
  });

  const rows = requests.data?.requests ?? [];

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div role="tablist" aria-label="Request status" className="inline-flex overflow-hidden rounded-sm border border-gray-300 text-sm">
          {FILTERS.map((f) => (
            <button
              key={f.value}
              type="button"
              role="tab"
              aria-selected={filter === f.value}
              onClick={() => {
                setFilter(f.value);
                setNotice(null);
              }}
              className={`px-3 py-1.5 ${filter === f.value ? 'bg-brand-600 text-white' : 'bg-white text-gray-600 hover:bg-gray-50'}`}
            >
              {f.label}
            </button>
          ))}
        </div>
      </div>

      {requests.data && !canApprove && (
        <p className="rounded-sm border border-gray-200 bg-gray-50 p-2 text-sm text-gray-600">
          This placementd does not support directory management, so requests are read-only here.
        </p>
      )}

      {notice && (
        <div
          role={notice.tone === 'error' ? 'alert' : 'status'}
          className={`rounded-sm border p-2 text-sm ${
            notice.tone === 'error'
              ? 'border-red-200 bg-red-50 text-red-700'
              : 'border-emerald-200 bg-emerald-50 text-emerald-800'
          }`}
        >
          {notice.text}
        </div>
      )}

      {requests.isLoading && <p className="text-gray-400">Loading…</p>}
      {requests.error && (
        <p className="text-sm text-red-600">Failed to list requests: {(requests.error as Error).message}</p>
      )}
      {requests.data && rows.length === 0 && (
        <p className="text-sm text-gray-500">
          {filter === 'pending' ? 'No pending requests.' : 'No requests.'}
        </p>
      )}

      {rows.length > 0 && (
        <ScrollableTable>
          <table className="min-w-full text-sm">
            <thead className="bg-gray-50 text-left text-xs text-gray-500">
              <tr>
                <th className="px-3 py-2 font-medium">Identity</th>
                <th className="px-3 py-2 font-medium">Email</th>
                <th className="px-3 py-2 font-medium">Projects</th>
                <th className="px-3 py-2 font-medium">Note</th>
                <th className="px-3 py-2 font-medium">Requested</th>
                <th className="px-3 py-2 font-medium">Status</th>
                <th className="px-3 py-2">
                  <span className="sr-only">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {rows.map((r) => (
                <tr key={r.id} className="align-top hover:bg-gray-50" data-testid={`request-row-${r.id}`}>
                  <td className="px-3 py-2">
                    <span className="font-mono text-xs">{r.identity}</span>
                    {r.display_name && <span className="block text-xs text-gray-500">{r.display_name}</span>}
                  </td>
                  <td className="px-3 py-2 text-xs text-gray-700">{r.email || '—'}</td>
                  <td className="px-3 py-2">
                    {r.projects.length > 0 ? <ChipList items={r.projects} max={4} /> : <span className="text-xs text-gray-400">—</span>}
                  </td>
                  <td className="max-w-xs px-3 py-2 text-xs text-gray-700">
                    <span className="whitespace-pre-wrap break-words">{r.note || '—'}</span>
                  </td>
                  <td className="whitespace-nowrap px-3 py-2 text-xs text-gray-600">{formatWhen(r.created_at)}</td>
                  <td className="px-3 py-2 text-xs">
                    <span className={`rounded-full px-2 py-0.5 font-medium ${STATUS_CLASS[r.status] ?? ''}`}>{r.status}</span>
                    {r.decided_by && (
                      <span className="mt-1 block text-gray-500">
                        by {r.decided_by}, {formatWhen(r.decided_at)}
                      </span>
                    )}
                    {r.account && (
                      <span className="block text-gray-500">
                        as <span className="font-mono">{r.account}</span>
                      </span>
                    )}
                    {r.decision_note && (
                      <span className="block whitespace-pre-wrap break-words text-gray-500">{r.decision_note}</span>
                    )}
                  </td>
                  <td className="whitespace-nowrap px-3 py-2 text-right">
                    {r.status === 'pending' && canApprove && (
                      <div className="inline-flex items-center gap-1">
                        <button
                          type="button"
                          disabled={!formReady}
                          onClick={() => {
                            setNotice(null);
                            setApproving(r);
                          }}
                          className="rounded-sm bg-brand-600 px-2 py-0.5 text-xs font-medium text-white hover:bg-brand-700 disabled:opacity-50"
                        >
                          Approve
                        </button>
                        <button
                          type="button"
                          onClick={() => {
                            setNotice(null);
                            setDenying(r);
                          }}
                          className="rounded-sm border border-gray-300 px-2 py-0.5 text-xs text-gray-700 hover:bg-red-50 hover:text-red-700"
                        >
                          Deny
                        </button>
                      </div>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </ScrollableTable>
      )}

      {approving && (
        <ApproveForm
          req={approving}
          accounts={accountList}
          authorizations={authzList}
          projects={projectNames}
          onClose={() => setApproving(null)}
          onDone={() => done('Request approved.')}
          onResolve={() => resolve.mutate(approving.id)}
          resolving={resolve.isPending}
        />
      )}
      {denying && <DenyForm req={denying} onClose={() => setDenying(null)} onDone={() => done('Request denied.')} />}
    </div>
  );
}

function ApproveForm({
  req,
  accounts,
  authorizations,
  projects,
  onClose,
  onDone,
  onResolve,
  resolving,
}: {
  req: AccessRequest;
  accounts: DirAccount[];
  authorizations: DirAuthorization[];
  projects: string[];
  onClose: () => void;
  onDone: (resp: EditResponse) => void;
  onResolve: () => void;
  resolving: boolean;
}) {
  const { initial, unknownProjects } = approvalStart(req, projects, authorizations);
  return (
    <OnboardWizard
      title="Approve access request"
      submitLabel="Approve"
      accounts={accounts}
      authorizations={authorizations}
      projects={projects}
      initial={initial}
      identityLocked
      confirmAttach
      onClose={onClose}
      onDone={onDone}
      submit={(input, _existing, dryRun, comment) =>
        placementAdmin.approveRequest(
          req.id,
          {
            account: input.account,
            authorizations: input.authorizations,
            projects: input.projects,
            default_project: input.defaultProject,
            expires_at: input.expiresAt,
            display_name: input.displayName,
            comment,
            attach_to_existing: input.attachToExisting ?? false,
          },
          dryRun,
        )
      }
      notice={
        (req.note || unknownProjects.length > 0) && (
          <div className="space-y-1 rounded-sm border border-gray-200 bg-gray-50 p-2 text-xs text-gray-700">
            {req.note && (
              <p>
                <span className="font-medium">Note: </span>
                <span className="whitespace-pre-wrap break-words">{req.note}</span>
              </p>
            )}
            {unknownProjects.length > 0 && (
              <p>
                <span className="font-medium">Requested, not in the directory: </span>
                {unknownProjects.join(', ')}
              </p>
            )}
          </div>
        )
      }
      errorAction={(err) =>
        err instanceof PlacementAdminError && err.identityExists ? (
          <span className="mt-1 block">
            If this person already has the access they asked for,{' '}
            <button type="button" onClick={onResolve} disabled={resolving} className="font-medium underline disabled:opacity-50">
              mark the request resolved
            </button>
            .
          </span>
        ) : null
      }
    />
  );
}

function DenyForm({ req, onClose, onDone }: { req: AccessRequest; onClose: () => void; onDone: () => void }) {
  const [reason, setReason] = useState('');
  const deny = useMutation({ mutationFn: () => placementAdmin.denyRequest(req.id, reason.trim()), onSuccess: onDone });
  return (
    <Modal title="Deny access request" onClose={onClose}>
      <form
        className="space-y-3"
        onSubmit={(e) => {
          e.preventDefault();
          deny.mutate();
        }}
      >
        <p className="text-sm text-gray-700">
          <span className="font-mono">{req.identity}</span>
          {req.display_name && <span className="text-gray-500"> ({req.display_name})</span>}
        </p>
        <Field label="Reason (shown to the requester)">
          <textarea
            className={inputClass}
            rows={3}
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            maxLength={2048}
            required
          />
        </Field>
        {deny.error && (
          <p role="alert" className="rounded-sm border border-red-200 bg-red-50 p-2 text-xs text-red-700">
            {(deny.error as Error).message}
          </p>
        )}
        <div className="flex justify-end gap-2 pt-2">
          <button
            type="button"
            onClick={onClose}
            className="rounded-sm border border-gray-300 px-3 py-1 text-sm text-gray-700 hover:bg-gray-50"
          >
            Cancel
          </button>
          <button
            type="submit"
            disabled={deny.isPending || reason.trim() === ''}
            className="rounded-sm bg-red-600 px-3 py-1 text-sm font-medium text-white hover:bg-red-700 disabled:opacity-50"
          >
            {deny.isPending ? 'Working…' : 'Deny'}
          </button>
        </div>
      </form>
    </Modal>
  );
}
