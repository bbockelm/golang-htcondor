'use client';

// Request access: for somebody signed in with an identity this access point
// does not know. Shows their latest request, or a form to file one.

import { useEffect, useRef, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api, type PlacementMyRequest, type PlacementMyRequestState } from '@/lib/api';

// The server's limits, so the form stops at them.
export const MAX_PROJECTS = 10;
export const MAX_PROJECT_LENGTH = 64;
export const MAX_NOTE_BYTES = 2048;

const QUERY_KEY = ['placement', 'me', 'request'];

function formatDate(iso?: string): string {
  if (!iso) return '';
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString();
}

export function PlacementAccessRequest({ onApproved }: { onApproved?: () => void }) {
  const qc = useQueryClient();
  const state = useQuery({
    queryKey: QUERY_KEY,
    queryFn: api.placement.myRequest,
    retry: false,
    // A pending request is looked at again now and then, so an approval
    // shows up without a reload.
    refetchInterval: (q) => (q.state.data?.request?.status === 'pending' ? 30_000 : false),
  });
  const [again, setAgain] = useState(false);

  const status = state.data?.request?.status;
  const announced = useRef(false);
  useEffect(() => {
    if (status === 'approved' && !announced.current) {
      announced.current = true;
      onApproved?.();
    }
  }, [status, onApproved]);

  const set = (next: PlacementMyRequestState) => {
    qc.setQueryData(QUERY_KEY, next);
    setAgain(false);
  };

  if (state.isLoading) return null;
  if (state.error || !state.data) {
    return (
      <p className="text-sm text-red-600">
        Could not load your access request: {(state.error as Error | null)?.message ?? 'no answer'}
      </p>
    );
  }
  const req = state.data.request;
  if (req && req.status === 'pending') return <PendingRequest req={req} onWithdrawn={set} />;
  if (req && req.status === 'approved') return <ApprovedRequest req={req} />;
  if (req && req.status === 'denied' && !again) {
    return <DeniedRequest req={req} onAgain={() => setAgain(true)} />;
  }
  return <RequestAccessForm state={state.data} withdrawn={req?.status === 'withdrawn'} onFiled={set} />;
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section
      aria-label={title}
      className="space-y-3 rounded-lg border border-gray-200 bg-white p-4 text-sm text-gray-700"
    >
      <h2 className="text-lg font-semibold text-gray-900">{title}</h2>
      {children}
    </section>
  );
}

function RequestSummary({ req }: { req: PlacementMyRequest }) {
  return (
    <dl className="grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1">
      <dt className="font-medium text-gray-600">Requested</dt>
      <dd>{formatDate(req.created_at)}</dd>
      <dt className="font-medium text-gray-600">Projects</dt>
      <dd>{req.projects.length > 0 ? req.projects.join(', ') : 'None named'}</dd>
      {req.note && (
        <>
          <dt className="font-medium text-gray-600">Note</dt>
          <dd className="whitespace-pre-wrap break-words">{req.note}</dd>
        </>
      )}
    </dl>
  );
}

function PendingRequest({
  req,
  onWithdrawn,
}: {
  req: PlacementMyRequest;
  onWithdrawn: (s: PlacementMyRequestState) => void;
}) {
  const withdraw = useMutation({ mutationFn: api.placement.withdrawRequest, onSuccess: onWithdrawn });
  return (
    <Section title="Access requested">
      <p>Your request is waiting for an administrator.</p>
      <RequestSummary req={req} />
      <div className="flex flex-wrap items-center gap-3">
        <button
          type="button"
          onClick={() => withdraw.mutate()}
          disabled={withdraw.isPending}
          className="rounded-sm border border-gray-300 px-3 py-1 text-sm text-gray-700 hover:bg-gray-50 disabled:opacity-50"
        >
          {withdraw.isPending ? 'Withdrawing…' : 'Withdraw request'}
        </button>
        {withdraw.error && <span className="text-red-600">{(withdraw.error as Error).message}</span>}
      </div>
    </Section>
  );
}

function ApprovedRequest({ req }: { req: PlacementMyRequest }) {
  return (
    <Section title="Access approved">
      <p>
        Your request was approved
        {req.account ? (
          <>
            {' '}
            for the account <span className="font-mono">{req.account}</span>
          </>
        ) : null}
        .
      </p>
    </Section>
  );
}

function DeniedRequest({ req, onAgain }: { req: PlacementMyRequest; onAgain: () => void }) {
  return (
    <Section title="Access denied">
      <p>Your request was denied{req.decided_at ? ` on ${formatDate(req.decided_at)}` : ''}.</p>
      {req.reason && (
        <p>
          <span className="font-medium text-gray-600">Reason: </span>
          <span className="whitespace-pre-wrap break-words">{req.reason}</span>
        </p>
      )}
      <button
        type="button"
        onClick={onAgain}
        className="rounded-sm border border-gray-300 px-3 py-1 text-sm text-gray-700 hover:bg-gray-50"
      >
        Request again
      </button>
    </Section>
  );
}

const utf8Length = (s: string) => new TextEncoder().encode(s).length;

function RequestAccessForm({
  state,
  withdrawn,
  onFiled,
}: {
  state: PlacementMyRequestState;
  withdrawn: boolean;
  onFiled: (s: PlacementMyRequestState) => void;
}) {
  const [projects, setProjects] = useState<string[]>([]);
  const [draft, setDraft] = useState('');
  const [note, setNote] = useState('');
  const file = useMutation({
    mutationFn: () => api.placement.requestAccess({ projects: withDraft(), note }),
    onSuccess: onFiled,
  });

  // withDraft is the project list with whatever is still being typed.
  const withDraft = () => addProject(projects, draft);
  const commitDraft = () => {
    setProjects(withDraft());
    setDraft('');
  };
  const full = projects.length >= MAX_PROJECTS;
  const noteBytes = utf8Length(note);
  const noteTooLong = noteBytes > MAX_NOTE_BYTES;

  return (
    <Section title="Request access">
      {withdrawn && <p>You withdrew your last request.</p>}
      <dl className="grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1">
        <dt className="font-medium text-gray-600">Identity</dt>
        <dd className="font-mono">{state.identity}</dd>
        <dt className="font-medium text-gray-600">Name</dt>
        <dd>{state.display_name || '—'}</dd>
        <dt className="font-medium text-gray-600">Email</dt>
        <dd>{state.email || '—'}</dd>
      </dl>
      <form
        className="space-y-3"
        onSubmit={(e) => {
          e.preventDefault();
          commitDraft();
          file.mutate();
        }}
      >
        <div>
          <label htmlFor="access-request-project" className="block font-medium text-gray-800">
            Projects
          </label>
          <p className="text-xs text-gray-500">
            Up to {MAX_PROJECTS}. Press Enter after each.
          </p>
          {projects.length > 0 && (
            <ul aria-label="Requested projects" className="mt-1 flex flex-wrap gap-1.5">
              {projects.map((p) => (
                <li
                  key={p.toLowerCase()}
                  className="inline-flex items-center gap-1 rounded-full bg-gray-100 px-2 py-0.5 text-xs text-gray-800"
                >
                  {p}
                  <button
                    type="button"
                    aria-label={`Remove ${p}`}
                    onClick={() => setProjects(projects.filter((x) => x !== p))}
                    className="text-gray-500 hover:text-gray-900"
                  >
                    ×
                  </button>
                </li>
              ))}
            </ul>
          )}
          <input
            id="access-request-project"
            value={draft}
            maxLength={MAX_PROJECT_LENGTH}
            disabled={full}
            placeholder={full ? `${MAX_PROJECTS} projects named` : ''}
            onChange={(e) => {
              const v = e.target.value;
              // A comma ends a project, as Enter does.
              if (v.includes(',')) {
                let next = projects;
                for (const part of v.split(',').slice(0, -1)) next = addProject(next, part);
                setProjects(next);
                setDraft(v.slice(v.lastIndexOf(',') + 1));
              } else {
                setDraft(v);
              }
            }}
            onKeyDown={(e) => {
              if (e.key === 'Enter') {
                e.preventDefault();
                commitDraft();
              } else if (e.key === 'Backspace' && draft === '' && projects.length > 0) {
                setProjects(projects.slice(0, -1));
              }
            }}
            onBlur={commitDraft}
            className="mt-1 w-full max-w-sm rounded-sm border border-gray-300 px-2 py-1 text-sm disabled:bg-gray-50"
          />
        </div>
        <div>
          <label htmlFor="access-request-note" className="block font-medium text-gray-800">
            Note (optional)
          </label>
          <textarea
            id="access-request-note"
            rows={3}
            value={note}
            onChange={(e) => setNote(e.target.value)}
            className="mt-1 w-full rounded-sm border border-gray-300 px-2 py-1 text-sm"
          />
          {noteTooLong && (
            <p className="text-xs text-red-600">
              The note is {noteBytes} bytes; the limit is {MAX_NOTE_BYTES}.
            </p>
          )}
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <button
            type="submit"
            disabled={file.isPending || noteTooLong}
            className="rounded-sm bg-brand-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-brand-700 disabled:opacity-50"
          >
            {file.isPending ? 'Sending…' : 'Request access'}
          </button>
          {file.error && <span className="text-red-600">{(file.error as Error).message}</span>}
        </div>
      </form>
    </Section>
  );
}

// addProject adds name to list unless it is empty, already there (ignoring
// case), or the list is full.
export function addProject(list: string[], name: string): string[] {
  const p = name.trim().slice(0, MAX_PROJECT_LENGTH);
  if (!p || list.length >= MAX_PROJECTS) return list;
  if (list.some((x) => x.toLowerCase() === p.toLowerCase())) return list;
  return [...list, p];
}
