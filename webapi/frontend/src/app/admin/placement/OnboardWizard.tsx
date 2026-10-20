'use client';

// Onboard a user in one batch: the account (created if it does not exist,
// its grants updated if changed), then the identity. The same form approves
// an access request, pre-filled from it and sent to the approve endpoint.

import { useMemo, useState } from 'react';
import { useMutation } from '@tanstack/react-query';
import {
  type BatchOperation,
  type DirAccount,
  type DirAuthorization,
  type EditResponse,
  describeBatchError,
  placementAdmin,
} from '@/lib/placementAdmin';
import { ExpiryField, GrantFields } from './EntityForm';
import { Field, Modal, inputClass } from './directoryShared';

export interface OnboardInput {
  identity: string;
  displayName: string;
  account: string;
  expiresAt: string | null;
  authorizations: string[];
  projects: string[];
  defaultProject: string;
  // The admin confirmed mapping the identity to an account that exists.
  attachToExisting?: boolean;
}

const sameList = (a: string[], b: string[]) => a.length === b.length && a.every((x, i) => x === b[i]);

// onboardOperations builds the batch for one new user.
export function onboardOperations(input: OnboardInput, existing?: DirAccount): BatchOperation[] {
  const ops: BatchOperation[] = [];
  const grants = {
    authorizations: input.authorizations,
    projects: input.projects,
    default_project: input.defaultProject || null,
  };
  if (!existing) {
    ops.push({
      operation: 'Create',
      target_type: 'Account',
      fields: {
        name: input.account,
        authorizations: input.authorizations,
        projects: input.projects,
        ...(input.defaultProject ? { default_project: input.defaultProject } : {}),
      },
    });
  } else if (
    existing.source !== 'mapfile' &&
    (!sameList(existing.authorizations, input.authorizations) ||
      !sameList(existing.projects, input.projects) ||
      (existing.default_project ?? '') !== input.defaultProject)
  ) {
    ops.push({
      operation: 'Update',
      target_type: 'Account',
      id: existing.id,
      expected_version: existing.version,
      fields: grants,
    });
  }
  const identity: BatchOperation['fields'] = {
    identity: input.identity,
    account: input.account,
  };
  if (input.expiresAt) identity.expires_at = input.expiresAt;
  if (input.displayName) identity.display_name = input.displayName;
  ops.push({ operation: 'Create', target_type: 'Identity', fields: identity });
  return ops;
}

// OnboardSubmit sends the onboarding, or checks it when dryRun is set.
export type OnboardSubmit = (
  input: OnboardInput,
  existing: DirAccount | undefined,
  dryRun: boolean,
  changeComment: string,
) => Promise<EditResponse>;

const submitBatch: OnboardSubmit = (input, existing, dryRun, changeComment) =>
  placementAdmin.batch(onboardOperations(input, existing), dryRun, changeComment);

export function OnboardWizard({
  accounts,
  authorizations,
  projects,
  onClose,
  onDone,
  initial,
  identityLocked = false,
  title = 'Onboard user',
  submitLabel = 'Onboard',
  submit = submitBatch,
  notice,
  errorAction,
  confirmAttach = false,
}: {
  accounts: DirAccount[];
  authorizations: DirAuthorization[];
  projects: string[];
  onClose: () => void;
  onDone: (resp: EditResponse) => void;
  // Starting values, e.g. from an access request.
  initial?: Partial<OnboardInput>;
  // The identity is shown but cannot be changed.
  identityLocked?: boolean;
  title?: string;
  submitLabel?: string;
  submit?: OnboardSubmit;
  // Shown above the grants.
  notice?: React.ReactNode;
  // Shown with an error, for an action that answers it.
  errorAction?: (err: unknown) => React.ReactNode;
  // An existing account is shown with who is on it and what it holds,
  // is not changed, and is used only once the admin confirms.
  confirmAttach?: boolean;
}) {
  const [identity, setIdentity] = useState(initial?.identity ?? '');
  const [displayName, setDisplayName] = useState(initial?.displayName ?? '');
  const [account, setAccount] = useState(initial?.account ?? '');
  const [expiresAt, setExpiresAt] = useState<string | null>(initial?.expiresAt ?? null);
  const [authz, setAuthz] = useState<string[]>(
    initial?.authorizations ?? authorizations.filter((a) => a.requestable).map((a) => a.name),
  );
  const [chosenProjects, setChosenProjects] = useState<string[]>(initial?.projects ?? []);
  const [defaultProject, setDefaultProject] = useState(
    initial?.defaultProject ?? initial?.projects?.[0] ?? '',
  );
  const [checked, setChecked] = useState<string | null>(null);
  const [changeComment, setChangeComment] = useState('');
  const [attach, setAttach] = useState(false);

  const existing = useMemo(
    () => accounts.find((a) => a.name === account.trim()),
    [accounts, account],
  );
  // Picking an existing account shows its grants.
  const [shownFor, setShownFor] = useState<string | undefined>(undefined);
  if (existing && shownFor !== existing.id) {
    setShownFor(existing.id);
    setAttach(false);
    setAuthz(existing.authorizations);
    setChosenProjects(existing.projects);
    setDefaultProject(existing.default_project ?? '');
  } else if (!existing && shownFor !== undefined) {
    setShownFor(undefined);
  }
  const grantsLocked = existing?.source === 'mapfile' || (confirmAttach && !!existing);
  const attachNeeded = confirmAttach && !!existing && !attach;

  const input: OnboardInput = {
    identity: identity.trim(),
    displayName: displayName.trim(),
    account: account.trim(),
    expiresAt,
    authorizations: authz,
    projects: chosenProjects,
    defaultProject,
    ...(confirmAttach ? { attachToExisting: !!existing && attach } : {}),
  };
  const ops = onboardOperations(input, existing);

  const run = useMutation({
    mutationFn: (dryRun: boolean) => submit(input, existing, dryRun, changeComment),
    onSuccess: (resp, dryRun) => {
      if (dryRun) {
        const warnings = resp.results.map((r) => r.warning).filter(Boolean);
        setChecked(warnings.length > 0 ? warnings.join(' ') : 'No problems found.');
      } else {
        onDone(resp);
      }
    },
    onError: () => setChecked(null),
  });

  const ready = input.identity !== '' && input.account !== '' && !attachNeeded;

  return (
    <Modal title={title} onClose={onClose} wide>
      <form
        className="space-y-3"
        onSubmit={(e) => {
          e.preventDefault();
          setChecked(null);
          run.mutate(false);
        }}
      >
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label="Identity">
            <input
              className={`${inputClass} font-mono read-only:bg-gray-50`}
              value={identity}
              onChange={(e) => setIdentity(e.target.value)}
              placeholder="alice@wisc.edu"
              readOnly={identityLocked}
              required
            />
          </Field>
          <Field label="Display name">
            <input className={inputClass} value={displayName} onChange={(e) => setDisplayName(e.target.value)} />
          </Field>
          <Field
            label="Account"
            hint={
              input.account === ''
                ? undefined
                : existing
                  ? grantsLocked
                    ? 'Existing account from the map file; its grants are read-only.'
                    : 'Existing account.'
                  : 'New account.'
            }
          >
            <input
              className={`${inputClass} font-mono`}
              list="onboard-accounts"
              value={account}
              onChange={(e) => setAccount(e.target.value)}
              placeholder="alice@ap.example.edu"
              required
            />
            <datalist id="onboard-accounts">
              {accounts.map((a) => (
                <option key={a.id} value={a.name} />
              ))}
            </datalist>
          </Field>
          <ExpiryField value={expiresAt} onChange={setExpiresAt} />
        </div>

        {confirmAttach && existing && (
          <section
            aria-label="Existing account"
            className="space-y-1 rounded-sm border border-amber-300 bg-amber-50 p-2 text-xs text-amber-900"
          >
            <p>
              The account <span className="font-mono">{existing.name}</span> already exists. Its grants are
              not changed here.
            </p>
            <p>Identities on it:</p>
            {existing.identities.length > 0 ? (
              <ul className="list-disc pl-5 font-mono">
                {existing.identities.map((i) => (
                  <li key={i}>{i}</li>
                ))}
              </ul>
            ) : (
              <p className="pl-5">None.</p>
            )}
            <p>Authorizations: {existing.authorizations.join(', ') || 'none'}</p>
            <p>
              Projects: {existing.projects.join(', ') || 'none'}
              {existing.default_project ? ` (default ${existing.default_project})` : ''}
            </p>
            <label className="flex items-center gap-2 pt-1 font-medium">
              <input type="checkbox" checked={attach} onChange={(e) => setAttach(e.target.checked)} />
              Attach this identity to the existing account
            </label>
          </section>
        )}

        {notice}

        <GrantFields
          authorizations={authorizations}
          projects={projects}
          selectedAuthz={authz}
          selectedProjects={chosenProjects}
          defaultProject={defaultProject}
          onAuthz={setAuthz}
          onProjects={(v) => {
            setChosenProjects(v);
            if (!v.includes(defaultProject)) setDefaultProject(v[0] ?? '');
          }}
          onDefault={setDefaultProject}
          disabled={grantsLocked}
        />

        <ol className="list-decimal space-y-0.5 pl-5 text-xs text-gray-600" aria-label="Changes">
          {ops.map((op, i) => (
            <li key={i}>
              {op.operation} {op.target_type.toLowerCase()}{' '}
              <span className="font-mono">
                {String(op.fields?.identity ?? op.fields?.name ?? input.account)}
              </span>
            </li>
          ))}
        </ol>

        <Field label="Change comment (optional)">
          <input className={inputClass} value={changeComment} onChange={(e) => setChangeComment(e.target.value)} />
        </Field>

        {checked && (
          <p role="status" className="rounded-sm border border-emerald-200 bg-emerald-50 p-2 text-xs text-emerald-800">
            {checked}
          </p>
        )}
        {run.error && (
          <p role="alert" className="rounded-sm border border-red-200 bg-red-50 p-2 text-xs text-red-700">
            {describeBatchError(run.error)}
            {errorAction?.(run.error)}
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
            type="button"
            disabled={!ready || run.isPending}
            onClick={() => {
              setChecked(null);
              run.mutate(true);
            }}
            className="rounded-sm border border-gray-300 px-3 py-1 text-sm text-gray-700 hover:bg-gray-50 disabled:opacity-50"
          >
            Check
          </button>
          <button
            type="submit"
            disabled={!ready || run.isPending}
            className="rounded-sm bg-brand-600 px-3 py-1 text-sm font-medium text-white hover:bg-brand-700 disabled:opacity-50"
          >
            {run.isPending ? 'Working…' : submitLabel}
          </button>
        </div>
      </form>
    </Modal>
  );
}
