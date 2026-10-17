'use client';

// Onboard a user in one batch: the account (created if it does not exist,
// its grants updated if changed), then the identity.

import { useMemo, useState } from 'react';
import { useMutation } from '@tanstack/react-query';
import {
  type BatchOperation,
  type DirAccount,
  type DirAuthorization,
  type EditResponse,
  PlacementAdminError,
  describeEditError,
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

export function OnboardWizard({
  accounts,
  authorizations,
  projects,
  onClose,
  onDone,
}: {
  accounts: DirAccount[];
  authorizations: DirAuthorization[];
  projects: string[];
  onClose: () => void;
  onDone: (resp: EditResponse) => void;
}) {
  const [identity, setIdentity] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [account, setAccount] = useState('');
  const [expiresAt, setExpiresAt] = useState<string | null>(null);
  const [authz, setAuthz] = useState<string[]>(
    authorizations.filter((a) => a.requestable).map((a) => a.name),
  );
  const [chosenProjects, setChosenProjects] = useState<string[]>([]);
  const [defaultProject, setDefaultProject] = useState('');
  const [checked, setChecked] = useState<string | null>(null);

  const existing = useMemo(
    () => accounts.find((a) => a.name === account.trim()),
    [accounts, account],
  );
  // Picking an existing account shows its grants.
  const [shownFor, setShownFor] = useState<string | undefined>(undefined);
  if (existing && shownFor !== existing.id) {
    setShownFor(existing.id);
    setAuthz(existing.authorizations);
    setChosenProjects(existing.projects);
    setDefaultProject(existing.default_project ?? '');
  } else if (!existing && shownFor !== undefined) {
    setShownFor(undefined);
  }
  const grantsLocked = existing?.source === 'mapfile';

  const input: OnboardInput = {
    identity: identity.trim(),
    displayName: displayName.trim(),
    account: account.trim(),
    expiresAt,
    authorizations: authz,
    projects: chosenProjects,
    defaultProject,
  };
  const ops = onboardOperations(input, existing);

  const run = useMutation({
    mutationFn: (dryRun: boolean) => placementAdmin.batch(ops, dryRun),
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

  const failed =
    run.error instanceof PlacementAdminError
      ? run.error.results.find((r) => r.error_code)
      : undefined;
  const ready = input.identity !== '' && input.account !== '';

  return (
    <Modal title="Onboard user" onClose={onClose} wide>
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
              className={`${inputClass} font-mono`}
              value={identity}
              onChange={(e) => setIdentity(e.target.value)}
              placeholder="alice@wisc.edu"
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

        {checked && (
          <p role="status" className="rounded-sm border border-emerald-200 bg-emerald-50 p-2 text-xs text-emerald-800">
            {checked}
          </p>
        )}
        {run.error && (
          <p role="alert" className="rounded-sm border border-red-200 bg-red-50 p-2 text-xs text-red-700">
            {failed && `Step ${failed.index + 1}: `}
            {describeEditError(run.error)}
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
            {run.isPending ? 'Working…' : 'Onboard'}
          </button>
        </div>
      </form>
    </Modal>
  );
}
