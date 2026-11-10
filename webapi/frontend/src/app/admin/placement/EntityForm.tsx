'use client';

// Create and edit forms for the four directory entities. An edit sends only
// the fields that changed, with the version the form was loaded at.

import { useState } from 'react';
import { useMutation } from '@tanstack/react-query';
import {
  type DirAccount,
  type DirAuthorization,
  type DirEntityByKind,
  type DirIdentity,
  type DirProject,
  type EditResponse,
  type EntityFields,
  PlacementAdminError,
  type PlacementKind,
  describeEditError,
  placementAdmin,
} from '@/lib/placementAdmin';
import {
  AuthzChip,
  CheckboxList,
  Field,
  Modal,
  fromLocalInput,
  inputClass,
  toLocalInput,
} from './directoryShared';

export const KIND_SINGULAR: Record<PlacementKind, string> = {
  identities: 'identity',
  accounts: 'account',
  projects: 'project',
  authorizations: 'authorization',
};

type FormValues = Record<string, string | boolean | string[] | null>;

// initialValues is the form's starting point: the entity's current values,
// or blanks for a create.
function initialValues(kind: PlacementKind, e: DirEntityByKind[PlacementKind] | null): FormValues {
  switch (kind) {
    case 'identities': {
      const i = e as DirIdentity | null;
      return {
        identity: i?.identity ?? '',
        account: i?.account ?? '',
        expires_at: i?.expires_at ?? null,
        display_name: i?.display_name ?? '',
        comment: i?.comment ?? '',
      };
    }
    case 'accounts': {
      const a = e as DirAccount | null;
      return {
        name: a?.name ?? '',
        authorizations: a?.authorizations ?? [],
        projects: a?.projects ?? [],
        default_project: a?.default_project ?? '',
      };
    }
    case 'projects': {
      const p = e as DirProject | null;
      return { name: p?.name ?? '', description: p?.description ?? '' };
    }
    case 'authorizations': {
      const z = e as DirAuthorization | null;
      return {
        name: z?.name ?? '',
        label: z?.label ?? '',
        color: z?.color ?? '',
        description: z?.description ?? '',
        requestable: z?.requestable ?? true,
      };
    }
  }
}

// Fields an empty string clears rather than sets.
const OPTIONAL = new Set(['display_name', 'comment', 'description', 'default_project', 'color']);

function same(a: FormValues[string], b: FormValues[string]): boolean {
  if (Array.isArray(a) && Array.isArray(b)) {
    return a.length === b.length && a.every((x, i) => x === b[i]);
  }
  return a === b;
}

// changedFields is the patch: what differs from the start, with cleared
// optional fields as null.
export function changedFields(start: FormValues, now: FormValues, create: boolean): EntityFields {
  const out: EntityFields = {};
  for (const [k, v] of Object.entries(now)) {
    if (!create && same(start[k], v)) continue;
    if (v === '' && OPTIONAL.has(k)) {
      if (!create) out[k] = null;
      continue;
    }
    if (v === null) {
      if (!create) out[k] = null;
      continue;
    }
    out[k] = v;
  }
  return out;
}

export function EntityForm<K extends PlacementKind>({
  kind,
  entity,
  authorizations,
  projects,
  accounts,
  onClose,
  onSaved,
  onReload,
}: {
  kind: K;
  // null creates.
  entity: DirEntityByKind[K] | null;
  authorizations: DirAuthorization[];
  projects: string[];
  accounts: string[];
  onClose: () => void;
  onSaved: (resp: EditResponse) => void;
  onReload: () => void;
}) {
  const create = entity === null;
  const [start] = useState(() => initialValues(kind, entity));
  const [values, setValues] = useState<FormValues>(start);
  const set = (k: string, v: FormValues[string]) => setValues((prev) => ({ ...prev, [k]: v }));

  const [changeComment, setChangeComment] = useState('');
  const save = useMutation({
    mutationFn: () => {
      const fields = changedFields(start, values, create);
      return entity === null
        ? placementAdmin.create(kind, fields, { changeComment })
        : placementAdmin.update(kind, entity.id, entity.version, fields, changeComment);
    },
    onSuccess: onSaved,
  });

  const conflict = save.error instanceof PlacementAdminError && save.error.isVersionConflict;
  const nothingChanged = !create && Object.keys(changedFields(start, values, false)).length === 0;
  const title = `${create ? 'New' : 'Edit'} ${KIND_SINGULAR[kind]}`;
  const str = (k: string) => (values[k] as string) ?? '';
  const list = (k: string) => (values[k] as string[]) ?? [];

  return (
    <Modal title={title} onClose={onClose} wide={kind === 'accounts'}>
      <form
        className="space-y-3"
        onSubmit={(e) => {
          e.preventDefault();
          save.mutate();
        }}
      >
        {kind === 'identities' && (
          <>
            <Field label="Identity">
              <input
                className={`${inputClass} font-mono`}
                value={str('identity')}
                onChange={(e) => set('identity', e.target.value)}
                placeholder="alice@wisc.edu"
                required
              />
            </Field>
            <Field label="Account">
              <input
                className={`${inputClass} font-mono`}
                list="placement-accounts"
                value={str('account')}
                onChange={(e) => set('account', e.target.value)}
                placeholder="alice@ap.example.edu"
                required
              />
              <datalist id="placement-accounts">
                {accounts.map((a) => (
                  <option key={a} value={a} />
                ))}
              </datalist>
            </Field>
            <ExpiryField value={values.expires_at as string | null} onChange={(v) => set('expires_at', v)} />
            <Field label="Display name">
              <input className={inputClass} value={str('display_name')} onChange={(e) => set('display_name', e.target.value)} />
            </Field>
            <Field label="Comment">
              <input className={inputClass} value={str('comment')} onChange={(e) => set('comment', e.target.value)} />
            </Field>
          </>
        )}

        {kind === 'accounts' && (
          <>
            <Field label="Account name">
              <input
                className={`${inputClass} font-mono`}
                value={str('name')}
                onChange={(e) => set('name', e.target.value)}
                placeholder="alice@ap.example.edu"
                required
              />
            </Field>
            <GrantFields
              authorizations={authorizations}
              projects={projects}
              selectedAuthz={list('authorizations')}
              selectedProjects={list('projects')}
              defaultProject={str('default_project')}
              onAuthz={(v) => set('authorizations', v)}
              onProjects={(v) => {
                set('projects', v);
                if (!v.includes(str('default_project'))) set('default_project', v[0] ?? '');
              }}
              onDefault={(v) => set('default_project', v)}
            />
          </>
        )}

        {kind === 'projects' && (
          <>
            <Field label="Project name">
              <input className={inputClass} value={str('name')} onChange={(e) => set('name', e.target.value)} required />
            </Field>
            <Field label="Description">
              <input className={inputClass} value={str('description')} onChange={(e) => set('description', e.target.value)} />
            </Field>
          </>
        )}

        {kind === 'authorizations' && (
          <>
            <div className="grid gap-3 sm:grid-cols-2">
              <Field label="Name">
                <input
                  className={`${inputClass} font-mono`}
                  value={str('name')}
                  onChange={(e) => set('name', e.target.value)}
                  placeholder="WRITE"
                  required
                />
              </Field>
              <Field label="Label">
                <input className={inputClass} value={str('label')} onChange={(e) => set('label', e.target.value)} required />
              </Field>
              <Field label="Color">
                <input className={inputClass} value={str('color')} onChange={(e) => set('color', e.target.value)} placeholder="#2563eb" />
              </Field>
              <div className="flex items-end gap-2 pb-1 text-xs">
                <span className="text-gray-500">Preview</span>
                <AuthzChip authz={{ name: str('name') || 'NAME', label: str('label'), color: str('color') }} />
              </div>
            </div>
            <Field label="Description">
              <input className={inputClass} value={str('description')} onChange={(e) => set('description', e.target.value)} />
            </Field>
            <label className="flex items-center gap-2 text-xs text-gray-700">
              <input
                type="checkbox"
                checked={values.requestable === true}
                onChange={(e) => set('requestable', e.target.checked)}
                className="rounded-sm border-gray-300"
              />
              Offered as a choice when requesting a token
            </label>
          </>
        )}

        <Field label="Change comment (optional)">
          <input className={inputClass} value={changeComment} onChange={(e) => setChangeComment(e.target.value)} />
        </Field>

        {save.error && (
          <div role="alert" className="rounded-sm border border-red-200 bg-red-50 p-2 text-xs text-red-700">
            {describeEditError(save.error)}
            {conflict && (
              <button type="button" onClick={onReload} className="ml-2 font-medium underline">
                Reload
              </button>
            )}
          </div>
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
            disabled={save.isPending || nothingChanged}
            className="rounded-sm bg-brand-600 px-3 py-1 text-sm font-medium text-white hover:bg-brand-700 disabled:opacity-50"
          >
            {save.isPending ? 'Saving…' : create ? 'Create' : 'Save'}
          </button>
        </div>
      </form>
    </Modal>
  );
}

export function ExpiryField({
  value,
  onChange,
}: {
  value: string | null;
  onChange: (v: string | null) => void;
}) {
  const never = value === null;
  return (
    <Field label="Expires">
      <div className="mt-1 flex items-center gap-3">
        <label className="flex items-center gap-1.5 text-xs text-gray-700">
          <input
            type="checkbox"
            checked={never}
            onChange={(e) => {
              if (e.target.checked) {
                onChange(null);
              } else {
                const d = new Date();
                d.setFullYear(d.getFullYear() + 1);
                onChange(d.toISOString().replace(/\.\d{3}Z$/, 'Z'));
              }
            }}
            className="rounded-sm border-gray-300"
          />
          Never
        </label>
        {!never && (
          <input
            type="datetime-local"
            aria-label="Expiry date"
            className={`${inputClass} mt-0 w-auto`}
            value={toLocalInput(value ?? undefined)}
            onChange={(e) => onChange(fromLocalInput(e.target.value))}
          />
        )}
      </div>
    </Field>
  );
}

export function GrantFields({
  authorizations,
  projects,
  selectedAuthz,
  selectedProjects,
  defaultProject,
  onAuthz,
  onProjects,
  onDefault,
  disabled,
}: {
  authorizations: DirAuthorization[];
  projects: string[];
  selectedAuthz: string[];
  selectedProjects: string[];
  defaultProject: string;
  onAuthz: (v: string[]) => void;
  onProjects: (v: string[]) => void;
  onDefault: (v: string) => void;
  disabled?: boolean;
}) {
  const byName = new Map(authorizations.map((a) => [a.name, a]));
  // Keep grants the lists do not know about, so an edit never drops one
  // silently.
  const authzOptions = [...authorizations.map((a) => a.name), ...selectedAuthz.filter((n) => !byName.has(n))];
  const projectOptions = [...projects, ...selectedProjects.filter((p) => !projects.includes(p))];
  return (
    <>
      <div className="text-xs">
        <span className="block text-gray-700">Authorizations</span>
        <CheckboxList
          options={authzOptions}
          selected={selectedAuthz}
          onChange={onAuthz}
          disabled={disabled}
          render={(n) => <AuthzChip authz={byName.get(n) ?? { name: n }} />}
          empty="No authorizations are defined."
        />
      </div>
      <div className="text-xs">
        <span className="block text-gray-700">Projects</span>
        <CheckboxList
          options={projectOptions}
          selected={selectedProjects}
          onChange={onProjects}
          disabled={disabled}
          empty="No projects are defined."
        />
      </div>
      <Field label="Default project">
        <select
          className={inputClass}
          value={defaultProject}
          onChange={(e) => onDefault(e.target.value)}
          disabled={disabled || selectedProjects.length === 0}
        >
          <option value="">None</option>
          {selectedProjects.map((p) => (
            <option key={p} value={p}>
              {p}
            </option>
          ))}
        </select>
      </Field>
    </>
  );
}
