'use client';

// Confirms a delete or an adopt, with an optional change comment for the
// history. A delete still referenced by other entries offers to delete them
// too.

import { useState } from 'react';
import { useMutation } from '@tanstack/react-query';
import {
  type EditResponse,
  PlacementAdminError,
  type PlacementKind,
  describeEditError,
  placementAdmin,
} from '@/lib/placementAdmin';
import { Field, Modal, inputClass } from './directoryShared';

export type ChangeAction =
  | { kind: 'delete'; entity: PlacementKind; id: string; version: number; label: string }
  | { kind: 'adopt'; entity: PlacementKind; id: string; version: number; label: string }
  | { kind: 'adoptAll' };

const SINGULAR: Record<PlacementKind, string> = {
  identities: 'identity',
  accounts: 'account',
  projects: 'project',
  authorizations: 'authorization',
};

export function ChangeDialog({
  action,
  onClose,
  onDone,
  onReload,
}: {
  action: ChangeAction;
  onClose: () => void;
  onDone: (resp: EditResponse, verb: string) => void;
  onReload: () => void;
}) {
  const [comment, setComment] = useState('');
  const run = useMutation({
    mutationFn: (cascade: boolean) => {
      switch (action.kind) {
        case 'delete':
          return placementAdmin.remove(action.entity, action.id, {
            cascade,
            expectedVersion: action.version,
            changeComment: comment,
          });
        case 'adopt':
          return placementAdmin.adopt(action.entity, action.id, action.version, comment);
        case 'adoptAll':
          return placementAdmin.adoptAll(comment);
      }
    },
    onSuccess: (resp) =>
      onDone(resp, action.kind === 'delete' ? 'Deleted.' : action.kind === 'adopt' ? 'Adopted.' : 'Adopted every map file entry.'),
  });

  const err = run.error;
  const cascadeRequired = err instanceof PlacementAdminError && err.cascadeRequired;
  const conflict = err instanceof PlacementAdminError && err.isVersionConflict;

  const title =
    action.kind === 'delete'
      ? `Delete ${SINGULAR[action.entity]}`
      : action.kind === 'adopt'
        ? `Adopt ${SINGULAR[action.entity]}`
        : 'Adopt every map file entry';
  const confirm = action.kind === 'delete' ? 'Delete' : action.kind === 'adopt' ? 'Adopt' : 'Adopt all';

  return (
    <Modal title={title} onClose={onClose}>
      <form
        className="space-y-3"
        onSubmit={(e) => {
          e.preventDefault();
          run.mutate(false);
        }}
      >
        {action.kind !== 'adoptAll' && <p className="font-mono text-sm text-gray-800">{action.label}</p>}
        <Field label="Change comment (optional)">
          <input className={inputClass} value={comment} onChange={(e) => setComment(e.target.value)} />
        </Field>

        {err && !cascadeRequired && (
          <div role="alert" className="rounded-sm border border-red-200 bg-red-50 p-2 text-xs text-red-700">
            {describeEditError(err)}
            {conflict && (
              <button type="button" onClick={onReload} className="ml-2 font-medium underline">
                Reload
              </button>
            )}
          </div>
        )}
        {cascadeRequired && (
          <div role="alert" className="rounded-sm border border-amber-300 bg-amber-50 p-2 text-xs text-amber-900">
            Other entries still refer to this one.
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
          {cascadeRequired ? (
            <button
              type="button"
              disabled={run.isPending}
              onClick={() => run.mutate(true)}
              className="rounded-sm bg-red-600 px-3 py-1 text-sm font-medium text-white hover:bg-red-700 disabled:opacity-50"
            >
              Delete with references
            </button>
          ) : (
            <button
              type="submit"
              disabled={run.isPending}
              className={`rounded-sm px-3 py-1 text-sm font-medium text-white disabled:opacity-50 ${
                action.kind === 'delete' ? 'bg-red-600 hover:bg-red-700' : 'bg-brand-600 hover:bg-brand-700'
              }`}
            >
              {run.isPending ? 'Working…' : confirm}
            </button>
          )}
        </div>
      </form>
    </Modal>
  );
}
