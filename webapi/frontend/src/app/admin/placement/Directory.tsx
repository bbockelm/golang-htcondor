'use client';

// Directory: the placementd's identities, accounts, projects and
// authorizations, for a placementd that serves the directory commands.
// Map-file rows are read-only and can be adopted; internal rows are edited
// here.

import { useCallback, useMemo, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  type DirAccount,
  type DirAuthorization,
  type DirEntityByKind,
  type DirIdentity,
  type DirProject,
  type EditResponse,
  PlacementAdminError,
  type PlacementKind,
  describeEditError,
  placementAdmin,
} from '@/lib/placementAdmin';
import { ChipList } from '@/components/ChipList';
import { ConfirmButton } from '@/components/ConfirmButton';
import { FilterControls, type FilterMode } from '@/components/FilterControls';
import {
  ScrollableTable,
  SortableHeader,
  useSortState,
  useSortedRows,
} from '@/components/SortableTable';
import { AuthzChips, SourceBadge, formatWhen } from './directoryShared';
import { EntityForm, KIND_SINGULAR } from './EntityForm';
import { OnboardWizard } from './OnboardWizard';

const VIEWS: { kind: PlacementKind; label: string }[] = [
  { kind: 'identities', label: 'Identities' },
  { kind: 'accounts', label: 'Accounts' },
  { kind: 'projects', label: 'Projects' },
  { kind: 'authorizations', label: 'Authorizations' },
];

type AnyEntity = DirEntityByKind[PlacementKind];

interface Column {
  key: string;
  label: string;
  value: (row: AnyEntity) => string | number | Date | undefined;
  render: (row: AnyEntity) => React.ReactNode;
}

const dateOf = (v?: string) => (v ? new Date(v) : undefined);

function columnsFor(kind: PlacementKind, authzByName: Map<string, DirAuthorization>): Column[] {
  switch (kind) {
    case 'identities':
      return [
        {
          key: 'foreign_id',
          label: 'Foreign ID',
          value: (r) => (r as DirIdentity).foreign_id,
          render: (r) => {
            const i = r as DirIdentity;
            return (
              <span className="font-mono text-xs">
                {i.foreign_id}
                {i.display_name && <span className="ml-2 font-sans text-gray-500">{i.display_name}</span>}
              </span>
            );
          },
        },
        {
          key: 'account',
          label: 'Account',
          value: (r) => (r as DirIdentity).account,
          render: (r) => <span className="font-mono text-xs">{(r as DirIdentity).account || '—'}</span>,
        },
        {
          key: 'authorizations',
          label: 'Authorizations',
          value: (r) => (r as DirIdentity).authorizations.join(','),
          render: (r) => <AuthzChips names={(r as DirIdentity).authorizations} byName={authzByName} />,
        },
        {
          key: 'projects',
          label: 'Projects',
          value: (r) => (r as DirIdentity).projects.join(','),
          render: (r) => <ChipList items={(r as DirIdentity).projects} max={4} />,
        },
        {
          key: 'expires_at',
          label: 'Expires',
          value: (r) => dateOf((r as DirIdentity).expires_at),
          render: (r) => {
            const i = r as DirIdentity;
            return (
              <span className="text-xs text-gray-600">
                {formatWhen(i.expires_at, 'Never')}
                {i.expired && (
                  <span className="ml-2 rounded-full bg-gray-200 px-2 py-0.5 text-[10px] font-medium text-gray-600">
                    expired
                  </span>
                )}
              </span>
            );
          },
        },
        {
          key: 'last_token_expiration',
          label: 'Last token expires',
          value: (r) => dateOf((r as DirIdentity).last_token_expiration),
          render: (r) => (
            <span className="text-xs text-gray-500">{formatWhen((r as DirIdentity).last_token_expiration)}</span>
          ),
        },
      ];
    case 'accounts':
      return [
        {
          key: 'name',
          label: 'Account',
          value: (r) => (r as DirAccount).name,
          render: (r) => <span className="font-mono text-xs">{(r as DirAccount).name}</span>,
        },
        {
          key: 'authorizations',
          label: 'Authorizations',
          value: (r) => (r as DirAccount).authorizations.join(','),
          render: (r) => <AuthzChips names={(r as DirAccount).authorizations} byName={authzByName} />,
        },
        {
          key: 'projects',
          label: 'Projects',
          value: (r) => (r as DirAccount).projects.join(','),
          render: (r) => {
            const a = r as DirAccount;
            // The default project first, marked.
            const ordered = a.default_project
              ? [`${a.default_project} (default)`, ...a.projects.filter((p) => p !== a.default_project)]
              : a.projects;
            return <ChipList items={ordered} max={4} />;
          },
        },
        {
          key: 'identities',
          label: 'Identities',
          value: (r) => (r as DirAccount).identities.length,
          render: (r) => <ChipList items={(r as DirAccount).identities} max={3} tone="blue" />,
        },
      ];
    case 'projects':
      return [
        {
          key: 'name',
          label: 'Project',
          value: (r) => (r as DirProject).name,
          render: (r) => <span className="text-xs font-medium">{(r as DirProject).name}</span>,
        },
        {
          key: 'description',
          label: 'Description',
          value: (r) => (r as DirProject).description,
          render: (r) => <span className="text-xs text-gray-600">{(r as DirProject).description || '—'}</span>,
        },
        {
          key: 'accounts',
          label: 'Accounts',
          value: (r) => (r as DirProject).accounts.length,
          render: (r) => <ChipList items={(r as DirProject).accounts} max={4} />,
        },
      ];
    case 'authorizations':
      return [
        {
          key: 'name',
          label: 'Authorization',
          value: (r) => (r as DirAuthorization).name,
          render: (r) => (
            <AuthzChips names={[(r as DirAuthorization).name]} byName={new Map([[(r as DirAuthorization).name.toUpperCase(), r as DirAuthorization]])} />
          ),
        },
        {
          key: 'raw',
          label: 'Name',
          value: (r) => (r as DirAuthorization).name,
          render: (r) => <span className="font-mono text-xs">{(r as DirAuthorization).name}</span>,
        },
        {
          key: 'description',
          label: 'Description',
          value: (r) => (r as DirAuthorization).description,
          render: (r) => <span className="text-xs text-gray-600">{(r as DirAuthorization).description || '—'}</span>,
        },
        {
          key: 'requestable',
          label: 'Requestable',
          value: (r) => ((r as DirAuthorization).requestable ? 1 : 0),
          render: (r) => <span className="text-xs">{(r as DirAuthorization).requestable ? 'Yes' : 'No'}</span>,
        },
      ];
  }
}

// searchText is what the text filter matches against.
function searchText(kind: PlacementKind, r: AnyEntity): string {
  switch (kind) {
    case 'identities': {
      const i = r as DirIdentity;
      return [i.foreign_id, i.account, i.display_name, i.comment, ...i.projects, ...i.authorizations].join(' ');
    }
    case 'accounts': {
      const a = r as DirAccount;
      return [a.name, ...a.projects, ...a.identities, ...a.authorizations].join(' ');
    }
    case 'projects': {
      const p = r as DirProject;
      return [p.name, p.description, ...p.accounts].join(' ');
    }
    case 'authorizations': {
      const z = r as DirAuthorization;
      return [z.name, z.label, z.description].join(' ');
    }
  }
}

function warningsOf(resp: EditResponse): string[] {
  return resp.results.map((r) => r.warning).filter((w): w is string => !!w);
}

export function Directory({ onIssueToken }: { onIssueToken?: (foreignId: string) => void }) {
  const qc = useQueryClient();
  const [view, setView] = useState<PlacementKind>('identities');
  const [mode, setMode] = useState<FilterMode>('text');
  const [input, setInput] = useState('');
  const [constraint, setConstraint] = useState('');
  const [editing, setEditing] = useState<{ entity: AnyEntity | null } | null>(null);
  const [onboarding, setOnboarding] = useState(false);
  const [notice, setNotice] = useState<{ tone: 'ok' | 'warn' | 'error'; text: string } | null>(null);
  const [cascadeFor, setCascadeFor] = useState<string | null>(null);

  const rows = useQuery({
    queryKey: ['placement', 'directory', view, constraint],
    queryFn: () => placementAdmin.list(view, constraint ? { constraint } : undefined),
  });
  // The pick lists every form needs.
  const authz = useQuery({
    queryKey: ['placement', 'directory', 'authorizations', ''],
    queryFn: () => placementAdmin.list('authorizations'),
  });
  const projects = useQuery({
    queryKey: ['placement', 'directory', 'projects', ''],
    queryFn: () => placementAdmin.list('projects'),
  });
  const accounts = useQuery({
    queryKey: ['placement', 'directory', 'accounts', ''],
    queryFn: () => placementAdmin.list('accounts'),
  });

  const authzList = useMemo(() => (authz.data ?? []) as DirAuthorization[], [authz.data]);
  const authzByName = useMemo(() => {
    const m = new Map<string, DirAuthorization>();
    for (const a of authzList) m.set(a.name.toUpperCase(), a);
    return m;
  }, [authzList]);
  const projectNames = useMemo(() => ((projects.data ?? []) as DirProject[]).map((p) => p.name), [projects.data]);
  const accountList = useMemo(() => (accounts.data ?? []) as DirAccount[], [accounts.data]);

  const refresh = useCallback(() => {
    qc.invalidateQueries({ queryKey: ['placement'] });
  }, [qc]);

  const afterEdit = (verb: string) => (resp: EditResponse) => {
    const warnings = warningsOf(resp);
    setNotice(warnings.length > 0 ? { tone: 'warn', text: warnings.join(' ') } : { tone: 'ok', text: verb });
    setCascadeFor(null);
    refresh();
  };
  const onError = (err: unknown, id?: string) => {
    if (err instanceof PlacementAdminError && err.cascadeRequired && id) {
      setCascadeFor(id);
      setNotice(null);
      return;
    }
    setNotice({ tone: 'error', text: describeEditError(err) });
  };

  const remove = useMutation({
    mutationFn: (v: { id: string; version: number; cascade: boolean }) =>
      placementAdmin.remove(view, v.id, { cascade: v.cascade, expectedVersion: v.version }),
    onSuccess: afterEdit('Deleted.'),
    onError: (err, v) => onError(err, v.id),
  });
  const adopt = useMutation({
    mutationFn: (v: { id: string; version: number }) => placementAdmin.adopt(view, v.id, v.version),
    onSuccess: afterEdit('Adopted.'),
    onError: (err) => onError(err),
  });
  const adoptAll = useMutation({
    mutationFn: () => placementAdmin.adoptAll(),
    onSuccess: afterEdit('Adopted every map file entry.'),
    onError: (err) => onError(err),
  });

  const columns = useMemo(() => columnsFor(view, authzByName), [view, authzByName]);
  const [sort, setSort] = useSortState<string>(columns[0].key, 'asc');
  const activeSort = columns.some((c) => c.key === sort.key) ? sort : { key: columns[0].key, direction: 'asc' as const };
  const valueOf = useCallback(
    (row: AnyEntity, key: string) => {
      if (key === 'source') return row.source;
      return columns.find((c) => c.key === key)?.value(row);
    },
    [columns],
  );

  const filtered = useMemo(() => {
    const all = (rows.data ?? []) as AnyEntity[];
    const needle = mode === 'text' ? input.trim().toLowerCase() : '';
    if (!needle) return all;
    return all.filter((r) => searchText(view, r).toLowerCase().includes(needle));
  }, [rows.data, mode, input, view]);
  const sorted = useSortedRows(filtered, activeSort, valueOf);

  const switchView = (k: PlacementKind) => {
    setView(k);
    setNotice(null);
    setCascadeFor(null);
    setSort({ key: columnsFor(k, authzByName)[0].key, direction: 'asc' });
  };

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div role="tablist" aria-label="Directory" className="inline-flex overflow-hidden rounded-sm border border-gray-300 text-sm">
          {VIEWS.map((v) => (
            <button
              key={v.kind}
              type="button"
              role="tab"
              aria-selected={view === v.kind}
              onClick={() => switchView(v.kind)}
              className={`px-3 py-1.5 ${view === v.kind ? 'bg-brand-600 text-white' : 'bg-white text-gray-600 hover:bg-gray-50'}`}
            >
              {v.label}
            </button>
          ))}
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <ConfirmButton
            label="Adopt all"
            confirmLabel="Adopt every map file entry"
            title="Adopt every map file entry"
            pending={adoptAll.isPending}
            onConfirm={() => adoptAll.mutate()}
          />
          <button
            type="button"
            onClick={() => setOnboarding(true)}
            className="rounded-sm border border-brand-600 px-3 py-1.5 text-sm font-medium text-brand-700 hover:bg-brand-50"
          >
            Onboard user
          </button>
          <button
            type="button"
            onClick={() => setEditing({ entity: null })}
            className="rounded-sm bg-brand-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-brand-700"
          >
            New {KIND_SINGULAR[view]}
          </button>
        </div>
      </div>

      <FilterControls
        mode={mode}
        input={input}
        onMode={(m) => {
          setMode(m);
          if (m === 'text') setConstraint('');
        }}
        onInput={setInput}
        onApplyExpr={() => setConstraint(input.trim())}
        textPlaceholder={`Filter ${VIEWS.find((v) => v.kind === view)?.label.toLowerCase()}`}
        exprPlaceholder='Source == "internal"'
      />

      {notice && (
        <div
          role={notice.tone === 'error' ? 'alert' : 'status'}
          className={`rounded-sm border p-2 text-sm ${
            notice.tone === 'error'
              ? 'border-red-200 bg-red-50 text-red-700'
              : notice.tone === 'warn'
                ? 'border-amber-200 bg-amber-50 text-amber-800'
                : 'border-emerald-200 bg-emerald-50 text-emerald-800'
          }`}
        >
          {notice.text}
          {notice.tone === 'error' && notice.text.startsWith('This entry changed') && (
            <button type="button" onClick={refresh} className="ml-2 font-medium underline">
              Reload
            </button>
          )}
        </div>
      )}

      {rows.isLoading && <p className="text-gray-400">Loading…</p>}
      {rows.error && (
        <p className="text-sm text-red-600">
          Failed to list {view}: {(rows.error as Error).message}
        </p>
      )}
      {rows.data && sorted.length === 0 && <p className="text-sm text-gray-500">Nothing matches.</p>}

      {sorted.length > 0 && (
        <ScrollableTable>
          <table className="min-w-full text-sm">
            <thead className="bg-gray-50 text-left text-xs text-gray-500">
              <tr>
                {columns.map((c) => (
                  <SortableHeader key={c.key} label={c.label} sortKey={c.key} sort={activeSort} onSort={setSort} />
                ))}
                <SortableHeader label="Source" sortKey="source" sort={activeSort} onSort={setSort} />
                <th className="px-3 py-2">
                  <span className="sr-only">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {sorted.map((row) => {
                const mapfile = row.source === 'mapfile';
                return (
                  <tr key={row.id} className="align-top hover:bg-gray-50" data-testid={`dir-row-${row.id}`}>
                    {columns.map((c) => (
                      <td key={c.key} className="px-3 py-2">
                        {c.render(row)}
                      </td>
                    ))}
                    <td className="px-3 py-2">
                      <SourceBadge source={row.source} />
                    </td>
                    <td className="whitespace-nowrap px-3 py-2 text-right">
                      <div className="inline-flex items-center gap-1">
                        {view === 'identities' && onIssueToken && (
                          <button
                            type="button"
                            onClick={() => onIssueToken((row as DirIdentity).foreign_id)}
                            className="rounded-sm border border-gray-300 px-2 py-0.5 text-xs text-gray-700 hover:bg-gray-100"
                          >
                            Issue token
                          </button>
                        )}
                        {mapfile ? (
                          <button
                            type="button"
                            disabled={adopt.isPending}
                            onClick={() => adopt.mutate({ id: row.id, version: row.version })}
                            className="rounded-sm border border-amber-400 px-2 py-0.5 text-xs font-medium text-amber-800 hover:bg-amber-50 disabled:opacity-50"
                          >
                            Adopt
                          </button>
                        ) : (
                          <>
                            <button
                              type="button"
                              onClick={() => setEditing({ entity: row })}
                              className="rounded-sm border border-gray-300 px-2 py-0.5 text-xs text-gray-700 hover:bg-gray-100"
                            >
                              Edit
                            </button>
                            {cascadeFor === row.id ? (
                              <span className="inline-flex items-center gap-1">
                                <span className="text-xs text-red-700">Still referenced.</span>
                                <ConfirmButton
                                  compact
                                  label="Delete with references"
                                  confirmLabel="Delete all"
                                  pending={remove.isPending}
                                  onConfirm={() => remove.mutate({ id: row.id, version: row.version, cascade: true })}
                                />
                              </span>
                            ) : (
                              <ConfirmButton
                                compact
                                label="Delete"
                                confirmLabel="Delete"
                                pending={remove.isPending}
                                onConfirm={() => remove.mutate({ id: row.id, version: row.version, cascade: false })}
                              />
                            )}
                          </>
                        )}
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </ScrollableTable>
      )}

      {editing && (
        <EntityForm
          kind={view}
          entity={editing.entity}
          authorizations={authzList}
          projects={projectNames}
          accounts={accountList.map((a) => a.name)}
          onClose={() => setEditing(null)}
          onSaved={(resp) => {
            setEditing(null);
            afterEdit(editing.entity ? 'Saved.' : 'Created.')(resp);
          }}
          onReload={() => {
            setEditing(null);
            refresh();
          }}
        />
      )}

      {onboarding && (
        <OnboardWizard
          accounts={accountList}
          authorizations={authzList}
          projects={projectNames}
          onClose={() => setOnboarding(false)}
          onDone={(resp) => {
            setOnboarding(false);
            afterEdit('User onboarded.')(resp);
          }}
        />
      )}
    </div>
  );
}
