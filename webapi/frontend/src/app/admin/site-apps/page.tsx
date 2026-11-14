'use client';

// Site apps, for the administrator.
//
// Two questions, and they are different questions. "What is published
// right now, and to whom?" is the library's live answer. "What was
// published in October?" is the audit trail, which exists because the
// configuration only ever describes now and a bundle replaced in place
// leaves nothing behind.
//
// A row opens onto both, plus the app's settings. Those settings are
// the configuration's and are named as the configuration names them --
// HTTP_API_SITE_APP_<ID>_GROUPS, not a word invented for this page --
// because the administrator reading them has to be able to put the
// same string into condor_config_val or a configuration file. The
// server builds those names: the mapping from an id is not the
// identity (a hyphen becomes an underscore) and a second
// implementation of that rule here would be a second thing to get
// wrong.
//
// Publishing from here is deliberately not always available. An
// uploaded app is served same-origin to the groups it names and can do
// anything its visitor can, so the site turns it on with
// HTTP_API_SITE_APPS_UPLOAD; without it this page reads, and says where
// to put a bundle instead. An app the configuration publishes is never
// editable here whatever that setting says -- the configuration is the
// authority, and the server refuses both an upload and a settings
// change for such an id rather than letting either look like it
// worked.

import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  api,
  type AdminSiteApp,
  type AdminSiteApps,
  type AdminSiteAppConfig,
  type AdminSiteAppSetting,
} from '@/lib/api';
import { ConfirmButton } from '@/components/ConfirmButton';
import {
  EVERYONE,
  latestRelease,
  nearestSiteAppID,
  parseGroupList,
  releaseDiffers,
  validateSiteAppID,
} from '@/lib/siteapps';

const TH = 'px-3 py-2';
const TD = 'px-3 py-2 align-top';
const INPUT =
  'mt-1 w-full rounded-sm border border-gray-300 px-2 py-1 text-sm focus:border-brand-400 focus:outline-hidden focus:ring-1 focus:ring-brand-400';
const BTN =
  'rounded-sm border border-gray-300 bg-white px-2 py-0.5 text-xs text-gray-700 hover:bg-gray-50 disabled:opacity-50';

function formatBytes(n?: number): string {
  if (!n) return '';
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(0)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

function formatWhen(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString();
}

// shortDigest is the first twelve characters, which is enough to
// compare two by eye and short enough to sit in a table.
function shortDigest(d?: string): string {
  return d ? d.slice(0, 12) : '';
}

function Code({ children }: { children: React.ReactNode }) {
  return (
    <code className="rounded-sm bg-gray-100 px-1 py-0.5 font-mono text-xs text-gray-800">
      {children}
    </code>
  );
}


function AppHistory({ id }: { id: string }) {
  const q = useQuery({
    queryKey: ['admin', 'site-apps', id, 'history'],
    queryFn: () => api.admin.siteAppHistory(id),
  });

  if (q.isLoading) return <p className="text-sm text-gray-400">Loading history…</p>;
  if (q.isError) {
    return (
      <p className="text-sm text-red-600" data-testid="history-error">
        {(q.error as Error).message}
      </p>
    );
  }
  const rows = q.data?.history ?? [];
  if (rows.length === 0) {
    return (
      <p className="text-sm text-gray-500" data-testid="history-empty">
        Nothing recorded yet. A period appears here once a scan has seen this app.
      </p>
    );
  }
  return (
    <div className="overflow-x-auto rounded-lg border border-gray-200 bg-white">
      <table className="min-w-full text-sm" data-testid="history-table">
        <thead className="bg-gray-50 text-left text-xs uppercase tracking-wide text-gray-500">
          <tr>
            <th className={TH}>Served</th>
            <th className={TH}>Build</th>
            <th className={TH}>Digest</th>
            <th className={TH}>Visible to</th>
            <th className={TH}>Published by</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-gray-100">
          {rows.map((h, i) => (
            <tr key={`${h.digest}-${h.first_seen}-${i}`}>
              <td className={`${TD} whitespace-nowrap text-gray-700`}>
                {formatWhen(h.first_seen)} – {formatWhen(h.last_seen)}
              </td>
              <td className={TD}>
                {h.version || <span className="text-gray-400">unversioned</span>}
                {h.revision ? ` (${h.revision})` : ''}
                {h.size_bytes ? (
                  <span className="text-gray-500"> · {formatBytes(h.size_bytes)}</span>
                ) : null}
              </td>
              <td className={TD}>
                <Code>{shortDigest(h.digest)}</Code>
                {h.attested ? (
                  <span
                    className="ml-2 inline-flex rounded-full bg-emerald-100 px-2 py-0.5 text-xs font-medium text-emerald-800"
                    title="A .sha256 accompanied the bundle and matched"
                  >
                    checksummed
                  </span>
                ) : null}
              </td>
              <td className={TD}>{h.groups.join(', ')}</td>
              <td className={`${TD} text-gray-500`}>{h.origin}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// settingValue is what an editor starts from: what is set, not what is
// merely in force. An empty NAME and a NAME that happens to equal the
// bundle's label look the same once merged, and only one of them is a
// parameter the administrator has to maintain.
function draftFrom(settings: AdminSiteAppSetting[]): Record<string, string> {
  const d: Record<string, string> = {};
  for (const s of settings) {
    if (s.editable) d[s.key] = s.value;
  }
  return d;
}

function SettingValue({ s }: { s: AdminSiteAppSetting }) {
  return (
    <>
      {s.value ? (
        <span className="font-mono text-xs text-gray-800">{s.value}</span>
      ) : (
        <span className="text-xs text-gray-400">not set</span>
      )}
      {s.effective ? (
        <div className="mt-0.5 text-xs text-gray-500">
          <span className="font-mono">{s.effective}</span> in force
          {s.effective_from === 'bundle' ? ', from the bundle’s app.yaml' : ' by default'}
        </div>
      ) : null}
    </>
  );
}

// AppConfig is the app's settings, as the configuration's key-value
// pairs.
//
// What it will not do is imply that a change took effect when it did
// not. An app the configuration publishes is read-only here, and says
// so naming condor_reconfig; an app this server stores can be changed,
// and that change is in force by the time the listing in the response
// is drawn, because the server rescans before answering.
function AppConfig({ id }: { id: string }) {
  const qc = useQueryClient();
  const [draft, setDraft] = useState<Record<string, string> | null>(null);

  const q = useQuery({
    queryKey: ['admin', 'site-apps', id, 'config'],
    queryFn: () => api.admin.siteAppConfig(id),
  });

  const save = useMutation({
    mutationFn: (settings: Record<string, string>) => api.admin.setSiteAppConfig(id, settings),
    onSuccess: (d) => {
      qc.setQueryData(['admin', 'site-apps'], d);
      qc.invalidateQueries({ queryKey: ['admin', 'site-apps', id, 'config'] });
      setDraft(null);
    },
  });

  if (q.isLoading) return <p className="text-sm text-gray-400">Loading settings…</p>;
  if (q.isError) {
    return (
      <p className="text-sm text-red-600" data-testid="config-error">
        {(q.error as Error).message}
      </p>
    );
  }
  const cfg: AdminSiteAppConfig | undefined = q.data;
  if (!cfg) return null;
  const groupsKey = cfg.settings.find((s) => s.setting === 'GROUPS')?.key ?? '';
  const editing = draft !== null;

  const groupsDraft = editing ? draft[groupsKey] ?? '' : '';
  const groupsError =
    editing && groupsKey in draft && parseGroupList(groupsDraft).length === 0
      ? `${groupsKey} names no groups. Name the groups that may see this app, or ${EVERYONE} for every authenticated user; withdraw it to stop serving it.`
      : null;

  return (
    <div className="space-y-2">
      <div className="flex items-start justify-between gap-3">
        <div>
          <h3 className="text-sm font-semibold text-gray-900">Settings</h3>
          <p className="text-xs text-gray-500">
            The configuration parameters for this app, named as the configuration names them.
          </p>
        </div>
        {cfg.editable ? (
          editing ? (
            <div className="flex shrink-0 gap-2">
              <button
                type="button"
                className={BTN}
                data-testid="config-cancel"
                onClick={() => setDraft(null)}
                disabled={save.isPending}
              >
                Cancel
              </button>
              <button
                type="button"
                className="rounded-sm bg-brand-600 px-2 py-0.5 text-xs font-medium text-white hover:bg-brand-700 disabled:opacity-50"
                data-testid="config-save"
                disabled={save.isPending || groupsError !== null}
                onClick={() => save.mutate(draft)}
              >
                {save.isPending ? 'Saving…' : 'Save'}
              </button>
            </div>
          ) : (
            <button
              type="button"
              className={`${BTN} shrink-0`}
              data-testid="config-edit"
              onClick={() => setDraft(draftFrom(cfg.settings))}
            >
              Edit
            </button>
          )
        ) : null}
      </div>

      {cfg.stored_here ? (
        <p className="text-xs text-gray-600" data-testid="config-note">
          {cfg.editable ? (
            <>
              These are kept by this access point, because <Code>{id}</Code> was published from
              this page. Saving applies them at once — no <Code>condor_reconfig</Code>. A{' '}
              <Code>{groupsKey}</Code> in the configuration would take precedence over everything
              here.
            </>
          ) : (
            <>
              These are kept by this access point, because <Code>{id}</Code> was published from
              this page. They cannot be changed here while{' '}
              <Code>HTTP_API_SITE_APPS_UPLOAD</Code> is off.
            </>
          )}
        </p>
      ) : (
        <p className="text-xs text-gray-600" data-testid="config-readonly">
          <Code>{id}</Code> is published by this access point’s configuration, which takes
          precedence over anything this page could store. Change these in the configuration and
          run <Code>condor_reconfig</Code>; the values below are the ones this server read at
          startup or at the last reconfigure.
        </p>
      )}

      <div className="overflow-x-auto rounded-lg border border-gray-200 bg-white">
        <table className="min-w-full text-sm" data-testid="config-table">
          <thead className="bg-gray-50 text-left text-xs uppercase tracking-wide text-gray-500">
            <tr>
              <th className={TH}>Parameter</th>
              <th className={TH}>Value</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-100">
            {cfg.settings.map((s) => (
              <tr key={s.key} data-testid={`config-${s.setting.toLowerCase()}`}>
                <td className={`${TD} whitespace-nowrap`}>
                  <span className="font-mono text-xs text-gray-700">{s.key}</span>
                </td>
                <td className={TD}>
                  {editing && s.editable ? (
                    s.setting === 'HOME' ? (
                      <select
                        className={INPUT}
                        data-testid={`config-input-${s.setting.toLowerCase()}`}
                        value={draft[s.key] ?? ''}
                        onChange={(e) => setDraft({ ...draft, [s.key]: e.target.value })}
                      >
                        <option value="false">false</option>
                        <option value="true">true</option>
                      </select>
                    ) : (
                      <input
                        className={INPUT}
                        data-testid={`config-input-${s.setting.toLowerCase()}`}
                        value={draft[s.key] ?? ''}
                        onChange={(e) => setDraft({ ...draft, [s.key]: e.target.value })}
                      />
                    )
                  ) : (
                    <SettingValue s={s} />
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {groupsError ? (
        <p className="text-sm text-red-600" data-testid="config-groups-error">
          {groupsError}
        </p>
      ) : null}
      {save.isError ? (
        <p className="text-sm text-red-600" data-testid="config-save-error">
          {(save.error as Error).message}
        </p>
      ) : null}
    </div>
  );
}

// GroupsField is who may see the app: a checkbox for everyone signed
// in, or named groups as pills.
//
// A raw comma-separated string hid its own mistakes -- a trailing
// comma, a doubled entry, a stray "*" that quietly published to the
// whole access point. A pill is a group the form has already accepted,
// and the "*" is a checkbox because it is a different decision rather
// than another group name.
function GroupsField({
  everyone,
  groups,
  pending,
  error,
  onEveryone,
  onGroups,
  onPending,
}: {
  everyone: boolean;
  groups: string[];
  pending: string;
  error: string | null;
  onEveryone: (v: boolean) => void;
  onGroups: (g: string[]) => void;
  onPending: (v: string) => void;
}) {
  const [note, setNote] = useState<string | null>(null);

  function commit(raw: string) {
    const next = [...groups];
    for (const g of parseGroupList(raw)) {
      if (g === EVERYONE) {
        setNote('“*” is every authenticated user — tick the box above instead.');
        continue;
      }
      if (next.some((h) => h.toLowerCase() === g.toLowerCase())) {
        // Group names are compared case-insensitively by the server,
        // so smith_lab and Smith_Lab are one group, not two.
        continue;
      }
      next.push(g);
      setNote(null);
    }
    onGroups(next);
    onPending('');
  }

  return (
    <div className="text-sm text-gray-700">
      <span className="block">Visible to</span>
      <label className="mt-1 flex items-center gap-2">
        <input
          type="checkbox"
          className="rounded-sm border-gray-300"
          data-testid="upload-everyone"
          checked={everyone}
          onChange={(e) => onEveryone(e.target.checked)}
        />
        Everyone signed in to this access point
      </label>
      {everyone ? (
        <p className="mt-1 text-xs text-gray-500">
          Sent as <Code>{EVERYONE}</Code>, which is what the configuration writes for it.
        </p>
      ) : (
        <>
          {groups.length > 0 ? (
            <div className="mt-2 flex flex-wrap gap-1">
              {groups.map((g) => (
                <span
                  key={g}
                  className="inline-flex items-center gap-1 rounded-full bg-gray-100 px-2 py-0.5 text-xs text-gray-800"
                  data-testid={`group-pill-${g}`}
                >
                  {g}
                  <button
                    type="button"
                    className="text-gray-500 hover:text-gray-900"
                    aria-label={`Remove ${g}`}
                    data-testid={`group-remove-${g}`}
                    onClick={() => onGroups(groups.filter((h) => h !== g))}
                  >
                    ×
                  </button>
                </span>
              ))}
            </div>
          ) : null}
          <input
            className={INPUT}
            placeholder="smith_lab — press Enter to add"
            data-testid="upload-groups"
            value={pending}
            onChange={(e) => {
              const v = e.target.value;
              // A comma is how the configuration separates them, so
              // typing one finishes the group rather than becoming
              // part of its name.
              if (v.includes(',')) commit(v);
              else onPending(v);
            }}
            onKeyDown={(e) => {
              if (e.key === 'Enter') {
                e.preventDefault();
                commit(pending);
              }
            }}
            onBlur={() => {
              if (pending.trim() !== '') commit(pending);
            }}
          />
          {note ? (
            <p className="mt-1 text-xs text-amber-700" data-testid="upload-groups-note">
              {note}
            </p>
          ) : null}
        </>
      )}
      {error ? (
        <p className="mt-1 text-sm text-red-600" data-testid="upload-groups-error">
          {error}
        </p>
      ) : null}
    </div>
  );
}

// published is what to say after an upload: which version is now
// being served and when it was published. Re-publishing an app that is
// already in the table changes nothing else visible about the row, so
// without this the administrator has no way to tell from the page that
// anything happened.
type Published = { id: string; version?: string; at?: string };

function UploadForm({
  apps,
  githubAllowed,
  onDone,
}: {
  apps: AdminSiteApp[];
  githubAllowed: boolean;
  onDone: (d: AdminSiteApps) => void;
}) {
  // The apps this server may replace. One the configuration publishes
  // is not among them: the server refuses to overwrite it, so offering
  // it here would be offering an action that cannot happen.
  const updatable = apps.filter((a) => a.managed);

  const [error, setError] = useState<string | null>(null);
  // Publishing something new and replacing something that exists are
  // different acts, and the form used to make them the same one: an id
  // that matched replaced, an id that did not create. A site meaning
  // to update `demos` typed `demo` and got a second app, with nothing
  // to say so -- `demo` was a valid id for a new app, which is exactly
  // what the form made.
  const [mode, setMode] = useState<'update' | 'new'>(
    updatable.length > 0 ? 'update' : 'new',
  );
  const [id, setID] = useState('');
  const [target, setTarget] = useState(updatable[0]?.id ?? '');
  const [idError, setIDError] = useState<string | null>(null);
  const [everyone, setEveryone] = useState(false);
  const [groups, setGroups] = useState<string[]>([]);
  const [pending, setPending] = useState('');
  const [groupsError, setGroupsError] = useState<string | null>(null);
  const [home, setHome] = useState(false);
  const [done, setDone] = useState<Published | null>(null);
  // Where the bytes come from. A file is always possible; fetching
  // from a release needs the server to have egress, which it reports.
  const [from, setFrom] = useState<'file' | 'github'>('file');
  const [repo, setRepo] = useState('');
  const [ref, setRef] = useState('');
  const [asset, setAsset] = useState('');
  const [repoError, setRepoError] = useState<string | null>(null);

  const chosen = mode === 'update' ? updatable.find((a) => a.id === target) : undefined;
  const effectiveID = mode === 'update' ? target : id;
  // Only ever a question, never a refusal: `demo` and `demos` can
  // both be real apps. It is shown while the id is being typed, which
  // is before the bundle is uploaded.
  const near = mode === 'new' ? nearestSiteAppID(id, apps.map((a) => a.id)) : null;

  /**
   * Take an existing app's audience as the starting point.
   *
   * Replacing a bundle is not a decision about who may see the app,
   * and an update that silently re-published to whatever was in an
   * empty form would be a visibility change nobody asked for.
   */
  function loadFrom(app: AdminSiteApp | undefined) {
    setEveryone(app?.groups.includes(EVERYONE) ?? false);
    setGroups((app?.groups ?? []).filter((g) => g !== EVERYONE));
    setHome(app?.home ?? false);
    setPending('');
    setGroupsError(null);
    setError(null);
    setDone(null);
    // An app that came from a release is updated from the same place
    // nine times out of ten, so the repository and the asset are
    // carried over and only the tag is left to say. The tag is NOT
    // carried over: it is the one thing an update changes, and a
    // prefilled old tag would reinstall what is already there.
    const src = app?.source;
    setRepoError(null);
    setRef('');
    if (src && githubAllowed) {
      setFrom('github');
      setRepo(src.repo);
      setAsset(src.asset ?? '');
    } else {
      setFrom('file');
      setRepo('');
      setAsset('');
    }
  }

  // The settings of whichever app is selected, including on the first
  // render: the form opens in update mode wherever there is something
  // to update, and an empty audience box would read as "visible to
  // nobody" for an app that is visible to a lab.
  const [loaded, setLoaded] = useState<string | null>(null);
  if (mode === 'update' && loaded !== target) {
    setLoaded(target);
    loadFrom(chosen);
  }

  const upload = useMutation({
    mutationFn: (form: FormData) => api.admin.uploadSiteApp(form),
    onSuccess: (d, form) => {
      setError(null);
      const want = String(form.get('id') ?? '');
      const app = d.apps.find((a) => a.id === want);
      setDone({ id: want, version: app?.version, at: app?.uploaded_at });
      onDone(d);
    },
    onError: (e: Error) => {
      setDone(null);
      setError(e.message);
    },
  });

  return (
    <form
      className="max-w-xl space-y-3 rounded-lg border border-gray-200 bg-white p-4"
      data-testid="upload-form"
      onSubmit={(e) => {
        e.preventDefault();
        const form = e.currentTarget;
        // Whatever is still in the group box counts: nobody should
        // have to press Enter to mean what they have just typed.
        const named = pending.trim() === '' ? groups : [...groups, ...parseGroupList(pending)];

        const idProblem =
          mode === 'update'
            ? target === ''
              ? 'Choose the app to replace.'
              : null
            : // A new app may not take an id that is already published.
              // Overwriting one by typing its name is the other half
              // of the mistake this form now refuses: it is an update,
              // and an update says so.
              (validateSiteAppID(id) ??
              (apps.some((a) => a.id === id.trim().toLowerCase())
                ? `${id.trim()} is already published. Choose “Replace an app” to put a new bundle under that id.`
                : null));
        const groupProblem =
          everyone || named.length > 0
            ? null
            : 'Name at least one group that may see this app, or tick “everyone signed in”.';
        // The server validates this too, and its answer is the one
        // that counts; this is here so an empty box is not a round
        // trip.
        const repoProblem =
          from === 'github' && repo.trim() === '' ? 'Name the repository as owner/name.' : null;
        setIDError(idProblem);
        setGroupsError(groupProblem);
        setRepoError(repoProblem);
        if (idProblem || groupProblem || repoProblem) return;

        setGroups(named);
        setPending('');
        setDone(null);
        const data = new FormData(form);
        data.set('id', effectiveID.trim());
        data.set('groups', everyone ? EVERYONE : named.join(', '));
        // Controlled now, because an update loads the app's current
        // setting into it; an unchecked box in the DOM would quietly
        // clear it.
        data.set('home', home ? 'true' : 'false');
        data.set('source', from);
        upload.mutate(data);
      }}
    >
      <div>
        <h2 className="text-sm font-semibold text-gray-900">Publish a bundle</h2>
        <p className="mt-1 text-xs text-gray-500">
          The app is served at <Code>/site/&lt;id&gt;/</Code> to the groups you name. It runs
          with the rights of everyone who opens it, in code this release does not review.
        </p>
      </div>

      {/* Which act this is. Asked first, because it decides whether an
          id is typed or chosen -- and typing one is how a site ended
          up with `demo` beside the `demos` it meant to replace. */}
      <fieldset className="text-sm text-gray-700">
        <legend className="sr-only">New app or replacement</legend>
        <div className="flex gap-4">
          <label className="flex items-center gap-2">
            <input
              type="radio"
              name="mode"
              value="update"
              checked={mode === 'update'}
              disabled={updatable.length === 0}
              data-testid="mode-update"
              onChange={() => {
                setMode('update');
                setIDError(null);
                setLoaded(null);
              }}
            />
            Replace an app
          </label>
          <label className="flex items-center gap-2">
            <input
              type="radio"
              name="mode"
              value="new"
              checked={mode === 'new'}
              data-testid="mode-new"
              onChange={() => {
                setMode('new');
                setIDError(null);
                loadFrom(undefined);
              }}
            />
            Publish a new app
          </label>
        </div>
        {updatable.length === 0 ? (
          <p className="mt-1 text-xs text-gray-500" data-testid="nothing-to-update">
            Nothing published here can be replaced from this page yet.
          </p>
        ) : null}
      </fieldset>

      {mode === 'update' ? (
        <label className="block text-sm text-gray-700">
          App
          <select
            className={INPUT}
            data-testid="upload-target"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
          >
            {updatable.map((a) => (
              <option key={a.id} value={a.id}>
                {a.id}
                {a.version ? ` — ${a.version}` : ''}
              </option>
            ))}
          </select>
        </label>
      ) : (
        <label className="block text-sm text-gray-700">
          Id
          <input
            name="id"
            className={INPUT}
            data-testid="upload-id"
            value={id}
            onChange={(e) => {
              setID(e.target.value);
              setIDError(null);
            }}
            // Checked on the way out of the field as well as on submit.
            // The bundle input is required, so a browser refuses the
            // submit before any of this runs -- an administrator who
            // typed a bad id would otherwise be told about the missing
            // file and nothing else.
            onBlur={() => {
              if (id.trim() !== '') setIDError(validateSiteAppID(id));
            }}
          />
        </label>
      )}
      {idError ? (
        <p className="text-sm text-red-600" data-testid="upload-id-error">
          {idError}
        </p>
      ) : null}
      {near && !idError ? (
        <p
          className="rounded-sm border border-amber-300 bg-amber-50 px-2 py-1 text-sm text-amber-900"
          data-testid="upload-near-miss"
        >
          <Code>{near}</Code> is already published, and <Code>{id.trim()}</Code> is nearly the
          same name. Publishing this makes a second app.{' '}
          <button
            type="button"
            className="underline"
            data-testid="upload-near-miss-switch"
            onClick={() => {
              setMode('update');
              setTarget(near);
              setLoaded(null);
              setIDError(null);
            }}
          >
            Replace {near} instead
          </button>
        </p>
      ) : null}
      {chosen ? (
        <p className="text-xs text-gray-600" data-testid="upload-replacing">
          Replaces the bundle served at <Code>{chosen.url}</Code>
          {chosen.version ? (
            <>
              , now at version <strong>{chosen.version}</strong>
            </>
          ) : null}
          . Its settings below are the ones in force; change them here and they change with the
          bundle.
        </p>
      ) : null}
      <GroupsField
        everyone={everyone}
        groups={groups}
        pending={pending}
        error={groupsError}
        onEveryone={(v) => {
          setEveryone(v);
          setGroupsError(null);
        }}
        onGroups={(g) => {
          setGroups(g);
          setGroupsError(null);
        }}
        onPending={(v) => {
          setPending(v);
          setGroupsError(null);
        }}
      />
      {/* Where the bytes come from. Offered only where the server
          will actually fetch: on an access point with no egress the
          choice would be between a file and a timeout. */}
      {githubAllowed ? (
        <fieldset className="text-sm text-gray-700">
          <legend className="sr-only">Where the bundle comes from</legend>
          <div className="flex gap-4">
            <label className="flex items-center gap-2">
              <input
                type="radio"
                name="from"
                value="file"
                checked={from === 'file'}
                data-testid="from-file"
                onChange={() => {
                  setFrom('file');
                  setRepoError(null);
                }}
              />
              Attach a file
            </label>
            <label className="flex items-center gap-2">
              <input
                type="radio"
                name="from"
                value="github"
                checked={from === 'github'}
                data-testid="from-github"
                onChange={() => {
                  setFrom('github');
                  setError(null);
                }}
              />
              From a GitHub release
            </label>
          </div>
        </fieldset>
      ) : null}

      {from === 'github' && githubAllowed ? (
        <div className="space-y-3" data-testid="github-fields">
          <label className="block text-sm text-gray-700">
            Repository
            <input
              name="repo"
              type="text"
              value={repo}
              placeholder="owner/name"
              autoCapitalize="none"
              autoCorrect="off"
              spellCheck={false}
              className={INPUT}
              data-testid="upload-repo"
              onChange={(e) => {
                setRepo(e.target.value);
                setRepoError(null);
              }}
            />
          </label>
          {repoError ? (
            <p className="text-sm text-red-600" data-testid="upload-repo-error">
              {repoError}
            </p>
          ) : null}
          <label className="block text-sm text-gray-700">
            Release
            <input
              name="ref"
              type="text"
              value={ref}
              placeholder="latest"
              autoCapitalize="none"
              autoCorrect="off"
              spellCheck={false}
              className={INPUT}
              data-testid="upload-ref"
              onChange={(e) => setRef(e.target.value)}
            />
            <span className="mt-1 block text-xs text-gray-500">
              A tag such as <Code>v1.2.0</Code>. Blank takes the latest release, and the tag it
              resolves to is what gets recorded.
            </span>
          </label>
          <label className="block text-sm text-gray-700">
            Asset
            <input
              name="asset"
              type="text"
              value={asset}
              placeholder="the release's only .zip"
              autoCapitalize="none"
              autoCorrect="off"
              spellCheck={false}
              className={INPUT}
              data-testid="upload-asset"
              onChange={(e) => setAsset(e.target.value)}
            />
            <span className="mt-1 block text-xs text-gray-500">
              Only needed where a release attaches more than one bundle. A <Code>.sha256</Code>{' '}
              published beside it is checked before anything is served.
            </span>
          </label>
          <p className="text-xs text-gray-500">
            The repository must be public: this fetches without credentials.
          </p>
        </div>
      ) : (
        <label className="block text-sm text-gray-700">
          Bundle
          <input
            name="bundle"
            type="file"
            accept=".zip"
            required
            className={`${INPUT} file:mr-2 file:rounded-sm file:border-0 file:bg-gray-100 file:px-2 file:py-1 file:text-xs`}
            data-testid="upload-bundle"
          />
        </label>
      )}
      <label className="flex items-center gap-2 text-sm text-gray-700">
        <input
          name="home"
          type="checkbox"
          checked={home}
          onChange={(e) => setHome(e.target.checked)}
          className="rounded-sm border-gray-300"
          data-testid="upload-home"
        />
        Members of an app-only group land here
      </label>
      {error ? (
        <p className="text-sm text-red-600" data-testid="upload-error">
          {error}
        </p>
      ) : null}
      {upload.isPending ? (
        <p className="text-sm text-gray-600" data-testid="upload-busy">
          {from === 'github'
            ? `Fetching ${repo.trim()} and publishing ${effectiveID.trim()}…`
            : `Publishing ${effectiveID.trim()}… the bundle is being stored and the directory rescanned.`}
        </p>
      ) : null}
      {done && !upload.isPending ? (
        <p
          className="rounded-sm border border-emerald-300 bg-emerald-50 px-2 py-1 text-sm text-emerald-900"
          data-testid="upload-result"
        >
          Published <Code>{done.id}</Code>
          {done.version ? (
            <>
              {' '}
              version <strong>{done.version}</strong>
            </>
          ) : (
            ' (the bundle names no version)'
          )}
          {done.at ? ` at ${formatWhen(done.at)}` : ''}. It is being served now.
        </p>
      ) : null}
      <button
        type="submit"
        disabled={upload.isPending}
        className="rounded-sm bg-brand-600 px-3 py-1 text-sm font-medium text-white hover:bg-brand-700 disabled:opacity-50"
        data-testid="upload-submit"
      >
        {upload.isPending
          ? 'Publishing…'
          : mode === 'update'
            ? 'Replace bundle'
            : 'Publish new app'}
      </button>
    </form>
  );
}

function Header() {
  return (
    <div>
      <h1 className="text-2xl font-bold text-gray-900">Site apps</h1>
      <p className="text-sm text-gray-500">
        Single-page apps this access point serves under <Code>/site/&lt;id&gt;/</Code>, each
        visible only to the groups it names. The table is what is published now; open a row for
        its settings and what was published before.
      </p>
    </div>
  );
}

export default function AdminSiteAppsPage() {
  const qc = useQueryClient();
  const [open, setOpen] = useState<string | null>(null);

  const list = useQuery({
    queryKey: ['admin', 'site-apps'],
    queryFn: api.admin.listSiteApps,
  });

  const withdraw = useMutation({
    mutationFn: (id: string) => api.admin.withdrawSiteApp(id),
    onSuccess: (d) => qc.setQueryData(['admin', 'site-apps'], d),
  });

  if (list.isLoading) {
    return (
      <div className="max-w-5xl space-y-4">
        <Header />
        <p className="text-sm text-gray-400">Loading…</p>
      </div>
    );
  }
  if (list.isError) {
    return (
      <div className="max-w-5xl space-y-4">
        <Header />
        <p className="text-sm text-red-600" data-testid="list-error">
          {(list.error as Error).message}
        </p>
      </div>
    );
  }

  const data = list.data as AdminSiteApps;

  if (!data.enabled) {
    return (
      <div className="max-w-5xl space-y-4">
        <Header />
        <div
          className="rounded-lg border border-amber-300 bg-amber-50 p-4"
          data-testid="site-apps-off"
        >
          <h2 className="text-sm font-semibold text-amber-900">
            Site apps are not configured on this access point
          </h2>
          <p className="mt-1 text-sm text-amber-800">
            Set <Code>HTTP_API_SITE_APPS_DIR</Code> to the directory that will hold bundles, then
            run <Code>condor_reconfig</Code>. Nothing is served until it is set, and this page
            stays read-only.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="max-w-5xl space-y-4">
      <Header />

      {data.apps.length === 0 ? (
        <p className="text-sm text-gray-500" data-testid="no-apps">
          Nothing is published. Bundles go in <Code>{data.directory}</Code>.
        </p>
      ) : (
        <div className="overflow-x-auto rounded-lg border border-gray-200 bg-white">
          <table className="min-w-full text-sm" data-testid="apps-table">
            <thead className="bg-gray-50 text-left text-xs uppercase tracking-wide text-gray-500">
              <tr>
                <th className={TH}>App</th>
                <th className={TH}>Build</th>
                <th className={TH}>Visible to</th>
                <th className={TH}>Published by</th>
                <th className={TH} />
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {data.apps.map((a: AdminSiteApp) => (
                <AppRows
                  key={a.id}
                  app={a}
                  open={open === a.id}
                  uploadAllowed={data.upload_allowed}
                  onToggle={() => setOpen(open === a.id ? null : a.id)}
                  onWithdraw={() => withdraw.mutate(a.id)}
                />
              ))}
            </tbody>
          </table>
        </div>
      )}

      {data.upload_allowed ? (
        <UploadForm
          apps={data.apps}
          githubAllowed={data.github_allowed ?? false}
          onDone={(d) => qc.setQueryData(['admin', 'site-apps'], d)}
        />
      ) : (
        <div
          className="max-w-xl rounded-lg border border-gray-200 bg-gray-50 p-4"
          data-testid="upload-off"
        >
          <h2 className="text-sm font-semibold text-gray-900">Publishing from here is off</h2>
          <p className="mt-1 text-xs text-gray-600">
            Copy the bundle into <Code>{data.directory}</Code> and name its groups with{' '}
            <Code>HTTP_API_SITE_APP_&lt;ID&gt;_GROUPS</Code>, then run{' '}
            <Code>condor_reconfig</Code>. To publish from this page instead, set{' '}
            <Code>HTTP_API_SITE_APPS_UPLOAD = true</Code> — an uploaded app runs with the rights
            of everyone who opens it, so it is a grant separate from administering this server.
          </p>
        </div>
      )}
    </div>
  );
}

/**
 * "There is a newer release" for an app installed from one.
 *
 * Asked of GitHub by the browser. The access point is not made to poll
 * every repository it ever installed from -- that would be a standing
 * outbound request on a schedule, for a convenience -- and it does not
 * need to be: api.github.com answers cross-origin, so the page can ask
 * for itself, once per repository, while it is open.
 *
 * Silent on every failure. A rate-limited or unreachable GitHub means
 * no badge; it must not put an error on a page that is otherwise
 * correct.
 */
function UpdateBadge({ app }: { app: AdminSiteApp }) {
  const repo = app.source?.repo;
  const { data } = useQuery({
    queryKey: ['site-app-release', repo],
    queryFn: () => latestRelease(repo as string),
    enabled: Boolean(repo),
    // Releases are not published by the minute, and an unauthenticated
    // caller gets 60 requests an hour from this address -- shared with
    // every other tab the viewer has open.
    staleTime: 10 * 60 * 1000,
    retry: false,
  });
  if (!repo || !data || !releaseDiffers(app.source?.ref, data.tag)) return null;
  return (
    <a
      href={data.url}
      target="_blank"
      rel="noreferrer"
      onClick={(e) => e.stopPropagation()}
      data-testid={`update-${app.id}`}
      className="mt-0.5 inline-block rounded-sm border border-amber-300 bg-amber-50 px-1.5 py-0.5 text-xs text-amber-900 hover:bg-amber-100"
    >
      {data.tag} is the current release
    </a>
  );
}

// AppRows is one app: the row, and the detail it opens onto.
function AppRows({
  app: a,
  open,
  uploadAllowed,
  onToggle,
  onWithdraw,
}: {
  app: AdminSiteApp;
  open: boolean;
  uploadAllowed: boolean;
  onToggle: () => void;
  onWithdraw: () => void;
}) {
  return (
    <>
      <tr
        data-testid={`app-${a.id}`}
        aria-expanded={open}
        className={`cursor-pointer hover:bg-gray-50 ${open ? 'bg-gray-50' : ''}`}
        onClick={onToggle}
      >
        <td className={TD}>
          <a
            href={a.url}
            className="font-medium text-brand-700 hover:underline"
            onClick={(e) => e.stopPropagation()}
          >
            {a.name}
          </a>
          <div className="text-xs text-gray-500">{a.id}</div>
        </td>
        <td className={TD}>
          {a.version || <span className="text-gray-400">unversioned</span>}
          <div className="mt-0.5 text-xs text-gray-500">
            <Code>{shortDigest(a.digest)}</Code>
            {a.attested ? ' · checksummed' : ''}
            {a.size_bytes ? ` · ${formatBytes(a.size_bytes)}` : ''}
          </div>
          {a.uploaded_at ? (
            <div className="mt-0.5 text-xs text-gray-500" data-testid={`published-${a.id}`}>
              published {formatWhen(a.uploaded_at)}
            </div>
          ) : null}
          {a.source ? (
            <div className="mt-0.5 text-xs text-gray-500" data-testid={`source-${a.id}`}>
              from{' '}
              <a
                href={`https://github.com/${a.source.repo}`}
                target="_blank"
                rel="noreferrer"
                className="hover:underline"
                onClick={(e) => e.stopPropagation()}
              >
                {a.source.repo}
              </a>
              {a.source.ref ? ` at ${a.source.ref}` : ''}
            </div>
          ) : null}
          <UpdateBadge app={a} />
        </td>
        <td className={TD}>
          {a.groups.join(', ')}
          {a.home ? <div className="text-xs text-gray-500">home</div> : null}
        </td>
        <td className={`${TD} text-gray-500`}>
          {a.origin}
          {a.uploaded_by ? <div className="text-xs">by {a.uploaded_by}</div> : null}
        </td>
        <td className={TD}>
          <div
            className="flex items-center justify-end gap-2"
            onClick={(e) => e.stopPropagation()}
          >
            <button
              type="button"
              onClick={onToggle}
              className={BTN}
              data-testid={`history-${a.id}`}
            >
              {open ? 'Hide' : 'Details'}
            </button>
            {/* Only an uploaded app can be withdrawn here. One the
                configuration publishes is changed where it was
                decided, and the server refuses it anyway. */}
            {a.managed && uploadAllowed ? (
              <ConfirmButton
                label="Withdraw"
                confirmLabel="Confirm"
                compact
                onConfirm={onWithdraw}
              />
            ) : null}
          </div>
        </td>
      </tr>
      {open ? (
        <tr data-testid={`details-${a.id}`}>
          <td colSpan={5} className="bg-gray-50 px-3 py-3">
            <div className="space-y-4" data-testid="history-section">
              <AppConfig id={a.id} />
              <div className="space-y-2">
                <div>
                  <h3 className="text-sm font-semibold text-gray-900">What has been served</h3>
                  <p className="text-xs text-gray-500">
                    One row per period this app was served from one bundle under one policy. A
                    new row means the bundle or who could see it changed.
                  </p>
                </div>
                <AppHistory id={a.id} />
              </div>
            </div>
          </td>
        </tr>
      ) : null}
    </>
  );
}
