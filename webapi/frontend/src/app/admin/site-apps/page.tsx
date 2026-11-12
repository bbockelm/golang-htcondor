'use client';

// Site apps, for the administrator.
//
// Two questions, and they are different questions. "What is published
// right now, and to whom?" is the library's live answer. "What was
// published in October?" is the audit trail, which exists because the
// configuration only ever describes now and a bundle replaced in place
// leaves nothing behind.
//
// Publishing from here is deliberately not always available. An
// uploaded app is served same-origin to the groups it names and can do
// anything its visitor can, so the site turns it on with
// HTTP_API_SITE_APPS_UPLOAD; without it this page reads, and says where
// to put a bundle instead. An app the configuration publishes is never
// editable here whatever that setting says -- the configuration is the
// authority, and the server refuses an upload for such an id rather
// than letting it look like it worked.

import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api, type AdminSiteApp, type AdminSiteApps } from '@/lib/api';
import { ConfirmButton } from '@/components/ConfirmButton';

const TH = 'px-3 py-2';
const TD = 'px-3 py-2 align-top';
const INPUT =
  'mt-1 w-full rounded-sm border border-gray-300 px-2 py-1 text-sm focus:border-brand-400 focus:outline-hidden focus:ring-1 focus:ring-brand-400';

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

function UploadForm({ onDone }: { onDone: (d: AdminSiteApps) => void }) {
  const [error, setError] = useState<string | null>(null);
  const upload = useMutation({
    mutationFn: (form: FormData) => api.admin.uploadSiteApp(form),
    onSuccess: (d) => {
      setError(null);
      onDone(d);
    },
    onError: (e: Error) => setError(e.message),
  });

  return (
    <form
      className="max-w-xl space-y-3 rounded-lg border border-gray-200 bg-white p-4"
      data-testid="upload-form"
      onSubmit={(e) => {
        e.preventDefault();
        upload.mutate(new FormData(e.currentTarget));
      }}
    >
      <div>
        <h2 className="text-sm font-semibold text-gray-900">Publish a bundle</h2>
        <p className="mt-1 text-xs text-gray-500">
          The app is served at <Code>/site/&lt;id&gt;/</Code> to the groups you name. It runs
          with the rights of everyone who opens it, in code this release does not review.
        </p>
      </div>
      <label className="block text-sm text-gray-700">
        Id
        <input
          name="id"
          required
          pattern="[a-z0-9][a-z0-9_-]*"
          className={INPUT}
          data-testid="upload-id"
        />
      </label>
      <label className="block text-sm text-gray-700">
        Visible to
        <input
          name="groups"
          required
          placeholder="smith_lab, jones_lab — or * for everyone signed in"
          className={INPUT}
          data-testid="upload-groups"
        />
      </label>
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
      <label className="flex items-center gap-2 text-sm text-gray-700">
        <input
          name="home"
          type="checkbox"
          value="true"
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
      <button
        type="submit"
        disabled={upload.isPending}
        className="rounded-sm bg-brand-600 px-3 py-1 text-sm font-medium text-white hover:bg-brand-700 disabled:opacity-50"
        data-testid="upload-submit"
      >
        {upload.isPending ? 'Publishing…' : 'Publish'}
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
        visible only to the groups it names. The table is what is published now; the history
        beneath an app is what was published before.
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
                <tr key={a.id} data-testid={`app-${a.id}`}>
                  <td className={TD}>
                    <a href={a.url} className="font-medium text-brand-700 hover:underline">
                      {a.name}
                    </a>
                    <div className="text-xs text-gray-500">{a.id}</div>
                  </td>
                  <td className={TD}>
                    {a.version || <span className="text-gray-400">unversioned</span>}
                    <div className="mt-0.5 text-xs text-gray-500">
                      <Code>{shortDigest(a.digest)}</Code>
                      {a.attested ? ' · checksummed' : ''}
                    </div>
                  </td>
                  <td className={TD}>
                    {a.groups.join(', ')}
                    {a.home ? <div className="text-xs text-gray-500">home</div> : null}
                  </td>
                  <td className={`${TD} text-gray-500`}>{a.origin}</td>
                  <td className={TD}>
                    <div className="flex items-center justify-end gap-2">
                      <button
                        type="button"
                        onClick={() => setOpen(open === a.id ? null : a.id)}
                        className="rounded-sm border border-gray-300 bg-white px-2 py-0.5 text-xs text-gray-700 hover:bg-gray-50"
                        data-testid={`history-${a.id}`}
                      >
                        {open === a.id ? 'Hide history' : 'History'}
                      </button>
                      {/* Only an uploaded app can be withdrawn here. One the
                          configuration publishes is changed where it was
                          decided, and the server refuses it anyway. */}
                      {a.managed && data.upload_allowed ? (
                        <ConfirmButton
                          label="Withdraw"
                          confirmLabel="Confirm"
                          compact
                          onConfirm={() => withdraw.mutate(a.id)}
                        />
                      ) : null}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {open ? (
        <section className="space-y-2" data-testid="history-section">
          <div>
            <h2 className="text-sm font-semibold text-gray-900">
              What has been served: {open}
            </h2>
            <p className="text-xs text-gray-500">
              One row per period this app was served from one bundle under one policy. A new row
              means the bundle or who could see it changed.
            </p>
          </div>
          <AppHistory id={open} />
        </section>
      ) : null}

      {data.upload_allowed ? (
        <UploadForm onDone={(d) => qc.setQueryData(['admin', 'site-apps'], d)} />
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
