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

function AppHistory({ id }: { id: string }) {
  const q = useQuery({
    queryKey: ['admin', 'site-apps', id, 'history'],
    queryFn: () => api.admin.siteAppHistory(id),
  });

  if (q.isLoading) return <p className="muted">Loading history…</p>;
  if (q.isError) {
    return (
      <p className="error" data-testid="history-error">
        {(q.error as Error).message}
      </p>
    );
  }
  const rows = q.data?.history ?? [];
  if (rows.length === 0) {
    return (
      <p className="muted" data-testid="history-empty">
        Nothing recorded yet. A period appears here once a scan has seen this app.
      </p>
    );
  }
  return (
    <table className="table" data-testid="history-table">
      <thead>
        <tr>
          <th>Served</th>
          <th>Build</th>
          <th>Digest</th>
          <th>Visible to</th>
          <th>Published by</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((h, i) => (
          <tr key={`${h.digest}-${h.first_seen}-${i}`}>
            <td>
              {formatWhen(h.first_seen)} – {formatWhen(h.last_seen)}
            </td>
            <td>
              {h.version || <span className="muted">unversioned</span>}
              {h.revision ? ` (${h.revision})` : ''}
              {h.size_bytes ? ` · ${formatBytes(h.size_bytes)}` : ''}
            </td>
            <td>
              <code>{shortDigest(h.digest)}</code>
              {h.attested ? (
                <span className="badge" title="A .sha256 accompanied the bundle and matched">
                  checksummed
                </span>
              ) : null}
            </td>
            <td>{h.groups.join(', ')}</td>
            <td className="muted">{h.origin}</td>
          </tr>
        ))}
      </tbody>
    </table>
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
      className="card"
      data-testid="upload-form"
      onSubmit={(e) => {
        e.preventDefault();
        upload.mutate(new FormData(e.currentTarget));
      }}
    >
      <h3>Publish a bundle</h3>
      <p className="muted">
        The app is served at <code>/site/&lt;id&gt;/</code> to the groups you name. It runs with
        the rights of everyone who opens it, in code this release does not review.
      </p>
      <label>
        Id
        <input name="id" required pattern="[a-z0-9][a-z0-9_-]*" data-testid="upload-id" />
      </label>
      <label>
        Visible to
        <input
          name="groups"
          required
          placeholder="smith_lab, jones_lab — or * for everyone signed in"
          data-testid="upload-groups"
        />
      </label>
      <label>
        Bundle
        <input name="bundle" type="file" accept=".zip" required data-testid="upload-bundle" />
      </label>
      <label className="checkbox">
        <input name="home" type="checkbox" value="true" data-testid="upload-home" />
        Members of an app-only group land here
      </label>
      {error ? (
        <p className="error" data-testid="upload-error">
          {error}
        </p>
      ) : null}
      <button type="submit" disabled={upload.isPending} data-testid="upload-submit">
        {upload.isPending ? 'Publishing…' : 'Publish'}
      </button>
    </form>
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

  if (list.isLoading) return <p className="muted">Loading…</p>;
  if (list.isError) {
    return (
      <p className="error" data-testid="list-error">
        {(list.error as Error).message}
      </p>
    );
  }

  const data = list.data as AdminSiteApps;

  if (!data.enabled) {
    return (
      <section>
        <h1>Site apps</h1>
        <p data-testid="site-apps-off">
          Site apps are not configured on this access point. Set{' '}
          <code>HTTP_API_SITE_APPS_DIR</code> to the directory that will hold bundles.
        </p>
      </section>
    );
  }

  return (
    <section>
      <h1>Site apps</h1>

      {data.apps.length === 0 ? (
        <p className="muted" data-testid="no-apps">
          Nothing is published. Bundles go in <code>{data.directory}</code>.
        </p>
      ) : (
        <table className="table" data-testid="apps-table">
          <thead>
            <tr>
              <th>App</th>
              <th>Build</th>
              <th>Visible to</th>
              <th>Published by</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {data.apps.map((a: AdminSiteApp) => (
              <tr key={a.id} data-testid={`app-${a.id}`}>
                <td>
                  <a href={a.url}>{a.name}</a>
                  <div className="muted">{a.id}</div>
                </td>
                <td>
                  {a.version || <span className="muted">unversioned</span>}
                  <div className="muted">
                    <code>{shortDigest(a.digest)}</code>
                    {a.attested ? ' · checksummed' : ''}
                  </div>
                </td>
                <td>
                  {a.groups.join(', ')}
                  {a.home ? <div className="muted">home</div> : null}
                </td>
                <td className="muted">{a.origin}</td>
                <td>
                  <button
                    type="button"
                    onClick={() => setOpen(open === a.id ? null : a.id)}
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
                      onConfirm={() => withdraw.mutate(a.id)}
                    />
                  ) : null}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {open ? (
        <section data-testid="history-section">
          <h2>What has been served: {open}</h2>
          <p className="muted">
            One row per period this app was served from one bundle under one policy. A new row
            means the bundle or who could see it changed.
          </p>
          <AppHistory id={open} />
        </section>
      ) : null}

      {data.upload_allowed ? (
        <UploadForm onDone={(d) => qc.setQueryData(['admin', 'site-apps'], d)} />
      ) : (
        <p className="muted" data-testid="upload-off">
          Publishing from here is off. Copy the bundle into <code>{data.directory}</code> and name
          its groups with <code>HTTP_API_SITE_APP_&lt;ID&gt;_GROUPS</code>, then run{' '}
          <code>condor_reconfig</code>. To publish from this page instead, set{' '}
          <code>HTTP_API_SITE_APPS_UPLOAD = true</code> — an uploaded app runs with the rights of
          everyone who opens it, so it is a grant separate from administering this server.
        </p>
      )}
    </section>
  );
}
