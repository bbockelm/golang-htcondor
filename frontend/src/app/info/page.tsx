'use client';

import { useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { api } from '@/lib/api';

export default function InfoPage() {
  const { data: session, isLoading: sessionLoading, error: sessionError } =
    useQuery({ queryKey: ['session'], queryFn: api.auth.me });
  const { data: version, isLoading: versionLoading, error: versionError } =
    useQuery({ queryKey: ['version'], queryFn: api.version });

  return (
    <div className="space-y-6 max-w-4xl">
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Info</h1>
        <p className="text-sm text-gray-500">
          Build information for this access point and details about your
          current session.
        </p>
      </div>

      <Section title="Web app">
        {versionLoading && <p className="text-gray-400 text-sm">Loading...</p>}
        {versionError && (
          <p className="text-red-600 text-sm">
            Could not load version: {(versionError as Error).message}
          </p>
        )}
        {version && (
          <DefList>
            <Row label="Version" value={version.version || '(unset)'} />
            <Row label="Commit" mono value={version.commit || '(unset)'} />
          </DefList>
        )}
      </Section>

      <Section title="Signed-in user">
        {sessionLoading && <p className="text-gray-400 text-sm">Loading...</p>}
        {sessionError && (
          <p className="text-red-600 text-sm">
            Could not load session: {(sessionError as Error).message}
          </p>
        )}
        {session && !session.authenticated && (
          <p className="text-sm text-gray-500">
            Not signed in.{' '}
            <a
              href="/login"
              className="text-brand-700 hover:text-brand-900 underline"
            >
              Sign in
            </a>
            .
          </p>
        )}
        {session?.authenticated && (
          <DefList>
            <Row label="Username" value={session.username ?? '(unknown)'} />
            <Row
              label="Admin"
              value={session.is_admin ? 'Yes' : 'No'}
            />
            <Row
              label="Groups"
              value={
                session.groups && session.groups.length > 0 ? (
                  <ul className="space-y-0.5">
                    {session.groups.map((g) => (
                      <li key={g} className="font-mono text-xs">
                        {g}
                      </li>
                    ))}
                  </ul>
                ) : (
                  <span className="text-gray-500">none</span>
                )
              }
            />
          </DefList>
        )}
      </Section>

      {/* Admin-only: HTCondor config readout. Hidden entirely for
          non-admins (the endpoint also gates server-side, so a
          curious user crafting their own request still gets 403). */}
      {session?.is_admin && <CondorConfigSection />}
    </div>
  );
}

// CondorConfigSection renders the running HTCondor config as a
// filterable, height-capped table. The full readout is on the order
// of a few thousand keys; without a height cap the table swallows
// the page. We cap visible rows to ~14 and let the rest scroll
// inside the section, with the filter input pinned above the scroll
// container so it stays reachable without backtracking.
function CondorConfigSection() {
  const { data, isLoading, error } = useQuery({
    queryKey: ['admin-condor-config'],
    queryFn: api.admin.condorConfig,
    // Config doesn't change at runtime; cache for the tab's lifetime.
    staleTime: Infinity,
    retry: false,
  });
  const [filter, setFilter] = useState('');

  // Filter on every render — the entry count is a few thousand, the
  // user's filter text is short, substring match is cheap. Memoize
  // anyway so a re-render that didn't change the filter doesn't re-
  // walk the array.
  const filtered = useMemo(() => {
    if (!data?.entries) return [];
    const q = filter.trim().toLowerCase();
    if (!q) return data.entries;
    return data.entries.filter(
      (e) =>
        e.key.toLowerCase().includes(q) ||
        (e.value ? e.value.toLowerCase().includes(q) : false),
    );
  }, [data, filter]);

  const total = data?.entries?.length ?? 0;

  return (
    <Section title="HTCondor configuration (admin)">
      <p className="text-xs text-gray-500 mb-3">
        Running config of this access point. Equivalent to{' '}
        <code className="font-mono">condor_config_val -dump</code>. Values for
        keys that look like secrets (PASSWORD / SECRET / API_KEY / TOKEN / …)
        are redacted server-side; the key still appears so you can confirm
        it&apos;s set.
      </p>

      {isLoading && <p className="text-sm text-gray-400">Loading…</p>}
      {error && (
        <p className="text-sm text-red-700">
          Could not load config: {(error as Error).message}
        </p>
      )}
      {data && !data.configured && (
        <p className="text-sm text-gray-500">
          No HTCondor config object is wired into this server (typically only
          the demo path).
        </p>
      )}

      {data?.configured && (
        <>
          <div className="flex items-baseline gap-3 mb-2">
            <input
              type="text"
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              placeholder="Filter by key or value (substring, case-insensitive)…"
              className="flex-1 rounded border border-gray-300 px-2 py-1 text-sm"
              aria-label="Filter HTCondor config"
            />
            <span className="text-[11px] text-gray-500 tabular-nums shrink-0">
              {filter
                ? `${filtered.length.toLocaleString()} / ${total.toLocaleString()}`
                : total.toLocaleString()}
            </span>
          </div>

          {/* Inner scroll container caps the table height so the
              admin readout never displaces the rest of the page.
              Using max-h instead of h means short filtered results
              don't get a wasteful scrollbar. */}
          <div className="overflow-y-auto rounded border border-gray-200 max-h-[28rem]">
            {filtered.length === 0 ? (
              <p className="px-3 py-3 text-xs text-gray-500">
                No matches.
              </p>
            ) : (
              <table className="min-w-full text-xs">
                <thead className="sticky top-0 bg-gray-50 text-left text-[10px] uppercase tracking-wide text-gray-500">
                  <tr>
                    <th className="px-3 py-1.5 w-64">Key</th>
                    <th className="px-3 py-1.5">Value</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-100">
                  {filtered.map((e) => (
                    <tr key={e.key}>
                      <td className="px-3 py-1.5 align-top font-mono text-gray-700 break-all">
                        {e.key}
                      </td>
                      <td className="px-3 py-1.5 align-top font-mono text-gray-900 break-all">
                        {e.redacted ? (
                          <span
                            className="rounded bg-gray-200 px-1.5 py-0.5 text-[10px] uppercase tracking-wide text-gray-600"
                            title="Server-side redacted; the key is set but the value is hidden"
                          >
                            redacted
                          </span>
                        ) : e.value ? (
                          e.value
                        ) : (
                          <span className="text-gray-400">(empty)</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </>
      )}
    </Section>
  );
}

function Section({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  return (
    <section className="rounded-lg border border-gray-200 bg-white p-4">
      <h2 className="text-sm font-semibold text-gray-900 mb-3">{title}</h2>
      {children}
    </section>
  );
}

function DefList({ children }: { children: React.ReactNode }) {
  return (
    <dl className="grid grid-cols-[max-content_1fr] gap-x-4 gap-y-2 text-sm">
      {children}
    </dl>
  );
}

function Row({
  label,
  value,
  mono,
}: {
  label: string;
  value: React.ReactNode;
  mono?: boolean;
}) {
  return (
    <>
      <dt className="text-gray-500">{label}</dt>
      <dd
        className={`text-gray-900 break-all ${mono ? 'font-mono text-xs' : ''}`}
      >
        {value}
      </dd>
    </>
  );
}
