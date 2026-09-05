"use client";

import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api, type DBMirrorHealth } from "@/lib/api";

export default function InfoPage() {
  const {
    data: session,
    isLoading: sessionLoading,
    error: sessionError,
  } = useQuery({ queryKey: ["session"], queryFn: api.auth.me });
  const {
    data: version,
    isLoading: versionLoading,
    error: versionError,
  } = useQuery({ queryKey: ["version"], queryFn: api.version });

  return (
    <div className="space-y-6 max-w-4xl">
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Info</h1>
        <p className="text-sm text-gray-500">
          Build information for this access point and details about your current
          session.
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
            <Row label="Version" value={version.version || "(unset)"} />
            <Row label="Commit" mono value={version.commit || "(unset)"} />
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
            Not signed in.{" "}
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
            <Row label="Username" value={session.username ?? "(unknown)"} />
            <Row label="Admin" value={session.is_admin ? "Yes" : "No"} />
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
      {session?.is_admin && <DBMirrorSection />}

      {session?.is_admin && <CondorConfigSection />}
    </div>
  );
}

// DBMirrorSection answers "is this access point serving reads out of
// htcondordb, or out of the schedd?".
//
// Routing is deliberately invisible in normal operation: a working
// mirror looks exactly like a fast schedd, and a mirror that falls
// behind silently hands the work back rather than failing. That is the
// right behavior and it leaves an operator with no way to tell whether
// the deployment they configured is doing anything -- hence the counts,
// which distinguish "a mirror exists" from "a mirror is answering".
function DBMirrorSection() {
  const { data, isLoading, error } = useQuery({
    queryKey: ['dbmirror', 'status'],
    queryFn: api.dbmirror.status,
    refetchInterval: 30_000,
    retry: false,
  });

  return (
    <Section title="htcondordb mirror (admin)">
      {isLoading && <p className="text-gray-400 text-sm">Loading...</p>}
      {error && (
        <p className="text-red-600 text-sm">
          Could not load mirror status: {(error as Error).message}
        </p>
      )}

      {data && !data.enabled && (
        <p className="text-sm text-gray-600">
          Not configured. Every job and history read goes to the schedd.
          Routing needs both a collector to discover the mirror through
          and the HTCondor config whose <code className="font-mono text-xs">SEC_*</code>{' '}
          settings authenticate the connection.
        </p>
      )}

      {data?.enabled && (
        <div className="space-y-4">
          <DefList>
            <Row
              label="Reads served"
              value={
                data.served_total + data.declined_total === 0 ? (
                  <span className="text-gray-500">
                    No routable read yet since this server started.
                  </span>
                ) : (
                  <span>
                    <strong>{data.served_total.toLocaleString()}</strong> from
                    the mirror,{' '}
                    <strong>{data.declined_total.toLocaleString()}</strong> from
                    the schedd
                  </span>
                )
              }
            />
            {data.health && <MirrorHealthRows health={data.health} />}
          </DefList>

          {data.routing && data.routing.length > 0 && (
            <div>
              <h3 className="mb-1 text-xs font-semibold uppercase tracking-wide text-gray-500">
                Routing decisions since startup
              </h3>
              <div className="overflow-x-auto rounded-sm border border-gray-200">
                <table className="min-w-full text-sm">
                  <thead className="bg-gray-50 text-left text-xs uppercase tracking-wide text-gray-500">
                    <tr>
                      <th className="px-3 py-1.5">Read</th>
                      <th className="px-3 py-1.5">Outcome</th>
                      <th className="px-3 py-1.5">Reason</th>
                      <th className="px-3 py-1.5 text-right">Count</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-100">
                    {data.routing.map((row) => (
                      <tr
                        key={`${row.table}-${row.decision}-${row.reason}`}
                        className="hover:bg-gray-50"
                      >
                        <td className="px-3 py-1.5">{row.table}</td>
                        <td className="px-3 py-1.5">
                          <span
                            className={`inline-flex rounded-full px-2 py-0.5 text-xs font-medium ${
                              row.decision === 'served'
                                ? 'bg-green-100 text-green-800'
                                : 'bg-gray-100 text-gray-700'
                            }`}
                          >
                            {row.decision === 'served' ? 'mirror' : 'schedd'}
                          </span>
                        </td>
                        <td className="px-3 py-1.5 font-mono text-xs text-gray-600">
                          {row.reason}
                        </td>
                        <td className="px-3 py-1.5 text-right tabular-nums">
                          {row.count.toLocaleString()}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <p className="mt-1 text-xs text-gray-400">
                Cumulative since this server started, not a current rate.
              </p>
            </div>
          )}
        </div>
      )}
    </Section>
  );
}

// MirrorHealthRows renders the discovery and freshness half. Staleness is
// shown against the tolerance that actually gates routing, because the
// number alone does not say whether it is a problem.
function MirrorHealthRows({ health }: { health: DBMirrorHealth }) {
  const badge =
    health.status === 'ok'
      ? 'bg-green-100 text-green-800'
      : health.status === 'warning'
        ? 'bg-amber-100 text-amber-800'
        : health.status === 'unknown'
          ? 'bg-gray-100 text-gray-700'
          : 'bg-red-100 text-red-800';
  const statusText =
    health.status === 'ok'
      ? 'Serving'
      : health.status === 'warning'
        ? 'Discovered, not serving'
        : health.status === 'unknown'
          ? 'Not checked yet'
          : 'Not reachable';

  return (
    <>
      <Row
        label="Status"
        value={
          <span
            className={`inline-flex rounded-full px-2 py-0.5 text-xs font-medium ${badge}`}
          >
            {statusText}
          </span>
        }
      />
      {health.name && <Row label="Mirror" value={health.name} />}
      {health.address && <Row label="Address" mono value={health.address} />}
      {health.required ? (
        <Row
          label="Required"
          value="Yes — a read the mirror cannot serve FAILS instead of falling back to the schedd."
        />
      ) : (
        health.status !== 'ok' && (
          // Say the consequence, not only the fault. The error below is
          // the loudest thing on the panel, and without this an operator
          // reasonably reads it as an outage — when a mirror that cannot
          // be reached is a lost optimisation and nothing more, because
          // every declined read goes to the schedd instead.
          <Row
            label="Impact"
            value="None on correctness — reads are falling back to the schedd. The mirror is an
              optimisation here (HTTP_API_DBMIRROR_REQUIRED is not set), so a failure below means
              queries are slower and land on the access point, not that they fail."
          />
        )
      )}
      {(health.pinned_name || health.pinned_address) && (
        <Row
          label="Pinned to"
          mono
          value={[health.pinned_name, health.pinned_address]
            .filter(Boolean)
            .join(' @ ')}
        />
      )}
      {health.discovered ? (
        <>
          <Row
            label="Job queue"
            value={
              <StalenessValue
                ok={health.job_queue_caught_up}
                okText="caught up"
                notOkText="behind the schedd's job_queue.log"
                seconds={health.job_queue_staleness_seconds}
                tolerance={health.jobs_tolerance_seconds}
              />
            }
          />
          <Row
            label="History"
            value={
              health.history_gap ? (
                <span className="text-red-700">
                  durability gap reported — history routing is stopped
                </span>
              ) : (
                <StalenessValue
                  ok
                  okText=""
                  notOkText=""
                  seconds={health.history_staleness_seconds}
                  tolerance={health.history_tolerance_seconds}
                />
              )
            }
          />
        </>
      ) : (
        <Row
          label="Freshness"
          value={
            <span className="text-gray-500">
              Unknown — no mirror advertisement has been read, and the lag
              is only ever reported by the mirror itself.
            </span>
          }
        />
      )}
      <Row
        label="Last polled"
        value={
          health.last_attempt ? (
            <span>
              {new Date(health.last_attempt).toLocaleString()}
              {health.ad_age_seconds ? (
                <span className="text-gray-400">
                  {' '}
                  · advertisement read{' '}
                  {health.ad_age_seconds.toLocaleString()}s ago
                </span>
              ) : null}
            </span>
          ) : (
            <span className="text-gray-500">
              Never — nothing has asked the collector for the mirror yet.
            </span>
          )
        }
      />
      {health.last_success && (
        <Row
          label="Last discovered"
          value={new Date(health.last_success).toLocaleString()}
        />
      )}
      {health.last_error && (
        <Row
          label="Discovery error"
          value={<span className="text-red-700">{health.last_error}</span>}
        />
      )}
      {health.dial_error && (
        <Row
          label="Connection error"
          value={
            <span>
              <span className="text-red-700">{health.dial_error}</span>
              <span className="block text-xs text-gray-400">
                The mirror was found but could not be connected to, so reads
                fall back to the schedd and are counted as{' '}
                <code className="font-mono">dial_failed</code> below.
                {health.dial_last_success
                  ? ` Last connected ${new Date(health.dial_last_success).toLocaleString()}.`
                  : ' It has never connected since this server started.'}
              </span>
            </span>
          }
        />
      )}
    </>
  );
}

// StalenessValue puts a staleness next to the tolerance that gates it:
// "12s behind (routes below 60s)" is actionable where a bare "12" is not.
//
// The number is the lag the mirror measured on ITSELF when it last
// advertised, not anything derived from this server's clock. The mirror
// advertises every few minutes but syncs continuously, so an aging
// advertisement is not a lagging mirror -- how old the reading is, is
// the "Last polled" row's job.
function StalenessValue({
  ok,
  okText,
  notOkText,
  seconds,
  tolerance,
}: {
  ok: boolean;
  okText: string;
  notOkText: string;
  seconds?: number;
  tolerance: number;
}) {
  if (seconds === undefined) {
    return (
      <span className="text-gray-500">
        unknown{' '}
        <span className="text-gray-400">(routes below {tolerance}s)</span>
      </span>
    );
  }
  const over = seconds > tolerance;
  return (
    <span className={over || !ok ? 'text-amber-700' : undefined}>
      {seconds.toLocaleString()}s behind when last advertised{' '}
      <span className="text-gray-400">(routes below {tolerance}s)</span>
      {!ok && notOkText ? ` — ${notOkText}` : ''}
      {ok && okText && !over ? ` — ${okText}` : ''}
    </span>
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
    queryKey: ["admin-condor-config"],
    queryFn: api.admin.condorConfig,
    // Config doesn't change at runtime; cache for the tab's lifetime.
    staleTime: Infinity,
    retry: false,
  });
  const [filter, setFilter] = useState("");
  // Default to hiding untouched parameters. A stock config carries on
  // the order of a thousand built-in defaults against a handful the
  // deployment actually set, so showing everything by default buries
  // the interesting rows in noise.
  const [modifiedOnly, setModifiedOnly] = useState(true);

  // Filter on every render — the entry count is a few thousand, the
  // user's filter text is short, substring match is cheap. Memoize
  // anyway so a re-render that didn't change the filter doesn't re-
  // walk the array.
  const filtered = useMemo(() => {
    if (!data?.entries) return [];
    const q = filter.trim().toLowerCase();
    return data.entries.filter((e) => {
      if (modifiedOnly && e.is_default) return false;
      if (!q) return true;
      return (
        e.key.toLowerCase().includes(q) ||
        (e.value ? e.value.toLowerCase().includes(q) : false)
      );
    });
  }, [data, filter, modifiedOnly]);

  const total = data?.entries?.length ?? 0;
  // Prefer the server's count: it is computed over the whole readout
  // rather than the current filter, so the label stays stable while
  // the user types.
  const modifiedCount = data?.modified_count ?? 0;

  return (
    <Section title="HTCondor configuration (admin)">
      <p className="text-xs text-gray-500 mb-3">
        Running config of this access point. Equivalent to{" "}
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
              className="flex-1 rounded-sm border border-gray-300 px-2 py-1 text-sm"
              aria-label="Filter HTCondor config"
            />
            <span className="text-[11px] text-gray-500 tabular-nums shrink-0">
              {`${filtered.length.toLocaleString()} / ${total.toLocaleString()}`}
            </span>
          </div>

          <label className="mb-2 flex items-center gap-2 text-xs text-gray-600">
            <input
              type="checkbox"
              checked={modifiedOnly}
              onChange={(e) => setModifiedOnly(e.target.checked)}
            />
            Only show values changed from their default
            <span className="text-gray-400">
              ({modifiedCount.toLocaleString()} of {total.toLocaleString()})
            </span>
          </label>

          {/* Inner scroll container caps the table height so the
              admin readout never displaces the rest of the page.
              Using max-h instead of h means short filtered results
              don't get a wasteful scrollbar. */}
          <div className="overflow-y-auto rounded-sm border border-gray-200 max-h-112">
            {filtered.length === 0 ? (
              <p className="px-3 py-3 text-xs text-gray-500">
                {modifiedOnly
                  ? "No matches among changed values — untick the box above to search the built-in defaults too."
                  : "No matches."}
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
                            className="rounded-sm bg-gray-200 px-1.5 py-0.5 text-[10px] uppercase tracking-wide text-gray-600"
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
        className={`text-gray-900 break-all ${mono ? "font-mono text-xs" : ""}`}
      >
        {value}
      </dd>
    </>
  );
}
