'use client';

// One section of the issues page -- Holds, or the run failures -- and the
// rows inside it.
//
// The reading order is the point. Biggest problem first, with its size
// shown as a bar relative to the biggest in the section (the question is
// "is this THE problem or one of five", which is a shape rather than a
// number), the number of distinct users beside the count, and one
// representative case expanded far enough to recognise without clicking:
// a masked template is what the occurrences have in common, not
// something anybody can act on.

import { useState } from 'react';
import Link from 'next/link';
import type { IssueCluster, IssueFacetSpread, IssueSection } from '@/lib/api';

export function IssueSectionPanel({ section }: { section: IssueSection }) {
  if (section.clusters.length === 0) return null;
  // Bars are relative to the biggest problem in this section, so the
  // shape of the section is readable whatever the absolute numbers.
  const largest = Math.max(...section.clusters.map((c) => c.count));
  return (
    <section className="space-y-2">
      <div className="flex items-baseline gap-3">
        <h2 className="text-lg font-semibold text-gray-900">{section.title}</h2>
        <span className="text-sm text-gray-500">
          {section.total.toLocaleString()} job
          {section.total === 1 ? '' : 's'}, {section.users.toLocaleString()} user
          {section.users === 1 ? '' : 's'}
        </span>
      </div>
      <div className="divide-y divide-gray-100 overflow-hidden rounded-lg border border-gray-200 bg-white">
        {section.clusters.map((cluster, i) => (
          <ClusterRow
            key={`${cluster.template}-${i}`}
            cluster={cluster}
            largest={largest}
          />
        ))}
      </div>
    </section>
  );
}

export function ClusterRow({
  cluster,
  largest,
}: {
  cluster: IssueCluster;
  largest: number;
}) {
  const [open, setOpen] = useState(false);
  const examples = cluster.examples ?? [];
  // The representative case: the newest occurrence belonging to whoever
  // this is mostly happening to. Shown unexpanded, because a template
  // with the detail masked out is not something you can act on.
  const lead = examples[0];
  const share = largest > 0 ? Math.max(2, (cluster.count / largest) * 100) : 0;

  const more = Math.max(0, examples.length - 1);

  return (
    <div className="px-3 py-3">
      <div className="flex items-start gap-3">
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
            <span className="text-base font-semibold tabular-nums text-gray-900">
              {cluster.count.toLocaleString()}
            </span>
            <span className="text-sm text-gray-500">
              job{cluster.count === 1 ? '' : 's'}
            </span>
            <UsersBadge users={cluster.users} topUsers={cluster.top_users} />
            {cluster.facets?.map((f) => (
              <FacetBadge key={f.name} facet={f} />
            ))}
            {cluster.codes?.slice(0, 2).map((c) => (
              <span
                key={`${c.code}.${c.subcode}`}
                className="rounded-full bg-gray-100 px-2 py-0.5 text-xs text-gray-600"
                title={`HoldReasonCode ${c.code}, subcode ${c.subcode}`}
              >
                {c.label || `code ${c.code}`}
              </span>
            ))}
            {cluster.last_seen ? (
              <span className="text-xs text-gray-400">
                last {new Date(cluster.last_seen * 1000).toLocaleString()}
              </span>
            ) : null}
          </div>

          {/* Relative size. A bar rather than a percentage because the
              question it answers is "is this the problem, or one of
              five", which is a shape not a number. */}
          <div className="mt-1.5 h-1.5 w-full max-w-md overflow-hidden rounded-full bg-gray-100">
            <div
              className="h-full rounded-full bg-brand-500"
              style={{ width: `${share}%` }}
            />
          </div>

          {lead ? (
            <p className="mt-2 break-words font-mono text-xs leading-relaxed text-gray-800">
              {lead.message}
            </p>
          ) : (
            <p className="mt-2 font-mono text-xs text-gray-500">
              {cluster.template}
            </p>
          )}

          <div className="mt-1.5 flex flex-wrap items-center gap-3 text-xs text-gray-500">
            {lead && (
              <>
                <Link
                  href={`/jobs/${lead.cluster_id}.${lead.proc_id}`}
                  className="font-mono text-brand-700 hover:underline"
                >
                  {lead.cluster_id}.{lead.proc_id}
                </Link>
                {lead.owner && (
                  <Link
                    href={`/users/${encodeURIComponent(lead.owner)}`}
                    className="rounded-full bg-indigo-100 px-2 py-0.5 font-medium text-indigo-800 hover:bg-indigo-200"
                  >
                    {lead.owner}
                  </Link>
                )}
              </>
            )}
            {(more > 0 || (cluster.variants?.length ?? 0) > 1) && (
              <button
                type="button"
                onClick={() => setOpen((v) => !v)}
                className="text-brand-700 hover:underline"
                aria-expanded={open}
              >
                {open ? 'show less' : `show ${more} more example${more === 1 ? '' : 's'}`}
              </button>
            )}
          </div>

          {open && <ClusterDetail cluster={cluster} examples={examples} />}
        </div>
      </div>
    </div>
  );
}

// FacetBadge says where a problem is happening.
//
// A cluster confined to one resource is that resource's problem however
// many users it reaches, and one spread over thirty is the pool's. That
// distinction is invisible in a job count and is the reason the page
// reads the structured attributes at all, so it gets the same treatment
// as the user count: called out when it is concentrated, stated plainly
// when it is not.
export function FacetBadge({ facet }: { facet: IssueFacetSpread }) {
  const concentrated = facet.distinct === 1 && !!facet.top?.length;
  const title = facet.top?.length
    ? facet.top.map((v) => `${v.value}: ${v.count}`).join('\n')
    : undefined;
  return (
    <span
      title={title}
      className={`rounded-full px-2 py-0.5 text-xs font-medium ${
        concentrated
          ? 'bg-sky-100 text-sky-900'
          : 'bg-gray-100 text-gray-600'
      }`}
    >
      {concentrated
        ? `all at ${facet.top![0].value}`
        : `${facet.distinct.toLocaleString()} ${facet.name}s`}
    </span>
  );
}

// UsersBadge is the number the page exists to put beside the count.
export function UsersBadge({
  users,
  topUsers,
}: {
  users: number;
  topUsers?: { owner: string; count: number }[];
}) {
  const title = topUsers?.length
    ? topUsers.map((u) => `${u.owner}: ${u.count}`).join('\n')
    : undefined;
  return (
    <span
      title={title}
      className={`rounded-full px-2 py-0.5 text-xs font-medium ${
        // One user is somebody's own problem; many is the pool's. The
        // colours say which without the reader doing arithmetic.
        users > 1 ? 'bg-amber-100 text-amber-900' : 'bg-gray-100 text-gray-600'
      }`}
    >
      {users.toLocaleString()} user{users === 1 ? '' : 's'}
    </span>
  );
}

function ClusterDetail({
  cluster,
  examples,
}: {
  cluster: IssueCluster;
  examples: NonNullable<IssueCluster['examples']>;
}) {
  return (
    <div className="mt-3 space-y-3 border-t border-gray-100 pt-3">
      {(cluster.variants?.length ?? 0) > 1 && (
        <div>
          <div className="text-[11px] uppercase tracking-wide text-gray-500">
            Folded together at this detail level
          </div>
          <ul className="mt-1 space-y-1">
            {cluster.variants!.map((v) => (
              <li key={v.template} className="font-mono text-[11px] text-gray-600">
                <span className="tabular-nums text-gray-900">{v.count}</span>{' '}
                {v.template}
              </li>
            ))}
          </ul>
        </div>
      )}

      {(cluster.facets?.length ?? 0) > 0 && (
        <div className="space-y-1">
          {cluster.facets!.map((f) => (
            <div key={f.name} className="flex flex-wrap items-center gap-2">
              <span className="text-[11px] uppercase tracking-wide text-gray-500">
                {f.name}
                {f.distinct > (f.top?.length ?? 0) ? ` (${f.distinct})` : ''}
              </span>
              {f.top?.map((v) => (
                <span
                  key={v.value}
                  className="rounded-full bg-sky-50 px-2 py-0.5 text-xs text-sky-900"
                >
                  {v.value} <span className="tabular-nums">{v.count}</span>
                </span>
              ))}
            </div>
          ))}
        </div>
      )}

      {(cluster.top_users?.length ?? 0) > 0 && (
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-[11px] uppercase tracking-wide text-gray-500">
            Most affected
          </span>
          {cluster.top_users!.map((u) => (
            <Link
              key={u.owner}
              href={`/users/${encodeURIComponent(u.owner)}`}
              className="rounded-full bg-indigo-100 px-2 py-0.5 text-xs font-medium text-indigo-800 hover:bg-indigo-200"
            >
              {u.owner} <span className="tabular-nums">{u.count}</span>
            </Link>
          ))}
        </div>
      )}

      <div>
        <div className="text-[11px] uppercase tracking-wide text-gray-500">
          Example jobs
        </div>
        <ul className="mt-1 divide-y divide-gray-100">
          {examples.slice(1).map((ex) => (
            <li key={`${ex.cluster_id}.${ex.proc_id}-${ex.at ?? 0}`} className="py-1.5">
              <div className="flex flex-wrap items-baseline gap-2 text-xs">
                <Link
                  href={`/jobs/${ex.cluster_id}.${ex.proc_id}`}
                  className="font-mono text-brand-700 hover:underline"
                >
                  {ex.cluster_id}.{ex.proc_id}
                </Link>
                {ex.owner && <span className="text-gray-600">{ex.owner}</span>}
                {ex.batch && <span className="text-gray-400">{ex.batch}</span>}
                {ex.at ? (
                  <span className="text-gray-400">
                    {new Date(ex.at * 1000).toLocaleString()}
                  </span>
                ) : null}
              </div>
              {ex.message && (
                <p className="mt-0.5 break-words font-mono text-[11px] leading-relaxed text-gray-600">
                  {ex.message}
                </p>
              )}
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}
