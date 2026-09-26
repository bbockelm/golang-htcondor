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
import { Sparkline, sparklineLabel } from '@/components/Sparkline';

export function IssueSectionPanel({
  section,
  bucketSeconds,
  endsAt,
}: {
  section: IssueSection;
  // The window's shape, passed to every row so the sparklines share one
  // axis.
  bucketSeconds?: number;
  endsAt?: number;
}) {
  if (section.clusters.length === 0) return null;
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
            bucketSeconds={bucketSeconds}
            endsAt={endsAt}
          />
        ))}
      </div>
    </section>
  );
}

export function ClusterRow({
  cluster,
  bucketSeconds,
  endsAt,
}: {
  cluster: IssueCluster;
  bucketSeconds?: number;
  endsAt?: number;
}) {
  const [open, setOpen] = useState(false);
  const examples = cluster.examples ?? [];
  // The representative case: the newest occurrence belonging to whoever
  // this is mostly happening to. Shown unexpanded, because a template
  // with the detail masked out is not something you can act on.
  const lead = examples[0];
  const more = Math.max(0, examples.length - 1);
  const timeline = cluster.timeline ?? [];

  return (
    <div className="px-3 py-3">
      <div className="flex items-start gap-4">
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
            <span className="text-base font-semibold tabular-nums text-gray-900">
              {cluster.count.toLocaleString()}
            </span>
            <span className="text-sm text-gray-500">
              job{cluster.count === 1 ? '' : 's'}
            </span>
            <UsersBadge users={cluster.users} topUsers={cluster.top_users} />
            {visibleFacets(cluster.facets).map((f) => (
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

          {/* The example's own words when it has any. A record can
              reach here with an empty message -- a hold with no reason
              text -- and rendering that drew a row with nothing where
              the problem should be, which reads as a rendering fault
              rather than as an absence. The template at least names the
              shape of the thing. */}
          {lead?.message ? (
            <p className="mt-1.5 break-words font-mono text-xs leading-relaxed text-gray-800">
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

        {/* Right of the text rather than under it: down a list of rows
            it becomes a column, which is what makes one problem's shape
            comparable with the next one's. */}
        {timeline.length > 0 && (
          <div className="hidden shrink-0 pt-1 sm:block">
            <Sparkline
              counts={timeline}
              bucketSeconds={bucketSeconds}
              endsAt={endsAt}
              label={sparklineLabel(timeline, bucketSeconds, endsAt)}
            />
            <div className="mt-0.5 flex justify-between text-[10px] text-gray-400">
              <span>{spanLabel(timeline.length, bucketSeconds)}</span>
              <span>now</span>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

// spanLabel is the left end of the sparkline's axis -- the only chrome
// it gets. Without it the shape is legible but its extent is not, and
// "a burst at the left edge" means something different over an hour
// than over a week.
function spanLabel(buckets: number, bucketSeconds?: number): string {
  if (!bucketSeconds) return '';
  const seconds = buckets * bucketSeconds;
  if (seconds < 90 * 60) return `${Math.round(seconds / 60)}m ago`;
  if (seconds < 48 * 3600) return `${Math.round(seconds / 3600)}h ago`;
  return `${Math.round(seconds / 86400)}d ago`;
}

// visibleFacets drops a location whose name is already contained in a
// more specific one beside it.
//
// OSPool names a resource after its site most of the time, so a row
// reporting both reads "MTState-Tempest-CE1  MTState-Tempest" -- the
// same place twice, the second time less precisely. Where the names are
// genuinely different (IU-Jetstream2-Backfill at Pervasive Technology
// Institute) both are kept, because then the second one is telling you
// something.
//
// Only applied between concentrated facets: "9 sites" and "14
// resources" are two different counts and neither contains the other.
export function visibleFacets(
  facets: IssueFacetSpread[] | undefined,
): IssueFacetSpread[] {
  if (!facets?.length) return [];
  const valueOf = (f: IssueFacetSpread) =>
    f.distinct === 1 && f.top?.length ? f.top[0].value : '';
  return facets.filter((f) => {
    const mine = valueOf(f);
    if (!mine) return true;
    return !facets.some((other) => {
      const theirs = valueOf(other);
      return theirs !== '' && theirs !== mine && theirs.includes(mine);
    });
  });
}

// FacetBadge says where a problem is happening.
//
// A cluster confined to one resource is that resource's problem however
// many users it reaches, and one spread over thirty is the pool's. That
// distinction is invisible in a job count and is the reason the page
// reads the structured attributes at all.
//
// The colour carries "this is a place" so the words do not have to. An
// earlier version wrote "all at MTState-Tempest", which spends four
// words on what the badge's presence already says and reads as a
// sentence fragment next to the pills around it; the name alone is how
// a place is normally written down. Both states wear the same hue for
// the same reason -- a reader scanning the column should not have to
// re-read to tell a location from a status.
export function FacetBadge({ facet }: { facet: IssueFacetSpread }) {
  const concentrated = facet.distinct === 1 && !!facet.top?.length;
  // The facet's name is in the tooltip rather than on the chip: "site"
  // and "resource" are the page's words, not the reader's, and the
  // values are self-describing.
  const detail = facet.top?.length
    ? facet.top.map((v) => `${v.value}: ${v.count}`).join('\n')
    : '';
  return (
    <span
      title={`${facet.name}\n${detail}`}
      className={`rounded-full px-2 py-0.5 text-xs font-medium ${
        concentrated ? 'bg-sky-100 text-sky-900' : 'bg-sky-50 text-sky-800'
      }`}
    >
      {concentrated
        ? facet.top![0].value
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
