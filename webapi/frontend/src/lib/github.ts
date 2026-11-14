// Reading GitHub from the browser.
//
// Everything the publish form needs to know about a repository --
// whether it exists, what it has released, and what is attached to a
// release -- is answered here, from the page. GitHub serves
// api.github.com with `Access-Control-Allow-Origin: *`, so a page may
// read all of it directly.
//
// What the page may NOT read is the release asset itself: the download
// redirects to release-assets.githubusercontent.com, which sends no
// CORS headers at all. So the bytes are fetched by the access point
// while the questions about them are answered here. The split is
// forced by GitHub, not chosen.
//
// Nothing here is a security control. The server parses the same
// repository, resolves the same release and picks the same asset
// again, and its answer is the one that decides what gets installed.
// This exists so that an administrator finds out they have mistyped a
// repository while they are typing it, rather than after a minute of
// waiting on a fetch that was never going to work.

/** A repository, split the way GitHub's API addresses one. */
export interface RepoRef {
  owner: string;
  repo: string;
}

// The server's rules -- githubOwnerPattern and githubRepoPattern --
// mirrored. Being stricter here than the server is would refuse a
// repository that works; being looser only costs a request that comes
// back 404.
const OWNER = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/;
const REPO = /^[A-Za-z0-9._-]{1,100}$/;

/**
 * Read a repository out of whatever was typed or pasted.
 *
 * Accepts `owner/name`, and also the browser URL of the repository,
 * because pasting that is what someone does when they have the
 * repository open in another tab. Returns null for anything that is
 * not yet a repository, including a half-typed one.
 */
export function parseRepoRef(raw: string): RepoRef | null {
  let slug = raw.trim();
  for (const prefix of ['https://github.com/', 'http://github.com/', 'github.com/']) {
    if (slug.startsWith(prefix)) {
      slug = slug.slice(prefix.length);
      break;
    }
  }
  // A pasted URL may carry the rest of the page with it:
  // /tree/main, /releases/tag/v1, a query, a fragment.
  slug = slug.split(/[?#]/, 1)[0];
  slug = slug.replace(/\/+$/, '');
  if (slug.toLowerCase().endsWith('.git')) slug = slug.slice(0, -4);
  const parts = slug.split('/');
  if (parts.length < 2) return null;
  const [owner, repo] = parts;
  if (!OWNER.test(owner) || !REPO.test(repo) || repo === '.' || repo === '..') return null;
  return { owner, repo };
}

/** `owner/name`, which is how a repository is written everywhere else. */
export function repoSlug(r: RepoRef): string {
  return `${r.owner}/${r.repo}`;
}

/** A file attached to a release. */
export interface ReleaseAsset {
  name: string;
  size: number;
}

/** A published release, as this page needs it. */
export interface Release {
  /** The tag, exactly as the release carries it. */
  tag: string;
  /** The release's title, which is often the tag again. */
  name: string;
  prerelease: boolean;
  /** RFC 3339, or '' where GitHub did not say. */
  publishedAt: string;
  /** The release page, for a link that can be checked. */
  url: string;
  assets: ReleaseAsset[];
}

/**
 * What a listing can come back as.
 *
 * The failures are kept apart because they call for different words.
 * A repository that does not exist is a typo and the administrator can
 * fix it; a rate limit or an unreachable GitHub is not their mistake
 * and must not read like one -- in both of those cases the server may
 * well still be able to fetch the release, so the form has to let them
 * carry on by hand rather than stand in the way.
 */
export type ReleasesResult =
  | { ok: true; releases: Release[] }
  | { ok: false; reason: 'no-repo' | 'rate-limited' | 'unreachable' };

/** How many releases to list. A drop-down is not a history. */
const RELEASE_PAGE = 100;

/**
 * List a repository's published releases, newest first.
 *
 * Draft releases are absent because GitHub does not show them to an
 * anonymous reader, which is what this is: no credentials are sent,
 * deliberately. The viewer's GitHub cookies have no business on a read
 * made by an access point's admin page, and a private repository that
 * only the viewer can see is one the server could not fetch anyway.
 */
export async function listReleases(
  ref: RepoRef,
  fetchImpl: typeof fetch = fetch,
  signal?: AbortSignal,
): Promise<ReleasesResult> {
  let res: Response;
  try {
    res = await fetchImpl(
      `https://api.github.com/repos/${ref.owner}/${ref.repo}/releases?per_page=${RELEASE_PAGE}`,
      { headers: { Accept: 'application/vnd.github+json' }, credentials: 'omit', signal },
    );
  } catch {
    return { ok: false, reason: 'unreachable' };
  }
  if (!res.ok) {
    if (res.status === 404) return { ok: false, reason: 'no-repo' };
    // GitHub answers an exhausted anonymous quota with 403, and 429
    // under a secondary limit. 60 an hour per address is not many when
    // several people administer one pool from one campus.
    if (res.status === 403 || res.status === 429) return { ok: false, reason: 'rate-limited' };
    return { ok: false, reason: 'unreachable' };
  }
  let body: unknown;
  try {
    body = await res.json();
  } catch {
    return { ok: false, reason: 'unreachable' };
  }
  if (!Array.isArray(body)) return { ok: false, reason: 'unreachable' };
  const releases: Release[] = [];
  for (const raw of body) {
    const rel = readRelease(raw);
    if (rel) releases.push(rel);
  }
  return { ok: true, releases };
}

// readRelease takes the one release shape this page uses out of
// GitHub's much larger one, and drops anything that does not have the
// part everything else is keyed on. A release with no tag cannot be
// installed and cannot be named in a drop-down.
function readRelease(raw: unknown): Release | null {
  if (typeof raw !== 'object' || raw === null) return null;
  const r = raw as Record<string, unknown>;
  if (r.draft === true) return null;
  const tag = typeof r.tag_name === 'string' ? r.tag_name : '';
  if (tag === '') return null;
  const assets: ReleaseAsset[] = [];
  if (Array.isArray(r.assets)) {
    for (const a of r.assets) {
      if (typeof a !== 'object' || a === null) continue;
      const { name, size } = a as Record<string, unknown>;
      if (typeof name !== 'string' || name === '') continue;
      assets.push({ name, size: typeof size === 'number' ? size : 0 });
    }
  }
  return {
    tag,
    name: typeof r.name === 'string' && r.name !== '' ? r.name : tag,
    prerelease: r.prerelease === true,
    publishedAt: typeof r.published_at === 'string' ? r.published_at : '',
    url:
      typeof r.html_url === 'string' && r.html_url !== ''
        ? r.html_url
        : 'https://github.com',
    assets,
  };
}

/**
 * Which bundle a release offers, and whether it comes attested.
 *
 * This is the server's pickGitHubAssets, mirrored: with nothing named,
 * exactly one `.zip` is required rather than the first one found,
 * because a release carrying two bundles is a release where guessing
 * installs the wrong app under the name chosen for the other one.
 *
 * Mirrored so that the form can show the choice BEFORE the install --
 * the server's version of this answers with a 400 after the release
 * has been resolved, which is a slow way to learn that a drop-down was
 * needed.
 */
export type AssetChoice =
  | { ok: true; asset: string; attested: boolean }
  | { ok: false; problem: string; choices: string[] };

export function pickBundleAsset(rel: Release, want?: string): AssetChoice {
  const named = (want ?? '').trim();
  if (named !== '') {
    const found = rel.assets.find((a) => a.name === named);
    if (found) return { ok: true, asset: found.name, attested: hasSidecar(rel, found.name) };
    return {
      ok: false,
      problem: `${rel.tag} has no asset named ${named}.`,
      choices: rel.assets.map((a) => a.name),
    };
  }
  const zips = rel.assets.filter((a) => a.name.toLowerCase().endsWith('.zip'));
  if (zips.length === 1) {
    return { ok: true, asset: zips[0].name, attested: hasSidecar(rel, zips[0].name) };
  }
  if (zips.length === 0) {
    return {
      ok: false,
      problem: `${rel.tag} has no .zip attached, so there is no bundle to install.`,
      choices: [],
    };
  }
  return {
    ok: false,
    problem: `${rel.tag} attaches more than one bundle. Choose the one to install.`,
    choices: zips.map((a) => a.name),
  };
}

// A bundle is attested when the release publishes its checksum beside
// it under exactly that name, which is the file the server reads.
function hasSidecar(rel: Release, bundle: string): boolean {
  return rel.assets.some((a) => a.name === `${bundle}.sha256`);
}

/**
 * A repository's current release, as GitHub reports it.
 */
export interface LatestRelease {
  /** The tag, exactly as the release carries it. */
  tag: string;
  /** The release page, for a link the administrator can check. */
  url: string;
}

/**
 * Ask GitHub which release a repository is currently on.
 *
 * Returns null on any failure, deliberately. This decorates a listing
 * that is already correct and complete; GitHub being unreachable, rate
 * limiting the viewer's address, or having deleted the repository are
 * all reasons to show no badge, never reasons to show an error on a
 * page about something else.
 */
export async function latestRelease(
  repo: string,
  fetchImpl: typeof fetch = fetch,
): Promise<LatestRelease | null> {
  // Exactly `owner/name`, not the looser thing the form accepts. What
  // reaches here is a repository the server recorded when it installed
  // the app, so anything else is a sign the provenance is not what
  // this thinks it is -- and the answer to that is no badge, not a
  // request built out of a guess at which part was the repository.
  const ref = parseRepoRef(repo);
  if (!ref || repo.trim() !== repoSlug(ref)) return null;
  try {
    const res = await fetchImpl(
      `https://api.github.com/repos/${ref.owner}/${ref.repo}/releases/latest`,
      { headers: { Accept: 'application/vnd.github+json' }, credentials: 'omit' },
    );
    if (!res.ok) return null;
    const body: unknown = await res.json();
    if (typeof body !== 'object' || body === null) return null;
    const { tag_name: tag, html_url: url } = body as { tag_name?: unknown; html_url?: unknown };
    if (typeof tag !== 'string' || tag === '') return null;
    return {
      tag,
      url: typeof url === 'string' ? url : `https://github.com/${repoSlug(ref)}/releases`,
    };
  } catch {
    return null;
  }
}

/**
 * Whether the release a repository is on now differs from the one
 * installed.
 *
 * DIFFERENT, not newer. Comparing versions properly means knowing the
 * scheme a project tags with, and guessing it wrong tells an
 * administrator their up-to-date app is stale. A site that pinned an
 * older tag on purpose is told what the current release is and decides
 * for itself.
 *
 * A leading `v` is ignored on both sides: `v0.2` and `0.2` are one
 * release written two ways, and a badge that fired on that difference
 * would never go away.
 */
export function releaseDiffers(installed?: string, latest?: string): boolean {
  const norm = (s?: string) => (s ?? '').trim().replace(/^v/i, '').toLowerCase();
  const a = norm(installed);
  const b = norm(latest);
  if (a === '' || b === '') return false;
  return a !== b;
}
