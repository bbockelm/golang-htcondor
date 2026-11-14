// What a site app's id and group list may be.
//
// These rules are the server's -- siteapps.ValidateID and
// siteapps.ParseGroupList -- mirrored so the publish form can refuse a
// value before the bundle goes up. A bundle is megabytes; learning
// from a 400 that a capital letter is not allowed is a slow way to be
// told. Being wrong in either direction is worse than not checking at
// all, so they are kept narrow and tested against the same cases the
// Go side states.
//
// They live here rather than in the page because a Next.js page module
// may export nothing but the component and its route configuration.

// An id becomes a URL path segment and a file name, which is what
// bounds its length and its alphabet.
export const MAX_SITE_APP_ID = 64;

// EVERYONE is the group list that means every authenticated user, as
// the configuration writes it.
export const EVERYONE = '*';

export function validateSiteAppID(raw: string): string | null {
  const id = raw.trim();
  if (!id) {
    return 'Give the app an id. It is the bundle file name without .zip, and the path it is served at.';
  }
  if (id.length > MAX_SITE_APP_ID) {
    return `An id may be at most ${MAX_SITE_APP_ID} characters.`;
  }
  if (id.startsWith('_')) {
    return 'An id beginning with an underscore is reserved for this server’s own paths under /site/.';
  }
  if (!/^[a-z0-9]/.test(id) || !/[a-z0-9]$/.test(id)) {
    return 'An id must begin and end with a lowercase letter or digit.';
  }
  const bad = Array.from(id).find((c) => !/[a-z0-9_-]/.test(c));
  if (bad !== undefined) {
    return `An id may use only lowercase letters, digits, hyphen and underscore; ${JSON.stringify(bad)} is not one of them.`;
  }
  return null;
}

// parseGroupList splits a group list the way the configuration does:
// commas separate, surrounding whitespace is trimmed, and an empty
// entry is dropped rather than becoming a group named "".
export function parseGroupList(raw: string): string[] {
  return raw
    .split(',')
    .map((g) => g.trim())
    .filter((g) => g !== '');
}

// nearestSiteAppID answers the question behind a reported mistake: an
// administrator meaning to replace `demos` typed `demo`, and got a
// second app rather than a new version of the first one. Nothing was
// wrong with the upload -- `demo` is a perfectly good id -- so nothing
// complained, and the two apps sat side by side.
//
// Publishing a new app and replacing an existing one are different
// acts, and the form now asks which one is meant. This is the second
// line: if a NEW id is one or two characters away from one already
// published, say so before the bundle goes up.
//
// Returns the closest existing id, or null when nothing is close.
// Deliberately NOT a refusal: `demo` and `demos` may both be real.
export function nearestSiteAppID(typed: string, existing: readonly string[]): string | null {
  const id = typed.trim().toLowerCase();
  if (!id) return null;
  let best: string | null = null;
  let bestD = Infinity;
  for (const other of existing) {
    const o = other.toLowerCase();
    // An exact match is a collision, not a near miss. The caller has
    // to refuse that outright, and saying "did you mean X" about X
    // itself would be nonsense.
    if (o === id) return null;
    const d = editDistance(id, o);
    // Two edits, and never more than half the shorter name: at that
    // rate `cms` and `atlas` would be neighbours.
    if (d > 2 || d * 2 > Math.min(id.length, o.length)) continue;
    // Ties resolve by name so the answer does not depend on the order
    // the server happened to list the apps in.
    if (d < bestD || (d === bestD && best !== null && other < best)) {
      best = other;
      bestD = d;
    }
  }
  return best;
}

/** Levenshtein distance, two rows at a time. */
function editDistance(a: string, b: string): number {
  if (a === b) return 0;
  if (!a.length || !b.length) return a.length || b.length;
  let prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    const row = [i];
    for (let j = 1; j <= b.length; j++) {
      row[j] = Math.min(
        prev[j] + 1,
        row[j - 1] + 1,
        prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1),
      );
    }
    prev = row;
  }
  return prev[b.length];
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
 * This runs in the BROWSER, not on the access point, and that split is
 * forced rather than chosen. GitHub serves api.github.com with
 * `Access-Control-Allow-Origin: *`, so a page may read release
 * metadata directly; it does not serve the release ASSET that way --
 * the download redirects to release-assets.githubusercontent.com,
 * which sends no CORS headers at all. So the question "is there a
 * newer one?" is answered here for free, while fetching the bundle has
 * to go through the server.
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
  if (!/^[A-Za-z0-9][A-Za-z0-9-]{0,38}\/[A-Za-z0-9._-]{1,100}$/.test(repo)) return null;
  try {
    const res = await fetchImpl(`https://api.github.com/repos/${repo}/releases/latest`, {
      headers: { Accept: 'application/vnd.github+json' },
      // No credentials: this is a public read, and the viewer's
      // GitHub cookies have no business on it.
      credentials: 'omit',
    });
    if (!res.ok) return null;
    const body: unknown = await res.json();
    if (typeof body !== 'object' || body === null) return null;
    const { tag_name: tag, html_url: url } = body as { tag_name?: unknown; html_url?: unknown };
    if (typeof tag !== 'string' || tag === '') return null;
    return { tag, url: typeof url === 'string' ? url : `https://github.com/${repo}/releases` };
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
