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
