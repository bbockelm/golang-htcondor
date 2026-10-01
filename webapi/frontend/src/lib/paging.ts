// How many records a listing asks for in one request.
//
// One number for every listing, because they were set independently and
// drifted: /jobs and /users/<owner> asked for a thousand while /archive
// asked for a hundred, so the same access point felt fine on one page
// and slow on another.
//
// It is a page size, not a ceiling. Every listing that uses it fetches
// further pages -- by cursor where the backend offers one -- and says so
// when there is more than it has shown.
//
// The real ceiling is the server's, and it is bigger than this: a mirror
// read of projected rows is capped at dbmirror.MaxProjectedLimit. This
// stays well under it so a page is one round trip rather than a page
// plus a clamp nobody can see.
export const LISTING_PAGE_SIZE = 1000;
