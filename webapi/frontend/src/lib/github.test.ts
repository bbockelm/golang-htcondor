import { describe, expect, it, vi } from 'vitest';
import {
  listReleases,
  parseRepoRef,
  pickBundleAsset,
  type Release,
  latestRelease,
  releaseDiffers,
} from './github';

describe('releaseDiffers', () => {
  it('says so when the repository has moved on', () => {
    expect(releaseDiffers('v0.1', 'v0.2')).toBe(true);
  });

  it('is quiet when the installed release is the current one', () => {
    expect(releaseDiffers('v0.2', 'v0.2')).toBe(false);
  });

  it('treats v0.2 and 0.2 as one release written two ways', () => {
    // The release workflow stamps the version without the v and tags
    // with it. A badge that fired on that difference would be
    // permanent, and a permanent badge is ignored.
    expect(releaseDiffers('v0.2', '0.2')).toBe(false);
    expect(releaseDiffers('0.2', 'v0.2')).toBe(false);
    expect(releaseDiffers('V0.2', 'v0.2')).toBe(false);
  });

  it('says nothing when either side is unknown', () => {
    // An app uploaded as a file has no installed ref, and a
    // repository with no releases gives no tag. Neither is news.
    expect(releaseDiffers(undefined, 'v0.2')).toBe(false);
    expect(releaseDiffers('v0.1', undefined)).toBe(false);
    expect(releaseDiffers('', '')).toBe(false);
    expect(releaseDiffers('  ', 'v0.2')).toBe(false);
  });

  it('does not try to decide which release is newer', () => {
    // Deliberately symmetric. Working out that v0.10 follows v0.9
    // means knowing the project's scheme, and guessing it wrong tells
    // a site its current app is stale.
    expect(releaseDiffers('v0.10', 'v0.9')).toBe(true);
    expect(releaseDiffers('v0.9', 'v0.10')).toBe(true);
  });
});

describe('latestRelease', () => {
  const ok = (body: unknown) =>
    (async () =>
      ({ ok: true, json: async () => body }) as Response) as unknown as typeof fetch;

  it('reads the tag and the release page', async () => {
    const got = await latestRelease(
      'bbockelm/htcondor-site-app-template',
      ok({ tag_name: 'v0.2', html_url: 'https://github.com/o/r/releases/tag/v0.2' }),
    );
    expect(got).toEqual({ tag: 'v0.2', url: 'https://github.com/o/r/releases/tag/v0.2' });
  });

  it('is silent rather than noisy when GitHub will not answer', async () => {
    // A rate limit is the common case: 60 requests an hour per
    // address, shared with every other tab. It must not put an error
    // on a page about something else.
    const rateLimited = (async () => ({ ok: false, status: 403 }) as Response) as unknown as typeof fetch;
    expect(await latestRelease('o/r', rateLimited)).toBeNull();

    const broken = (async () => {
      throw new TypeError('Failed to fetch');
    }) as unknown as typeof fetch;
    expect(await latestRelease('o/r', broken)).toBeNull();
  });

  it('refuses to build a URL out of something that is not a repository', async () => {
    // Nothing should reach the network for these at all.
    let called = false;
    const spy = (async () => {
      called = true;
      return { ok: true, json: async () => ({ tag_name: 'v1' }) } as Response;
    }) as unknown as typeof fetch;
    for (const bad of ['', 'owner', 'owner/repo/extra', '../../etc', 'o r/repo']) {
      expect(await latestRelease(bad, spy)).toBeNull();
    }
    expect(called).toBe(false);
  });

  it('survives an answer that is not the shape it expects', async () => {
    expect(await latestRelease('o/r', ok({}))).toBeNull();
    expect(await latestRelease('o/r', ok(null))).toBeNull();
    expect(await latestRelease('o/r', ok({ tag_name: 42 }))).toBeNull();
    expect(await latestRelease('o/r', ok({ tag_name: '' }))).toBeNull();
  });

  it('falls back to the releases page when no page is named', async () => {
    const got = await latestRelease('o/r', ok({ tag_name: 'v3' }));
    expect(got).toEqual({ tag: 'v3', url: 'https://github.com/o/r/releases' });
  });
});

describe('reading a repository out of what was typed', () => {
  it('takes owner/name', () => {
    expect(parseRepoRef('bbockelm/htcondor-site-app-template')).toEqual({
      owner: 'bbockelm',
      repo: 'htcondor-site-app-template',
    });
  });

  it('takes the URL of the repository, because that is what gets pasted', () => {
    const want = { owner: 'bbockelm', repo: 'htcondor-site-app-template' };
    for (const typed of [
      'https://github.com/bbockelm/htcondor-site-app-template',
      'https://github.com/bbockelm/htcondor-site-app-template/',
      'https://github.com/bbockelm/htcondor-site-app-template.git',
      'github.com/bbockelm/htcondor-site-app-template',
      '  bbockelm/htcondor-site-app-template  ',
    ]) {
      expect(parseRepoRef(typed), typed).toEqual(want);
    }
  });

  it('takes a URL that carries the rest of the page with it', () => {
    // Copied from the address bar while looking at the releases.
    expect(parseRepoRef('https://github.com/acme/demos/releases/tag/v1.9')).toEqual({
      owner: 'acme',
      repo: 'demos',
    });
    expect(parseRepoRef('https://github.com/acme/demos?tab=readme')).toEqual({
      owner: 'acme',
      repo: 'demos',
    });
  });

  it('says nothing about something that is not a repository yet', () => {
    // Half-typed is the usual state of this box, and it is not an
    // error: it is somebody still typing.
    for (const typed of ['', '  ', 'bbockelm', 'bbockelm/', '/demos', '../../etc/passwd']) {
      expect(parseRepoRef(typed), typed).toBeNull();
    }
  });

  it('refuses an owner or a name GitHub could not have', () => {
    expect(parseRepoRef('has space/demos')).toBeNull();
    expect(parseRepoRef('-leading/demos')).toBeNull();
    expect(parseRepoRef('acme/..')).toBeNull();
    expect(parseRepoRef(`acme/${'x'.repeat(101)}`)).toBeNull();
  });
});

describe('listing a repository’s releases', () => {
  const answer = (status: number, body: unknown) =>
    (async () =>
      ({
        ok: status >= 200 && status < 300,
        status,
        json: async () => body,
      }) as Response) as unknown as typeof fetch;

  const ref = { owner: 'acme', repo: 'demos' };

  it('reads the tag, the title and what is attached', async () => {
    const got = await listReleases(
      ref,
      answer(200, [
        {
          tag_name: 'v1.9',
          name: 'Ninth',
          prerelease: false,
          published_at: '2026-11-14T12:00:00Z',
          html_url: 'https://github.com/acme/demos/releases/tag/v1.9',
          assets: [
            { name: 'demos.zip', size: 4096 },
            { name: 'demos.zip.sha256', size: 64 },
          ],
        },
      ]),
    );
    expect(got).toEqual({
      ok: true,
      releases: [
        {
          tag: 'v1.9',
          name: 'Ninth',
          prerelease: false,
          publishedAt: '2026-11-14T12:00:00Z',
          url: 'https://github.com/acme/demos/releases/tag/v1.9',
          assets: [
            { name: 'demos.zip', size: 4096 },
            { name: 'demos.zip.sha256', size: 64 },
          ],
        },
      ],
    });
  });

  it('asks without credentials', async () => {
    // The viewer's GitHub cookies have no business on a read made by
    // an access point's admin page, and a repository only they can
    // see is one the server could not fetch anyway.
    const fetchImpl = vi.fn(
      async () => ({ ok: true, status: 200, json: async () => [] }) as Response,
    ) as unknown as typeof fetch;
    await listReleases(ref, fetchImpl);
    const [url, init] = (fetchImpl as unknown as { mock: { calls: [string, RequestInit][] } }).mock
      .calls[0];
    expect(url).toContain('https://api.github.com/repos/acme/demos/releases');
    expect(init.credentials).toBe('omit');
  });

  it('tells a repository that is not there apart from GitHub not answering', async () => {
    // These call for different words: one is a typo the administrator
    // can fix, and the other is not their mistake at all.
    expect(await listReleases(ref, answer(404, {}))).toEqual({ ok: false, reason: 'no-repo' });
    expect(await listReleases(ref, answer(403, {}))).toEqual({
      ok: false,
      reason: 'rate-limited',
    });
    expect(await listReleases(ref, answer(429, {}))).toEqual({
      ok: false,
      reason: 'rate-limited',
    });
    expect(await listReleases(ref, answer(500, {}))).toEqual({
      ok: false,
      reason: 'unreachable',
    });
  });

  it('treats an unreachable GitHub as unreachable, not as an empty repository', async () => {
    // A repository with no releases and a network that refused the
    // question look the same to a drop-down, and must not: the first
    // means there is nothing to install, the second means ask again.
    const boom = (async () => {
      throw new TypeError('Failed to fetch');
    }) as unknown as typeof fetch;
    expect(await listReleases(ref, boom)).toEqual({ ok: false, reason: 'unreachable' });
  });

  it('survives an answer that is not the shape it expects', async () => {
    expect(await listReleases(ref, answer(200, { releases: [] }))).toEqual({
      ok: false,
      reason: 'unreachable',
    });
    // A release with no tag cannot be installed and cannot be named
    // in a drop-down, so it is dropped rather than shown blank.
    expect(await listReleases(ref, answer(200, [{ name: 'no tag' }, 7, null]))).toEqual({
      ok: true,
      releases: [],
    });
  });

  it('leaves out a draft, and falls back to the tag for a release with no title', async () => {
    const got = await listReleases(
      ref,
      answer(200, [
        { tag_name: 'v2', draft: true, assets: [] },
        { tag_name: 'v1', prerelease: true, assets: [] },
      ]),
    );
    expect(got.ok && got.releases.map((r) => r.tag)).toEqual(['v1']);
    expect(got.ok && got.releases[0].name).toBe('v1');
    expect(got.ok && got.releases[0].prerelease).toBe(true);
  });
});

describe('choosing the bundle in a release', () => {
  // These are the server's cases -- pickGitHubAssets -- asked of the
  // mirror, because the two answering differently is the one way this
  // can be worse than not checking at all.
  const rel = (...names: string[]): Release => ({
    tag: 'v1.9',
    name: 'v1.9',
    prerelease: false,
    publishedAt: '',
    url: '',
    assets: names.map((name) => ({ name, size: 1 })),
  });

  it('takes the only .zip, and notices its checksum', () => {
    expect(pickBundleAsset(rel('demos.zip', 'demos.zip.sha256', 'notes.txt'))).toEqual({
      ok: true,
      asset: 'demos.zip',
      attested: true,
    });
  });

  it('says a bundle with no checksum beside it is unattested', () => {
    expect(pickBundleAsset(rel('demos.zip'))).toEqual({
      ok: true,
      asset: 'demos.zip',
      attested: false,
    });
  });

  it('refuses to guess between two bundles, and offers them', () => {
    // Guessing installs the wrong app under the name chosen for the
    // other one, silently.
    const got = pickBundleAsset(rel('demos.zip', 'tools.zip'));
    expect(got.ok).toBe(false);
    expect(!got.ok && got.choices).toEqual(['demos.zip', 'tools.zip']);
    expect(!got.ok && got.problem).toContain('more than one');
  });

  it('says when a release has no bundle at all', () => {
    const got = pickBundleAsset(rel('notes.txt'));
    expect(got.ok).toBe(false);
    expect(!got.ok && got.problem).toContain('no .zip');
    expect(!got.ok && got.choices).toEqual([]);
  });

  it('takes the asset that was named, whatever it is called', () => {
    // The server matches the name exactly rather than by suffix.
    expect(pickBundleAsset(rel('a.zip', 'b.zip', 'b.zip.sha256'), 'b.zip')).toEqual({
      ok: true,
      asset: 'b.zip',
      attested: true,
    });
  });

  it('says so when the named asset is not in the release', () => {
    const got = pickBundleAsset(rel('demos.zip'), 'missing.zip');
    expect(got.ok).toBe(false);
    expect(!got.ok && got.problem).toContain('no asset named missing.zip');
    expect(!got.ok && got.choices).toEqual(['demos.zip']);
  });
});
