import { describe, expect, it } from 'vitest';
import { latestRelease, nearestSiteAppID, releaseDiffers } from './siteapps';

describe('catching an id that was meant to be another one', () => {
  // The reported mistake, exactly: meaning to replace `demos`, an
  // administrator typed `demo` and got a second app. Both ids are
  // valid, so nothing refused it and nothing said anything.
  const published = ['demos', 'cryoem', 'seq-qc', 'atlas-analysis'];

  it('finds the one that was probably meant', () => {
    expect(nearestSiteAppID('demo', published)).toBe('demos');
    expect(nearestSiteAppID('cryoem2', published)).toBe('cryoem');
    expect(nearestSiteAppID('seq-qd', published)).toBe('seq-qc');
  });

  it('says nothing about an id that is simply new', () => {
    // A question asked about every unfamiliar name is a question
    // nobody reads by the third app.
    expect(nearestSiteAppID('folding', published)).toBeNull();
    expect(nearestSiteAppID('gromacs', published)).toBeNull();
  });

  it('says nothing about an exact match, which is a different problem', () => {
    // "Did you mean cryoem?" about cryoem is nonsense. That case is a
    // refusal in the form -- publishing a new app under a taken id is
    // an update, and an update is chosen, not typed.
    expect(nearestSiteAppID('cryoem', published)).toBeNull();
    expect(nearestSiteAppID('  CryoEM  ', published)).toBeNull();
  });

  it('will not call short names neighbours of each other', () => {
    // Two edits is a lot of a three-letter word. Without the second
    // test every short id in a pool would warn about every other.
    expect(nearestSiteAppID('cms', ['ams', 'atlas'])).toBe('ams');
    expect(nearestSiteAppID('cms', ['lhcb', 'atlas'])).toBeNull();
    expect(nearestSiteAppID('ab', ['cd'])).toBeNull();
  });

  it('answers the same whatever order the server listed the apps in', () => {
    // Two candidates at the same distance: the answer is the names,
    // not the listing. /api/v1/admin/site-apps promises no order.
    expect(nearestSiteAppID('demoz', ['demos', 'demox'])).toBe('demos');
    expect(nearestSiteAppID('demoz', ['demox', 'demos'])).toBe('demos');
  });

  it('ignores case, because the server does', () => {
    expect(nearestSiteAppID('Demo', published)).toBe('demos');
  });

  it('has nothing to say about an empty box', () => {
    expect(nearestSiteAppID('', published)).toBeNull();
    expect(nearestSiteAppID('   ', published)).toBeNull();
    expect(nearestSiteAppID('demo', [])).toBeNull();
  });
});

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
