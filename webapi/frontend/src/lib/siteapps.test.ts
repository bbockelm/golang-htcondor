import { describe, expect, it } from 'vitest';
import { nearestSiteAppID } from './siteapps';

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
