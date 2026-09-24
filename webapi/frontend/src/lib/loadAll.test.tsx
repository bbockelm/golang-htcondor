import { renderHook } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { createBoolPreference } from './preference';
import { MAX_AUTO_PAGES, useAutoLoadAll } from './loadAll';

describe('createBoolPreference', () => {
  beforeEach(() => window.localStorage.clear());

  it('remembers the answer across store instances', () => {
    createBoolPreference('t.remember').set(true);
    // A fresh store is what a reload gets: the value has to come from
    // storage, not from the instance that wrote it.
    expect(createBoolPreference('t.remember').getSnapshot()).toBe(true);
  });

  it('renders the default before anything is stored', () => {
    expect(createBoolPreference('t.unset').getSnapshot()).toBe(false);
    expect(createBoolPreference('t.unset2', true).getSnapshot()).toBe(true);
  });

  it('answers the same for the server render as for a fresh page', () => {
    // The app is a static export: a getServerSnapshot that disagreed
    // with the default would be a hydration mismatch on every load.
    const pref = createBoolPreference('t.hydration', true);
    expect(pref.getServerSnapshot()).toBe(true);
  });

  it('survives storage that refuses to be read or written', () => {
    const getItem = vi
      .spyOn(Storage.prototype, 'getItem')
      .mockImplementation(() => {
        throw new Error('blocked');
      });
    const setItem = vi
      .spyOn(Storage.prototype, 'setItem')
      .mockImplementation(() => {
        throw new Error('blocked');
      });
    try {
      // A private window makes even reading throw. A display preference
      // is not worth failing a render over.
      const pref = createBoolPreference('t.blocked');
      expect(pref.getSnapshot()).toBe(false);
      pref.set(true);
      expect(pref.getSnapshot()).toBe(true);
    } finally {
      getItem.mockRestore();
      setItem.mockRestore();
    }
  });

  it('picks up another tab writing the key', () => {
    const pref = createBoolPreference('t.crosstab');
    const seen: boolean[] = [];
    const unsubscribe = pref.subscribe(() => seen.push(pref.getSnapshot()));
    window.localStorage.setItem('t.crosstab', 'true');
    window.dispatchEvent(new StorageEvent('storage', { key: 't.crosstab' }));
    expect(seen).toEqual([true]);
    unsubscribe();
  });
});

describe('useAutoLoadAll', () => {
  function run(over: Partial<Parameters<typeof useAutoLoadAll>[0]> = {}) {
    const fetchNextPage = vi.fn();
    const props = {
      enabled: true,
      hasNextPage: true,
      isFetching: false,
      pageCount: 1,
      fetchNextPage,
      ...over,
    };
    const view = renderHook((p: typeof props) => useAutoLoadAll(p), {
      initialProps: props,
    });
    return { fetchNextPage, view, props };
  }

  it('walks the cursor while the preference is on', () => {
    const { fetchNextPage } = run();
    expect(fetchNextPage).toHaveBeenCalledTimes(1);
  });

  it('does nothing for someone who never asked', () => {
    const { fetchNextPage } = run({ enabled: false });
    expect(fetchNextPage).not.toHaveBeenCalled();
  });

  it('waits for the fetch in flight', () => {
    // Starting a next-page fetch while the first page is still loading
    // throws away the cursor the walk is supposed to follow.
    const { fetchNextPage } = run({ isFetching: true });
    expect(fetchNextPage).not.toHaveBeenCalled();
  });

  it('stops at the end of the cursor', () => {
    const { fetchNextPage } = run({ hasNextPage: false });
    expect(fetchNextPage).not.toHaveBeenCalled();
  });

  it('stops at the backstop rather than paging forever', () => {
    const { fetchNextPage } = run({ pageCount: MAX_AUTO_PAGES });
    expect(fetchNextPage).not.toHaveBeenCalled();
  });

  it('resumes after a refetch drops back to one page', () => {
    // This is the whole point: a poll cycle that resets the query must
    // not leave the user looking at a truncated list they already asked
    // to have filled in.
    const { fetchNextPage, view, props } = run({ pageCount: 12, isFetching: true });
    expect(fetchNextPage).not.toHaveBeenCalled();
    view.rerender({ ...props, pageCount: 1, isFetching: false });
    expect(fetchNextPage).toHaveBeenCalledTimes(1);
  });
});
