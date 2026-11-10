import { afterEach, describe, expect, it, vi } from 'vitest';
import { api, submitTargets } from './api';

describe('api.jobs.submit', () => {
  afterEach(() => vi.unstubAllGlobals());

  function stubFetch() {
    const fetchMock = vi.fn(async () =>
      new Response(JSON.stringify({ cluster_id: 7, job_ids: ['7.0@ap3'] }), {
        status: 201,
        headers: { 'Content-Type': 'application/json' },
      }),
    );
    vi.stubGlobal('fetch', fetchMock);
    return fetchMock;
  }

  it('names the chosen access point in the query', async () => {
    const fetchMock = stubFetch();
    await api.jobs.submit('queue', 'ap3.example.org');
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(String((fetchMock.mock.calls[0] as unknown[])[0])).toBe('/api/v1/jobs?schedd=ap3.example.org');
  });

  it('escapes the access point name', async () => {
    const fetchMock = stubFetch();
    await api.jobs.submit('queue', 'ap2@127.0.0.1');
    expect(String((fetchMock.mock.calls[0] as unknown[])[0])).toBe('/api/v1/jobs?schedd=ap2%40127.0.0.1');
  });

  it('sends no query without a target', async () => {
    const fetchMock = stubFetch();
    await api.jobs.submit('queue');
    expect(String((fetchMock.mock.calls[0] as unknown[])[0])).toBe('/api/v1/jobs');
  });
});

describe('submitTargets', () => {
  it('lists the home access point first, then the alternates', () => {
    expect(submitTargets({ schedd: 'ap2', alternates: ['ap3'] })).toEqual(['ap2', 'ap3']);
    expect(submitTargets({ error: 'no access point is assigned to you' })).toEqual([]);
    expect(submitTargets(undefined)).toEqual([]);
  });
});
