import { afterEach, describe, expect, it, vi } from 'vitest';
import { api } from './api';

// The job page's multi-AP selector reaches the server only if
// api.metrics.query puts job_id (and schedd) on the URL. The component
// tests mock api.metrics.query, so dropping the parameter there would
// make every multi-AP job page plot all of the caller's samples, merged.
describe('api.metrics.query', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('sends job_id and schedd, and leaves them off when unset', async () => {
    const fetchMock = vi.fn(async () =>
      new Response(JSON.stringify({ enabled: false, table: 'job_metrics' }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    );
    vi.stubGlobal('fetch', fetchMock);
    await api.metrics.query('job_metrics', { agg: 'count:*', job_id: '12.0@ap2.example.org', schedd: 'ap2.example.org' });
    await api.metrics.query('job_metrics', { agg: 'count:*', constraint: 'ClusterId == 1' });
    const [withJob, without] = fetchMock.mock.calls.map((c) => new URL(String((c as unknown[])[0]), 'http://x'));
    expect(withJob.pathname).toBe('/api/v1/metrics/job_metrics');
    expect(withJob.searchParams.get('job_id')).toBe('12.0@ap2.example.org');
    expect(withJob.searchParams.get('schedd')).toBe('ap2.example.org');
    expect(without.searchParams.has('job_id')).toBe(false);
    expect(without.searchParams.has('schedd')).toBe(false);
    expect(without.searchParams.get('constraint')).toBe('ClusterId == 1');
  });
});
