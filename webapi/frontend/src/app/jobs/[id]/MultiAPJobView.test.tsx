import { render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { beforeEach, describe, expect, it, vi } from 'vitest';

// Multi-AP mode: the id segment is the server's job_id, the page never
// splits it, never offers an action, and moves to the URL that names the
// job completely.

let path = '/jobs/12.0';
const replace = vi.fn();
vi.mock('next/navigation', () => ({
  useRouter: () => ({ replace, push: vi.fn() }),
  useParams: () => ({ id: path.split('/').pop() }),
  usePathname: () => path,
  useSearchParams: () => new URLSearchParams(),
}));

const get = vi.fn();
const archiveOne = vi.fn();
vi.mock('next/dynamic', () => ({ default: () => () => null }));
vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api');
  return {
    ...actual,
    api: {
      ...actual.api,
      jobs: { ...actual.api.jobs, get: (...a: unknown[]) => get(...a), archiveOne: (...a: unknown[]) => archiveOne(...a) },
      chat: { info: vi.fn().mockResolvedValue({ enabled: false }) },
      auth: { me: vi.fn().mockResolvedValue({ authenticated: true, is_admin: false, multi_ap: true }) },
    },
  };
});

async function renderPage() {
  const { default: JobDetailClient } = await import('./JobDetailClient');
  const client = new QueryClient({ defaultOptions: { queries: { retryDelay: 0 } } });
  render(
    <QueryClientProvider client={client}>
      <JobDetailClient />
    </QueryClientProvider>,
  );
}

const job = {
  schedd: 'ap2.example.org',
  cluster: 12,
  proc: 0,
  job_id: '12.0@ap2.example.org',
  archived: false,
  source: 'hub',
  ClusterId: 12,
  ProcId: 0,
  JobStatus: 5,
  Owner: 'alice',
  Cmd: '/bin/sleep',
};

describe('the job page in multi-AP mode', () => {
  beforeEach(() => {
    replace.mockClear();
    get.mockReset();
    archiveOne.mockReset();
    path = '/jobs/12.0';
  });

  it('completes an incomplete id and offers no actions', async () => {
    get.mockResolvedValue(job);
    await renderPage();
    await waitFor(() => expect(replace).toHaveBeenCalledWith('/jobs/12.0%40ap2.example.org'));
    expect(get).toHaveBeenCalledWith('12.0');
    expect(await screen.findByText('ap2.example.org', { selector: 'span,div,dd,p' })).toBeTruthy();
    // A held job: the single-AP page would offer Release and Remove.
    expect(screen.queryByText('Release')).toBeNull();
    expect(screen.queryByText('Remove')).toBeNull();
    expect(archiveOne).not.toHaveBeenCalled();
  });

  it('sends a finished job to the archive page under its complete id', async () => {
    path = '/jobs/12.0@ap2.example.org';
    get.mockResolvedValue({ ...job, archived: true, JobStatus: 4 });
    await renderPage();
    await waitFor(() => expect(replace).toHaveBeenCalledWith('/archive/12.0%40ap2.example.org'));
  });

  it('lists the candidates when the id names jobs on two access points', async () => {
    const { ApiError } = await import('@/lib/api');
    get.mockRejectedValue(
      new ApiError(409, 'job 1.0 exists on 2 access points; name one', [
        { schedd: 'ap1', cluster: 1, proc: 0, job_id: '1.0@ap1', archived: false },
        { schedd: 'ap2', cluster: 1, proc: 0, job_id: '1.0@ap2', archived: true },
      ]),
    );
    path = '/jobs/1.0';
    await renderPage();
    const first = await screen.findByText('1.0@ap1');
    expect(first.closest('a')?.getAttribute('href')).toBe('/jobs/1.0%40ap1');
    expect(screen.getByText('1.0@ap2').closest('a')?.getAttribute('href')).toBe('/archive/1.0%40ap2');
    expect(get).toHaveBeenCalledTimes(1);
  });
});
