import { render, screen } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { describe, expect, it, vi } from 'vitest';

// The job page must not wait for the session before asking for the job:
// the mode only decides which view renders, and the request is the same
// in both. Here the session never arrives, and the job is asked for
// anyway.

vi.mock('next/navigation', () => ({
  useRouter: () => ({ replace: vi.fn(), push: vi.fn() }),
  useParams: () => ({ id: '4242.0' }),
  usePathname: () => '/jobs/4242.0',
  useSearchParams: () => new URLSearchParams(),
}));

const get = vi.fn();
vi.mock('next/dynamic', () => ({ default: () => () => null }));
vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api');
  return {
    ...actual,
    api: {
      ...actual.api,
      jobs: { ...actual.api.jobs, get: (...a: unknown[]) => get(...a) },
      chat: { info: vi.fn().mockResolvedValue({ enabled: false }) },
      // Pending forever: the session is still loading.
      auth: { me: vi.fn(() => new Promise(() => {})) },
    },
  };
});

describe('the job page', () => {
  it('requests the job while the session is still loading', async () => {
    get.mockResolvedValue({ ClusterId: 4242, ProcId: 0, JobStatus: 2 });
    const { default: JobDetailClient } = await import('./JobDetailClient');
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(
      <QueryClientProvider client={client}>
        <JobDetailClient />
      </QueryClientProvider>,
    );
    await vi.waitFor(() => expect(get).toHaveBeenCalledWith('4242.0'));
    expect(screen.getByText('Loading...')).toBeTruthy();
  });
});
