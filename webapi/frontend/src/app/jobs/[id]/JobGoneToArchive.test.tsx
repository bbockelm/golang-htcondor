import { render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { beforeEach, describe, expect, it, vi } from 'vitest';

// A job that finished between a page being drawn and one of its links
// being clicked is gone from the queue -- the schedd destroys a
// completed job within seconds -- and sitting in the archive under the
// same id. Following a link from /issues should land on the record, not
// on an error.

const replace = vi.fn();
vi.mock('next/navigation', () => ({
  useRouter: () => ({ replace, push: vi.fn() }),
  useParams: () => ({ id: '4242.0' }),
  usePathname: () => '/jobs/4242.0',
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
      auth: { me: vi.fn().mockResolvedValue({ authenticated: true, is_admin: false }) },
    },
  };
});

async function renderPage() {
  const { default: JobDetailClient } = await import('./JobDetailClient');
  // retryDelay 0, not retry false: the page's own retry rule is part of
  // what is being tested (a 5xx is retried, a 404 is not), so it must
  // not be overridden here -- only made fast.
  const client = new QueryClient({ defaultOptions: { queries: { retryDelay: 0 } } });
  render(
    <QueryClientProvider client={client}>
      <JobDetailClient />
    </QueryClientProvider>,
  );
}

describe('a job that has left the queue', () => {
  beforeEach(() => {
    replace.mockClear();
    get.mockReset();
    archiveOne.mockReset();
  });

  it('opens the archived record instead of showing a 404', async () => {
    const { ApiError } = await import('@/lib/api');
    get.mockRejectedValue(new ApiError(404, 'Job not found'));
    archiveOne.mockResolvedValue({ ClusterId: 4242, ProcId: 0 });

    await renderPage();

    await waitFor(() => expect(replace).toHaveBeenCalledWith('/archive/4242.0'));
    // Existence is the whole question; the archive page fetches the ad
    // for itself, so this lookup must not drag the whole thing over.
    expect(archiveOne).toHaveBeenCalledWith('4242.0', 'ClusterId,ProcId');
    // Asked once. A 404 is an answer, and retrying it three times with
    // backoff would leave somebody who clicked a link staring at
    // nothing for several seconds before the redirect they were always
    // going to get.
    expect(get).toHaveBeenCalledTimes(1);
  });

  it('says so plainly when the archive has never heard of it either', async () => {
    const { ApiError } = await import('@/lib/api');
    get.mockRejectedValue(new ApiError(404, 'Job not found'));
    archiveOne.mockResolvedValue(null);

    await renderPage();

    await waitFor(() =>
      expect(screen.getByText(/no record of it in the archive/i)).toBeInTheDocument(),
    );
    expect(replace).not.toHaveBeenCalled();
  });

  it('still reports a real failure as a failure', async () => {
    // A 500 is not "the job moved"; looking in the archive for it would
    // be answering a question nobody asked.
    const { ApiError } = await import('@/lib/api');
    get.mockRejectedValue(new ApiError(500, 'Query failed: schedd is down'));

    await renderPage();

    await waitFor(() => expect(screen.getByText(/schedd is down/)).toBeInTheDocument());
    expect(archiveOne).not.toHaveBeenCalled();
    expect(replace).not.toHaveBeenCalled();
  });
});
