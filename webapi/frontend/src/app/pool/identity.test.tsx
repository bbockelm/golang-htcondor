import { render, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import PoolPage from '@/app/pool/page';

vi.mock('@/components/ChatPanel', async () => (await import('@/test/chatPanelSpy')).chatPanelMock());
vi.mock('next/navigation', () => ({
  useRouter: () => ({ replace: vi.fn(), push: vi.fn() }),
  useSearchParams: () => new URLSearchParams(),
  usePathname: () => '/pool',
}));

const collectorList = vi.fn();
const authMe = vi.fn();
vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api');
  return {
    ...actual,
    api: {
      ...actual.api,
      auth: { ...actual.api.auth, me: () => authMe() },
      chat: { ...actual.api.chat, info: () => Promise.resolve({ enabled: false }) },
      collector: { ...actual.api.collector, list: (...a: unknown[]) => collectorList(...a) },
      pool: {
        ...actual.api.pool,
        drainEstimates: () => Promise.reject(new actual.ApiError(501, 'not here')),
      },
    },
  };
});

function renderPool() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <PoolPage />
    </QueryClientProvider>,
  );
}

// What the page asks the collector for.
function requestedProjection(): string {
  const call = collectorList.mock.calls.at(-1);
  return (call?.[0] as { projection?: string })?.projection ?? '';
}

describe('the pool page and withheld slot owners', () => {
  beforeEach(() => {
    collectorList.mockReset();
    collectorList.mockResolvedValue({ ads: [], total_returned: 0 });
    authMe.mockReset();
  });

  it('does not ask for the owner when the session says it is withheld', async () => {
    authMe.mockResolvedValue({ authenticated: true, pool_identity_restricted: true });
    renderPool();
    await waitFor(() => expect(collectorList).toHaveBeenCalled());
    await waitFor(() => expect(requestedProjection()).not.toContain('RemoteOwner'));
    // Still a real query: the page describes the pool, minus who is on it.
    expect(requestedProjection()).toContain('Machine');
  });

  it('asks for the owner when the session does not say it is withheld', async () => {
    authMe.mockResolvedValue({ authenticated: true });
    renderPool();
    await waitFor(() => expect(collectorList).toHaveBeenCalled());
    await waitFor(() => expect(requestedProjection()).toContain('RemoteOwner'));
  });
});
