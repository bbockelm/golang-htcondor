import { act, render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { chatPanelProps, resetChatPanelSpy } from '@/test/chatPanelSpy';
import { scopeStore } from '@/lib/scope';

vi.mock('@/components/ChatPanel', async () => (await import('@/test/chatPanelSpy')).chatPanelMock());
vi.mock('next/navigation', () => ({
  useRouter: () => ({ replace: vi.fn(), push: vi.fn() }),
  useSearchParams: () => new URLSearchParams(),
  usePathname: () => '/archive',
}));

// The session the page sees; a case that needs an administrator swaps it.
const session = vi.hoisted(() => ({ current: { username: 'alice', is_admin: false } }));
const list = vi.fn();
vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api');
  return {
    ...actual,
    api: {
      ...actual.api,
      auth: { ...actual.api.auth, me: () => Promise.resolve(session.current) },
      chat: { ...actual.api.chat, info: () => Promise.resolve({ enabled: true }) },
      jobs: { ...actual.api.jobs, archive: (...a: unknown[]) => list(...a) },
      metrics: { ...actual.api.metrics, query: () => Promise.resolve({ series: [] }) },
    },
  };
});

async function renderPage() {
  const { default: Page } = await import('./page');
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <Page />
    </QueryClientProvider>,
  );
}

// The archive page tells the assistant which view it is in: the
// Mine/Everyone toggle's position is the chat request's scope.
describe('archive page chat scope', () => {
  beforeEach(() => {
    resetChatPanelSpy();
    session.current = { username: 'alice', is_admin: false };
    scopeStore.setScope('mine');
    list.mockReset();
    list.mockResolvedValue({ ads: [], source: 'schedd' });
  });

  it("passes the toggle's position as the chat scope", async () => {
    session.current = { username: 'root', is_admin: true };
    scopeStore.setScope('all');
    await renderPage();
    await screen.findByRole('button', { name: 'Open chat assistant' });
    expect(chatPanelProps().page).toBe('archive');
    await waitFor(() => expect(chatPanelProps().scope).toBe('everyone'));

    act(() => {
      scopeStore.setScope('mine');
    });
    await waitFor(() => expect(chatPanelProps().scope).toBe('mine'));
  });
});
