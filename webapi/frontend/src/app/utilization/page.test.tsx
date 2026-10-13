import { act, render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { UtilizationResponse } from '@/lib/utilization';
import { callHook, chatPanelProps, resetChatPanelSpy } from '@/test/chatPanelSpy';
import { scopeStore } from '@/lib/scope';

vi.mock('@/components/ChatPanel', async () => (await import('@/test/chatPanelSpy')).chatPanelMock());

// The session the page sees; a case that needs an administrator swaps it.
const session = vi.hoisted(() => ({ current: { username: 'alice', is_admin: false } }));

// The page keeps its state in the URL. This stands in for Next's router:
// replace() moves the search params and re-renders whoever reads them, as
// navigation does.
const nav = vi.hoisted(() => {
  let search = new URLSearchParams();
  const listeners = new Set<() => void>();
  return {
    replace: vi.fn((href: string) => {
      search = new URLSearchParams(href.split('?')[1] ?? '');
      listeners.forEach((l) => l());
    }),
    reset: () => {
      search = new URLSearchParams();
    },
    subscribe: (l: () => void) => {
      listeners.add(l);
      return () => listeners.delete(l);
    },
    get: () => search,
  };
});
vi.mock('next/navigation', async () => {
  const { useSyncExternalStore } = await import('react');
  return {
    useRouter: () => ({ replace: nav.replace, push: vi.fn() }),
    useSearchParams: () => useSyncExternalStore(nav.subscribe, nav.get),
    usePathname: () => '/utilization',
  };
});

const utilization = vi.fn();
const chatInfo = vi.fn();
vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api');
  return {
    ...actual,
    api: {
      ...actual.api,
      auth: { ...actual.api.auth, me: () => Promise.resolve(session.current) },
      chat: { ...actual.api.chat, info: () => chatInfo() },
      utilization: (...a: unknown[]) => utilization(...a),
    },
  };
});

// No finished jobs: the page's empty state, which is when "why is this
// empty?" is the question to ask.
const empty = {
  jobs_considered: 0,
  truncated: false,
  limit: 50000,
  max_limit: 500000,
  workflows: [],
  suggestions: [],
  owners: [],
} as unknown as UtilizationResponse;

async function renderPage() {
  const { default: Page } = await import('./page');
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <Page />
    </QueryClientProvider>,
  );
}

describe('utilization page chat', () => {
  beforeEach(() => {
    session.current = { username: 'alice', is_admin: false };
    scopeStore.setScope('mine');
    utilization.mockReset();
    chatInfo.mockReset();
    nav.replace.mockClear();
    nav.reset();
    resetChatPanelSpy();
    utilization.mockResolvedValue(empty);
  });

  it('offers the assistant when chat is enabled, even with no finished jobs', async () => {
    chatInfo.mockResolvedValue({ enabled: true });
    await renderPage();
    expect(await screen.findByRole('button', { name: 'Open chat assistant' })).toBeInTheDocument();
    const props = chatPanelProps();
    expect(props.page).toBe('utilization');
    expect(props.confirmableTools).toEqual([]);
    await waitFor(() => expect(chatPanelProps().pageContext).toContain('Jobs analysed: 0'));
  });

  it('hides the assistant when chat is disabled', async () => {
    chatInfo.mockResolvedValue({ enabled: false });
    await renderPage();
    await waitFor(() => expect(utilization).toHaveBeenCalled());
    expect(screen.queryByRole('button', { name: 'Open chat assistant' })).toBeNull();
  });

  it('set_constraint moves the URL and the analysis asks for those jobs', async () => {
    chatInfo.mockResolvedValue({ enabled: true });
    await renderPage();
    await screen.findByRole('button', { name: 'Open chat assistant' });

    act(() => {
      callHook('set_constraint', { constraint: 'RequestGPUs >= 1' });
    });
    expect(nav.replace).toHaveBeenLastCalledWith(
      `/utilization?constraint=${encodeURIComponent('RequestGPUs >= 1').replace(/%20/g, '+')}`,
      { scroll: false },
    );
    await waitFor(() =>
      expect(utilization).toHaveBeenLastCalledWith(expect.objectContaining({ constraint: 'RequestGPUs >= 1' })),
    );
    // The filter box shows what is applied, in its expression form.
    expect(screen.getByRole('button', { name: 'ClassAd expression' })).toHaveAttribute('aria-pressed', 'true');
    expect(screen.getByDisplayValue('RequestGPUs >= 1')).toBeInTheDocument();
    await waitFor(() => expect(chatPanelProps().pageContext).toContain('RequestGPUs >= 1'));
  });

  it('set_filter puts text in the workflow filter and stops applying an expression', async () => {
    chatInfo.mockResolvedValue({ enabled: true });
    await renderPage();
    await screen.findByRole('button', { name: 'Open chat assistant' });

    act(() => {
      callHook('set_constraint', { constraint: 'RequestGPUs >= 1' });
    });
    act(() => {
      callHook('set_filter', { query: 'train' });
    });
    expect(nav.replace).toHaveBeenLastCalledWith('/utilization?q=train', { scroll: false });
    // The unfiltered answer is already cached from the first load, so
    // what the page now shows is read from what it tells the assistant.
    await waitFor(() => expect(chatPanelProps().pageContext).toContain('Expression filter: none.'));
    expect(chatPanelProps().pageContext).toContain('Text filter on workflow names: "train"');
    expect(screen.getByRole('button', { name: 'Text' })).toHaveAttribute('aria-pressed', 'true');
  });

  it("passes the toggle's position as the chat scope", async () => {
    session.current = { username: 'root', is_admin: true };
    scopeStore.setScope('all');
    chatInfo.mockResolvedValue({ enabled: true });
    await renderPage();
    await screen.findByRole('button', { name: 'Open chat assistant' });
    await waitFor(() => expect(chatPanelProps().scope).toBe('everyone'));

    act(() => {
      scopeStore.setScope('mine');
    });
    await waitFor(() => expect(chatPanelProps().scope).toBe('mine'));
  });

  it('asks for mine when the session cannot widen, whatever the stored scope', async () => {
    scopeStore.setScope('all');
    chatInfo.mockResolvedValue({ enabled: true });
    await renderPage();
    await screen.findByRole('button', { name: 'Open chat assistant' });
    await waitFor(() => expect(utilization).toHaveBeenCalled());
    expect(chatPanelProps().scope).toBe('mine');
  });
});
