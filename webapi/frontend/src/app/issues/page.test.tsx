import { act, render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { IssuesResponse } from '@/lib/api';
import { callHook, chatPanelProps, resetChatPanelSpy } from '@/test/chatPanelSpy';

vi.mock('@/components/ChatPanel', async () => (await import('@/test/chatPanelSpy')).chatPanelMock());

const issues = vi.fn();
const chatInfo = vi.fn();
vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api');
  return {
    ...actual,
    api: {
      ...actual.api,
      auth: { ...actual.api.auth, me: () => Promise.resolve({ username: 'alice', is_admin: false }) },
      chat: { ...actual.api.chat, info: () => chatInfo() },
      issues: (...a: unknown[]) => issues(...a),
    },
  };
});

const empty: IssuesResponse = {
  window_seconds: 86400,
  computed_at: 1760000000,
  granularity: 0.5,
  include_ended: true,
  sections: [],
};

async function renderPage() {
  const { default: Page } = await import('./page');
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <Page />
    </QueryClientProvider>,
  );
}

describe('issues page chat', () => {
  beforeEach(() => {
    issues.mockReset();
    chatInfo.mockReset();
    resetChatPanelSpy();
    issues.mockResolvedValue(empty);
  });

  it('offers the assistant when chat is enabled, even with nothing to show', async () => {
    chatInfo.mockResolvedValue({ enabled: true });
    await renderPage();
    expect(await screen.findByRole('button', { name: 'Open chat assistant' })).toBeInTheDocument();
    expect(await screen.findByText(/Nothing held and no failed run attempts/)).toBeInTheDocument();
    const props = chatPanelProps();
    expect(props.page).toBe('issues');
    expect(props.confirmableTools).toEqual([]);
    expect(props.pageContext).toContain('window_hours=24');
  });

  it('hides the assistant when chat is disabled', async () => {
    chatInfo.mockResolvedValue({ enabled: false });
    await renderPage();
    await screen.findByText(/Nothing held and no failed run attempts/);
    expect(screen.queryByRole('button', { name: 'Open chat assistant' })).toBeNull();
  });

  it('set_constraint applies the expression to the page and its request', async () => {
    chatInfo.mockResolvedValue({ enabled: true });
    await renderPage();
    await screen.findByRole('button', { name: 'Open chat assistant' });

    let result: unknown;
    act(() => {
      result = callHook('set_constraint', { constraint: 'RequestGPUs >= 1' });
    });
    expect(result).toEqual({ ok: true, applied_constraint: 'RequestGPUs >= 1' });
    await waitFor(() =>
      expect(issues).toHaveBeenLastCalledWith(expect.objectContaining({ constraint: 'RequestGPUs >= 1' })),
    );
    expect(screen.getByLabelText('Only jobs matching')).toHaveValue('RequestGPUs >= 1');
    await waitFor(() => expect(chatPanelProps().pageContext).toContain('Expression filter: RequestGPUs >= 1'));

    act(() => {
      callHook('set_constraint', { constraint: '' });
    });
    await waitFor(() =>
      expect(issues).toHaveBeenLastCalledWith(expect.objectContaining({ constraint: undefined })),
    );
  });
});
