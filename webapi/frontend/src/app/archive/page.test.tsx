import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
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
const queueList = vi.fn();
vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api');
  return {
    ...actual,
    api: {
      ...actual.api,
      auth: { ...actual.api.auth, me: () => Promise.resolve(session.current) },
      chat: { ...actual.api.chat, info: () => Promise.resolve({ enabled: true }) },
      jobs: {
        ...actual.api.jobs,
        archive: (...a: unknown[]) => list(...a),
        list: (...a: unknown[]) => queueList(...a),
      },
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
    queueList.mockReset();
    queueList.mockResolvedValue({ jobs: [] });
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

// A job submitted here is kept in the queue after it finishes, so it
// has no history record yet and this page cannot show it. That is the
// one thing a reader can come here for and not find, so the page can
// say where it went -- without paying for the extra query on every
// visit.
describe('finished jobs still in the queue', () => {
  beforeEach(() => {
    resetChatPanelSpy();
    session.current = { username: 'alice', is_admin: false };
    scopeStore.setScope('mine');
    list.mockReset();
    list.mockResolvedValue({ ads: [], source: 'schedd' });
    queueList.mockReset();
    queueList.mockResolvedValue({ jobs: [] });
  });

  it('asks for them only once the reader opts in', async () => {
    await renderPage();
    const box = await screen.findByLabelText(/finished jobs still in the queue/i);
    expect(queueList).not.toHaveBeenCalled();

    queueList.mockResolvedValue({
      jobs: [{ ClusterId: 77, ProcId: 0, Owner: 'alice', Cmd: '/bin/done', CompletionDate: 1_700_000_000 }],
    });
    fireEvent.click(box);

    await waitFor(() => expect(queueList).toHaveBeenCalled());
    // Only the finished ones, or the list would be the whole queue.
    expect(queueList.mock.calls[0][0]).toMatchObject({ constraint: 'JobStatus == 4' });
    expect(await screen.findByText('77.0')).toBeTruthy();
    // It links to the live job, not to an archive record that does not
    // exist yet.
    expect(screen.getByText('77.0').closest('a')).toHaveAttribute('href', '/jobs/77.0');
  });

  it('says so when nothing is waiting, rather than leaving a blank', async () => {
    await renderPage();
    fireEvent.click(await screen.findByLabelText(/finished jobs still in the queue/i));
    expect(await screen.findByText(/every finished job is in the history below/i)).toBeTruthy();
  });
});

// "your job history" is wrong in the pool-wide view, where the page and
// the assistant both cover everyone's jobs.
describe('the assistant is labelled for the view it is in', () => {
  beforeEach(() => {
    resetChatPanelSpy();
    session.current = { username: 'root', is_admin: true };
    scopeStore.setScope('mine');
    list.mockReset();
    list.mockResolvedValue({ ads: [], source: 'schedd' });
    queueList.mockReset();
    queueList.mockResolvedValue({ jobs: [] });
  });

  it('drops "your" when the view is everyone', async () => {
    await renderPage();
    await waitFor(() => expect(chatPanelProps().togglerLabel).toBe('Ask about your job history'));

    act(() => {
      scopeStore.setScope('all');
    });
    await waitFor(() => expect(chatPanelProps().togglerLabel).toBe('Ask about job history'));
  });
});
