import { act, render, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { ClassAd } from '@/lib/api';
import { chatPanelProps, resetChatPanelSpy } from '@/test/chatPanelSpy';

vi.mock('@/components/ChatPanel', async () => (await import('@/test/chatPanelSpy')).chatPanelMock());
vi.mock('next/navigation', () => ({
  useRouter: () => ({ replace: vi.fn(), push: vi.fn() }),
  useSearchParams: () => new URLSearchParams(),
  usePathname: () => '/jobs/2.0',
}));

const session = vi.hoisted(() => ({ current: { username: 'root', is_admin: true } }));
const me = vi.hoisted(() => vi.fn());
vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api');
  return {
    ...actual,
    api: {
      ...actual.api,
      auth: { ...actual.api.auth, me: () => me() },
      chat: { ...actual.api.chat, info: () => Promise.resolve({ enabled: true }) },
    },
  };
});

const job = (owner: string): ClassAd => ({ ClusterId: 2, ProcId: 0, Owner: owner, JobStatus: 2, JobUniverse: 5 });

async function renderChat(ad: ClassAd) {
  const { JobDetailChat } = await import('./JobDetailClient');
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <JobDetailChat jobID="2.0" job={ad} />
    </QueryClientProvider>,
  );
}

// A job page has no toggle: it asks for everyone's scope when the job is
// somebody else's, so an administrator's assistant can work on the job the
// page shows, and for mine otherwise.
describe('job detail chat scope', () => {
  beforeEach(() => {
    resetChatPanelSpy();
    session.current = { username: 'root', is_admin: true };
    me.mockReset();
    me.mockImplementation(() => Promise.resolve(session.current));
  });

  it("asks for everyone on another user's job", async () => {
    await renderChat(job('bob'));
    await waitFor(() => expect(chatPanelProps().scope).toBe('everyone'));
    expect(chatPanelProps().page).toBe('job-detail');
    expect(chatPanelProps().pageContext).toContain('owner=bob');
  });

  it('asks for mine on the user’s own job, qualified name or not', async () => {
    session.current = { username: 'bob@test.domain', is_admin: false };
    await renderChat(job('bob'));
    // Mine is also what it asks before the session is known, so wait
    // for the session before reading it.
    await waitFor(() => expect(me).toHaveBeenCalled());
    await act(async () => {});
    expect(chatPanelProps().scope).toBe('mine');
  });
});
