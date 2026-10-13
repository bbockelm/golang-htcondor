import { act, render, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { ClassAd } from '@/lib/api';
import { callHook, chatPanelProps, resetChatPanelSpy } from '@/test/chatPanelSpy';

vi.mock('@/components/ChatPanel', async () => (await import('@/test/chatPanelSpy')).chatPanelMock());
vi.mock('next/navigation', () => ({
  useRouter: () => ({ replace: vi.fn(), push: vi.fn() }),
  useSearchParams: () => new URLSearchParams(),
  usePathname: () => '/archive/12.0',
}));

const session = vi.hoisted(() => ({ current: { username: 'root', is_admin: true } }));
const me = vi.hoisted(() => vi.fn());
const matchAnalysis = vi.fn();
vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api');
  return {
    ...actual,
    api: {
      ...actual.api,
      auth: { ...actual.api.auth, me: () => me() },
      chat: { ...actual.api.chat, info: () => Promise.resolve({ enabled: true }) },
      jobs: { ...actual.api.jobs, matchAnalysis: (...a: unknown[]) => matchAnalysis(...a) },
    },
  };
});

const bobsJob: ClassAd = {
  ClusterId: 12,
  ProcId: 0,
  Owner: 'bob',
  JobStatus: 4,
  ExitCode: 1,
  HoldReason: 'earlier hold',
  LastRemoteHost: 'slot1@node7',
};

async function renderChat(job: ClassAd) {
  const { ArchiveDetailChat } = await import('./ArchiveDetailClient');
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <ArchiveDetailChat jobID="12.0" job={job} />
    </QueryClientProvider>,
  );
}

// An archived job's page has an assistant: read-only tools over the
// finished job, and the scope it asks for follows whose job it is.
describe('archived job chat', () => {
  beforeEach(() => {
    resetChatPanelSpy();
    session.current = { username: 'root', is_admin: true };
    me.mockReset();
    me.mockImplementation(() => Promise.resolve(session.current));
    matchAnalysis.mockReset();
  });

  it("asks for everyone's scope on another user's job, and names the job", async () => {
    await renderChat(bobsJob);
    await waitFor(() => expect(chatPanelProps().scope).toBe('everyone'));
    const props = chatPanelProps();
    expect(props.page).toBe('archive-detail');
    expect(props.pageContext).toContain('job_id=12.0');
    expect(props.pageContext).toContain('owner=bob');
    expect(props.pageContext).toContain('exit_code=1');
    // Nothing to confirm: nothing here changes the job.
    expect(props.confirmableTools).toEqual([]);
    expect(Object.keys(props.hooks ?? {}).sort()).toEqual(['get_job_attributes', 'get_match_analysis']);
  });

  it('asks for mine on the user’s own job', async () => {
    session.current = { username: 'bob@test.domain', is_admin: false };
    await renderChat(bobsJob);
    // Mine is also what it asks before the session is known, so wait
    // for the session before reading it.
    await waitFor(() => expect(me).toHaveBeenCalled());
    await act(async () => {});
    expect(chatPanelProps().scope).toBe('mine');
  });

  it('get_job_attributes reads the archived record and get_match_analysis asks for the archive', async () => {
    await renderChat(bobsJob);
    await waitFor(() => expect(chatPanelProps().scope).toBe('everyone'));
    expect(callHook('get_job_attributes', { names: ['exitcode', 'Nope'] })).toEqual({
      ok: true,
      attributes: { exitcode: 1 },
      missing: ['Nope'],
    });
    matchAnalysis.mockResolvedValue({
      job_id: '12.0',
      requirements: 'true',
      result: { total_slots: 3, full_matches: 3, narrowing_predicate_index: -1, predicates: [] },
    });
    const out = await callHook('get_match_analysis', {});
    expect(matchAnalysis).toHaveBeenCalledWith('12.0', { source: 'archive' });
    expect(out).toMatchObject({ ok: true, result: { full_matches: 3 } });
  });
});
