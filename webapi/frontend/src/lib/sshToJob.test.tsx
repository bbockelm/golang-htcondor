import { renderHook, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { describe, expect, it, vi } from 'vitest';
import type { Session } from '@/lib/api';

const me = vi.fn();
vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api');
  return { ...actual, api: { ...actual.api, auth: { ...actual.api.auth, me: () => me() } } };
});

async function sshToJob(session: Session) {
  me.mockReset();
  me.mockResolvedValue(session);
  const { useSSHToJob } = await import('./sshToJob');
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const { result } = renderHook(() => useSSHToJob(), {
    wrapper: ({ children }) => (
      <QueryClientProvider client={client}>{children}</QueryClientProvider>
    ),
  });
  await waitFor(() => expect(me).toHaveBeenCalled());
  return result;
}

const base: Session = { authenticated: true, is_admin: false, username: 'zoe' };

describe('useSSHToJob', () => {
  it('is false where the site allows nothing into a running job', async () => {
    const result = await sshToJob({ ...base, ssh_to_job: false });
    await waitFor(() => expect(result.current).toBe(false));
  });

  it('is true where it does', async () => {
    const result = await sshToJob({ ...base, ssh_to_job: true });
    await waitFor(() => expect(result.current).toBe(true));
  });

  // The case that decides which way the failure falls. A server too old
  // to send the field must not have its terminal hidden: offering one
  // that then refuses is a smaller failure than hiding one that works.
  it('is true when the server does not say', async () => {
    const result = await sshToJob(base);
    await waitFor(() => expect(result.current).toBe(true));
  });
});
