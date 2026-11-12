import { renderHook, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { describe, expect, it, vi } from 'vitest';
import type { Session } from '@/lib/api';

const me = vi.fn();
vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api');
  return { ...actual, api: { ...actual.api, auth: { ...actual.api.auth, me: () => me() } } };
});

async function offeredFor(session: Session) {
  me.mockReset();
  me.mockResolvedValue(session);
  const { useInteractiveAppOffered } = await import('./interactiveApps');
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const { result } = renderHook(() => useInteractiveAppOffered('vscode'), {
    wrapper: ({ children }) => (
      <QueryClientProvider client={client}>{children}</QueryClientProvider>
    ),
  });
  await waitFor(() => expect(me).toHaveBeenCalled());
  return result;
}

const base: Session = { authenticated: true, is_admin: false, username: 'zoe' };

describe('useInteractiveAppOffered', () => {
  it('is false for an app the access point leaves out of its list', async () => {
    const result = await offeredFor({ ...base, interactive: ['jupyter'] });
    await waitFor(() => expect(result.current).toBe(false));
  });

  it('is true for one it names', async () => {
    const result = await offeredFor({ ...base, interactive: ['jupyter', 'vscode'] });
    await waitFor(() => expect(result.current).toBe(true));
  });

  // An EMPTY list means the access point offers none.
  it('is false when the list is empty', async () => {
    const result = await offeredFor({ ...base, interactive: [] });
    await waitFor(() => expect(result.current).toBe(false));
  });
});
