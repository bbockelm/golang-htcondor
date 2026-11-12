import { render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { Session } from '@/lib/api';

const me = vi.fn();
vi.mock('next/navigation', () => ({
  usePathname: () => '/',
  useRouter: () => ({ replace: vi.fn(), push: vi.fn() }),
  useSearchParams: () => new URLSearchParams(),
}));
vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api');
  return { ...actual, api: { ...actual.api, auth: { ...actual.api.auth, me: () => me() } } };
});

async function renderShell(session: Session) {
  me.mockReset();
  me.mockResolvedValue(session);
  const { AppShell } = await import('./AppShell');
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <AppShell>
        <p>page body</p>
      </AppShell>
    </QueryClientProvider>,
  );
}

const base: Session = { authenticated: true, is_admin: false, username: 'zoe' };

describe('the Interactive item in the sidebar', () => {
  beforeEach(() => {
    me.mockReset();
  });

  it('is offered when the access point offers an app', async () => {
    await renderShell({ ...base, interactive: ['jupyter'] });
    await waitFor(() => expect(screen.getByText('Interactive')).toBeTruthy());
  });

  // The ask behind this: an item leading to a page that can only
  // explain that nothing can be started is worse than no item.
  it('goes when the access point offers none', async () => {
    await renderShell({ ...base, interactive: [] });
    // Wait for a sibling item, so the assertion is not just "the
    // sidebar has not rendered yet".
    await waitFor(() => expect(screen.getByText('Jobs')).toBeTruthy());
    expect(screen.queryByText('Interactive')).toBeNull();
  });

  // A server too old to say offers the item, which is what happened
  // before the field existed. Losing a working page on an upgrade
  // mismatch is the worse failure of the two.
  it('is offered when the server does not say', async () => {
    await renderShell(base);
    await waitFor(() => expect(screen.getByText('Interactive')).toBeTruthy());
  });
});
