import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { PlacementMe, Session } from '@/lib/api';

const me = vi.fn();
const placementMe = vi.fn();
vi.mock('next/navigation', () => ({
  usePathname: () => '/placement',
  useRouter: () => ({ replace: vi.fn(), push: vi.fn() }),
  useSearchParams: () => new URLSearchParams(),
}));
vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api');
  return {
    ...actual,
    api: {
      ...actual.api,
      auth: { ...actual.api.auth, me: (...a: unknown[]) => me(...a) },
      placement: { ...actual.api.placement, me: (...a: unknown[]) => placementMe(...a) },
    },
  };
});

const placementOnly: Session = {
  authenticated: true,
  is_admin: false,
  placement_only: true,
  placement: { identity: 'newbie@idp.example', display_name: 'Newbie' },
};

const onboarded: Session = {
  authenticated: true,
  is_admin: false,
  username: 'physnewbie@ap.example',
  placement: {
    identity: 'newbie@idp.example',
    display_name: 'Newbie',
    account: 'physnewbie@ap.example',
    levels: ['READ', 'WRITE'],
    projects: ['Physics'],
    project: 'Physics',
  },
};

const unauthorized: PlacementMe = {
  identity: 'newbie@idp.example',
  authorized: false,
  expired: false,
  authorizations: [],
  projects: [],
  account_enabled: false,
  records_available: false,
};

async function renderPage() {
  const { AppShell } = await import('@/components/AppShell');
  const { default: PlacementPage } = await import('./page');
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: 30_000 } } });
  render(
    <QueryClientProvider client={client}>
      <AppShell>
        <PlacementPage />
      </AppShell>
    </QueryClientProvider>,
  );
}

describe('/placement for a placement-only session', () => {
  beforeEach(() => {
    me.mockReset();
    placementMe.mockReset();
    placementMe.mockResolvedValue(unauthorized);
  });

  it('switches to the full shell when Check again finds an account', async () => {
    me.mockResolvedValue(placementOnly);
    await renderPage();
    const button = await screen.findByRole('button', { name: 'Check again' });
    expect(screen.queryByRole('link', { name: 'Jobs' })).not.toBeInTheDocument();
    const placementCalls = placementMe.mock.calls.length;

    me.mockResolvedValue(onboarded);
    fireEvent.click(button);

    expect(await screen.findByRole('link', { name: 'Jobs' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Check again' })).not.toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Placement token' })).toBeInTheDocument();
    // What the page read as the placement-only session is read again.
    await waitFor(() => expect(placementMe.mock.calls.length).toBeGreaterThan(placementCalls));
  });

  it('checks again when the window regains focus', async () => {
    me.mockResolvedValue(placementOnly);
    await renderPage();
    await screen.findByRole('button', { name: 'Check again' });
    const calls = me.mock.calls.length;

    me.mockResolvedValue(onboarded);
    act(() => {
      window.dispatchEvent(new Event('focus'));
    });
    await waitFor(() => expect(me.mock.calls.length).toBeGreaterThan(calls));
    expect(await screen.findByRole('link', { name: 'Jobs' })).toBeInTheDocument();
  });

  it('checks again when the tab becomes visible', async () => {
    me.mockResolvedValue(placementOnly);
    await renderPage();
    await screen.findByRole('button', { name: 'Check again' });
    const calls = me.mock.calls.length;

    act(() => {
      document.dispatchEvent(new Event('visibilitychange'));
    });
    await waitFor(() => expect(me.mock.calls.length).toBeGreaterThan(calls));
  });

  it('keeps the reduced shell while there is still no account', async () => {
    me.mockResolvedValue(placementOnly);
    await renderPage();
    fireEvent.click(await screen.findByRole('button', { name: 'Check again' }));
    await waitFor(() => expect(me).toHaveBeenCalledTimes(2));
    expect(await screen.findByRole('button', { name: 'Check again' })).toBeEnabled();
    expect(screen.queryByRole('link', { name: 'Jobs' })).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Sign out' })).toBeInTheDocument();
  });

  it('offers no check to a full session', async () => {
    me.mockResolvedValue(onboarded);
    await renderPage();
    expect(await screen.findByRole('link', { name: 'Jobs' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Check again' })).not.toBeInTheDocument();
  });
});
