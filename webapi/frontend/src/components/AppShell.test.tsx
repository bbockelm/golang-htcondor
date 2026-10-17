import { render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { Session } from '@/lib/api';

const me = vi.fn();
const replace = vi.fn();
let pathname = '/placement';
vi.mock('next/navigation', () => ({
  usePathname: () => pathname,
  useRouter: () => ({ replace, push: vi.fn() }),
  useSearchParams: () => new URLSearchParams(),
}));
vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api');
  return { ...actual, api: { ...actual.api, auth: { ...actual.api.auth, me: (...a: unknown[]) => me(...a) } } };
});

const placementOnly: Session = {
  authenticated: true,
  is_admin: false,
  placement_only: true,
  placement: { foreign_id: 'zoe@uni.example', display_name: 'Zoe Q' },
};

async function renderShell() {
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

describe('AppShell for a placement-only session', () => {
  beforeEach(() => {
    me.mockReset();
    replace.mockReset();
  });

  it('renders the placement page without the access point navigation', async () => {
    pathname = '/placement';
    me.mockResolvedValue(placementOnly);
    await renderShell();
    expect(await screen.findByText('page body')).toBeInTheDocument();
    expect(screen.getByText('Zoe Q')).toBeInTheDocument();
    expect(screen.queryByRole('link', { name: 'Jobs' })).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Sign out' })).toBeInTheDocument();
  });

  it('sends any other page to /placement', async () => {
    pathname = '/jobs';
    me.mockResolvedValue(placementOnly);
    await renderShell();
    await waitFor(() => expect(replace).toHaveBeenCalledWith('/placement'));
    expect(screen.queryByText('page body')).not.toBeInTheDocument();
  });

  it('offers the placement page to an ordinary session that can use it', async () => {
    pathname = '/jobs';
    me.mockResolvedValue({ authenticated: true, is_admin: false, username: 'alice', placement: { foreign_id: 'a@idp' } });
    await renderShell();
    expect(await screen.findByRole('link', { name: 'Placement token' })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Jobs' })).toBeInTheDocument();
    expect(replace).not.toHaveBeenCalled();
  });
});
