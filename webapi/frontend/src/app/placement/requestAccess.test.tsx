import { render, screen } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { PlacementMe, Session } from '@/lib/api';

const authMe = vi.fn();
const me = vi.fn();
const myRequest = vi.fn();
vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api');
  return {
    ...actual,
    api: {
      ...actual.api,
      auth: { ...actual.api.auth, me: (...a: unknown[]) => authMe(...a) },
      placement: {
        ...actual.api.placement,
        me: (...a: unknown[]) => me(...a),
        myRequest: (...a: unknown[]) => myRequest(...a),
      },
    },
  };
});

const { default: PlacementPage } = await import('./page');

const session: Session = {
  authenticated: true,
  is_admin: false,
  placement_only: true,
  placement: { identity: 'newbie@idp.example', display_name: 'New Bie' },
};

const unmapped: PlacementMe = {
  identity: 'newbie@idp.example',
  authorized: false,
  expired: false,
  authorizations: [],
  projects: [],
  account_enabled: true,
  records_available: false,
};

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <PlacementPage />
    </QueryClientProvider>,
  );
}

describe('/placement', () => {
  beforeEach(() => {
    authMe.mockReset().mockResolvedValue(session);
    me.mockReset();
    myRequest.mockReset().mockResolvedValue({ identity: 'newbie@idp.example', request: null });
  });

  it('offers to request access to an identity without it', async () => {
    me.mockResolvedValue(unmapped);
    renderPage();
    expect(await screen.findByText(/is not authorized to use this access point/)).toBeInTheDocument();
    expect(await screen.findByRole('region', { name: 'Request access' })).toBeInTheDocument();
  });

  it('sends an expired mapping to an administrator instead', async () => {
    me.mockResolvedValue({ ...unmapped, expired: true });
    renderPage();
    expect(await screen.findByText(/has expired on this/)).toBeInTheDocument();
    expect(await screen.findByText('Ask an administrator of this access point to extend it.')).toBeInTheDocument();
    expect(screen.queryByRole('region', { name: 'Request access' })).toBeNull();
    expect(myRequest).not.toHaveBeenCalled();
  });

  it('shows the token form, and no request, to an identity with access', async () => {
    me.mockResolvedValue({
      ...unmapped,
      authorized: true,
      account: 'newbie@ap.example',
      authorizations: [{ name: 'READ', label: 'Read' }],
      projects: [{ name: 'Physics', default: true, enabled: true }],
    });
    renderPage();
    expect(await screen.findByRole('button', { name: 'Request token' })).toBeInTheDocument();
    expect(screen.queryByRole('region', { name: 'Request access' })).toBeNull();
    expect(myRequest).not.toHaveBeenCalled();
  });
});
