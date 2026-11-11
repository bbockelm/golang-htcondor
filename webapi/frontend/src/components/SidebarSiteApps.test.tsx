import { render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { Session, SiteApp } from '@/lib/api';

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

const cryoem: SiteApp = {
  id: 'cryoem',
  name: 'CryoEM Pipeline',
  url: '/site/cryoem/',
  home: true,
  description: 'Submit and track reconstructions',
};

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

describe('site apps in the sidebar', () => {
  beforeEach(() => {
    me.mockReset();
  });

  it('lists the apps the server says this session may see', async () => {
    await renderShell({
      authenticated: true,
      is_admin: false,
      username: 'zoe',
      site_apps: [cryoem],
    });

    const link = await screen.findByTestId('site-app-cryoem');
    expect(link).toHaveTextContent('CryoEM Pipeline');
    expect(link).toHaveAttribute('href', '/site/cryoem/');
  });

  it('shows no Apps section when the server sent none', async () => {
    await renderShell({ authenticated: true, is_admin: false, username: 'zoe' });

    await screen.findByText('page body');
    // An empty heading with nothing under it reads as something
    // broken rather than as something absent.
    expect(screen.queryByText('Apps')).not.toBeInTheDocument();
  });

  it('renders only what the server sent, deciding nothing itself', async () => {
    // The server has already filtered by group. If the sidebar ever
    // grew its own filter, the two could disagree with the gate on
    // /site/{id}/ about who sees what -- so it must render the list
    // verbatim, including an app it has no other knowledge of.
    await renderShell({
      authenticated: true,
      is_admin: false,
      username: 'zoe',
      site_apps: [cryoem, { id: 'seqqc', name: 'SeqQC', url: '/site/seqqc/' }],
    });

    expect(await screen.findByTestId('site-app-cryoem')).toBeInTheDocument();
    expect(screen.getByTestId('site-app-seqqc')).toBeInTheDocument();
  });

  it('links out of the SPA rather than routing inside it', async () => {
    // A site app is a separate document served by the access point,
    // not a route in this export. A next/link here would ask Next for
    // a page that does not exist and 404 inside the shell.
    await renderShell({
      authenticated: true,
      is_admin: false,
      username: 'zoe',
      site_apps: [cryoem],
    });

    const link = await screen.findByTestId('site-app-cryoem');
    expect(link.tagName).toBe('A');
    await waitFor(() => expect(link.getAttribute('href')).toBe('/site/cryoem/'));
  });
});

describe('app-only sessions and the expert door', () => {
  beforeEach(() => {
    me.mockReset();
  });

  it('collapses the general-purpose navigation and offers the door', async () => {
    await renderShell({
      authenticated: true,
      is_admin: false,
      username: 'zoe',
      site_apps: [cryoem],
      app_only: true,
    });

    expect(await screen.findByTestId('site-app-cryoem')).toBeInTheDocument();
    expect(screen.getByTestId('expert-mode')).toHaveAttribute('href', '/site/expert');
    // The console pages are not offered. They are not forbidden --
    // typing the URL still works -- they are just not put in front of
    // somebody who did not ask for them.
    expect(screen.queryByText('Dashboard')).not.toBeInTheDocument();
    expect(screen.queryByText('Pool')).not.toBeInTheDocument();
  });

  it('restores the navigation and offers the way back once expert mode is on', async () => {
    await renderShell({
      authenticated: true,
      is_admin: false,
      username: 'zoe',
      site_apps: [cryoem],
      app_only: true,
      expert_active: true,
    });

    expect(await screen.findByText('Dashboard')).toBeInTheDocument();
    expect(screen.getByTestId('leave-expert-mode')).toHaveAttribute(
      'href',
      '/site/expert?close=1',
    );
    expect(screen.queryByTestId('expert-mode')).not.toBeInTheDocument();
  });

  it('leaves an ordinary session alone', async () => {
    // Somebody who is also staff keeps the full console and is never
    // shown a door they do not need.
    await renderShell({
      authenticated: true,
      is_admin: false,
      username: 'zoe',
      site_apps: [cryoem],
    });

    expect(await screen.findByText('Dashboard')).toBeInTheDocument();
    expect(screen.queryByTestId('expert-mode')).not.toBeInTheDocument();
    expect(screen.queryByTestId('leave-expert-mode')).not.toBeInTheDocument();
    // ...and still sees their app.
    expect(screen.getByTestId('site-app-cryoem')).toBeInTheDocument();
  });
});
