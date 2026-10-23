import { render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { Session } from '@/lib/api';
import type { Branding } from '@/lib/branding';

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

const session: Session = { authenticated: true, is_admin: false, username: 'zoe' };

const site: Branding = {
  site_name: 'UChicago ATLAS Analysis Facility',
  site_tagline: 'Analysis Facility',
  page_title: 'UChicago ATLAS Analysis Facility',
  footer_logos: [],
  software_credit: true,
  favicon: '/branding/af.svg',
};

async function renderShell(branding?: Branding) {
  if (branding) window.__HTCONDOR_BRANDING__ = branding;
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

describe('the shell under a site’s own branding', () => {
  beforeEach(() => {
    me.mockReset();
    me.mockResolvedValue(session);
    // Not in afterEach: the shell is still mounted there, and its head
    // observer puts the icon straight back.
    document.querySelector('link[rel="icon"]')?.remove();
    document.title = '';
  });
  afterEach(() => {
    delete window.__HTCONDOR_BRANDING__;
  });

  it('names the site in the sidebar, not HTCondor', async () => {
    await renderShell(site);
    // The sidebar heading and the narrow-screen top bar both carry it.
    expect(await screen.findAllByText('UChicago ATLAS Analysis Facility')).toHaveLength(2);
    expect(screen.queryByText('Access Point')).not.toBeInTheDocument();
    expect(screen.getByText('Analysis Facility')).toBeInTheDocument();
  });

  // A client-side navigation re-applies the layout's metadata over the
  // title the server wrote into the HTML, so the shell has to put it back.
  it('keeps the tab on the site’s title and icon', async () => {
    await renderShell(site);
    await waitFor(() => expect(document.title).toBe('UChicago ATLAS Analysis Facility'));
    expect(document.querySelector('link[rel="icon"]')).toHaveAttribute(
      'href',
      '/branding/af.svg',
    );
  });

  it('leaves an unconfigured deployment alone', async () => {
    await renderShell();
    expect(await screen.findByText('HTCondor')).toBeInTheDocument();
    expect(screen.getByText('Access Point')).toBeInTheDocument();
    expect(screen.getByText('HTCondor Access Point')).toBeInTheDocument();
    // Nothing the server did not ask for: no icon link is forced on it.
    expect(document.querySelector('link[rel="icon"]')).toBeNull();
  });
});
