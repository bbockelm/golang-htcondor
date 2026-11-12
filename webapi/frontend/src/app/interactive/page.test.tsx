import { render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { InteractiveApp, Session } from '@/lib/api';

const me = vi.fn();
const listApps = vi.fn();
const listJupyter = vi.fn();
const listTerminals = vi.fn();

vi.mock('next/navigation', () => ({
  usePathname: () => '/interactive',
  useRouter: () => ({ replace: vi.fn(), push: vi.fn() }),
  useSearchParams: () => new URLSearchParams(),
}));
vi.mock('@/lib/multiap', () => ({
  useMultiAP: () => false,
  useKindAssignment: () => ({ data: undefined }),
}));
vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api');
  return {
    ...actual,
    api: {
      ...actual.api,
      auth: { ...actual.api.auth, me: () => me() },
      apps: { ...actual.api.apps, list: () => listApps() },
      jupyter: { ...actual.api.jupyter, list: () => listJupyter() },
      interactive: { ...actual.api.interactive, listTerminals: () => listTerminals() },
    },
  };
});

async function renderPage(interactive: InteractiveApp[] | undefined) {
  const session: Session = { authenticated: true, is_admin: false, username: 'zoe', interactive };
  me.mockResolvedValue(session);
  const Page = (await import('./page')).default;
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <Page />
    </QueryClientProvider>,
  );
}

describe('the Interactive page', () => {
  beforeEach(() => {
    me.mockReset();
    listApps.mockReset().mockResolvedValue({ apps: [] });
    listJupyter.mockReset().mockResolvedValue({ instances: [] });
    listTerminals.mockReset().mockResolvedValue({ terminals: [] });
  });

  it('offers every app the access point offers', async () => {
    await renderPage(['jupyter', 'vscode', 'terminal']);
    await waitFor(() => expect(screen.getByText('Launch JupyterLab')).toBeTruthy());
    expect(screen.getByText('Launch VS Code')).toBeTruthy();
    expect(screen.getByText('Launch terminal')).toBeTruthy();
  });

  // An ABSENT list is a server too old to say, not a site that offers
  // nothing: every such server offers all three. Reading it as "none"
  // hid every application from everyone talking to one -- caught by the
  // multi-AP browser smoke test, whose mocked session has no such
  // field.
  it('offers every app when the server does not say', async () => {
    await renderPage(undefined);
    await waitFor(() => expect(screen.getByText('Launch JupyterLab')).toBeTruthy());
    expect(screen.getByText('Launch VS Code')).toBeTruthy();
    expect(screen.getByText('Launch terminal')).toBeTruthy();
  });

  // The section goes entirely, rather than offering a form that the
  // server would refuse.
  it('drops the section for an app that is not offered', async () => {
    await renderPage(['jupyter']);
    await waitFor(() => expect(screen.getByText('Launch JupyterLab')).toBeTruthy());
    expect(screen.queryByText('VS Code')).toBeNull();
    expect(screen.queryByText('Terminal')).toBeNull();
  });

  // A session the site has stopped offering is still the user's to open
  // and to stop, so it stays listed -- without the launch form.
  it('keeps listing a session in an app that is no longer offered', async () => {
    listTerminals.mockResolvedValue({
      terminals: [{ job_id: '12.0', status: 2, batch_name: 'term-abc' }],
    });
    await renderPage(['jupyter']);
    await waitFor(() => expect(screen.getByText('Terminal')).toBeTruthy());
    expect(screen.queryByText('Launch terminal')).toBeNull();
    expect(
      screen.getByText(/does not offer Terminal sessions/),
    ).toBeTruthy();
  });

  it('says so when the access point offers none of them', async () => {
    await renderPage([]);
    await waitFor(() =>
      expect(screen.getByText(/does not offer interactive sessions/)).toBeTruthy(),
    );
    expect(screen.queryByText('Launch JupyterLab')).toBeNull();
  });
});
