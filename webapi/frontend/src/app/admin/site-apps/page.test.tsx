import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { describe, expect, it, vi, beforeEach } from 'vitest';
import type { AdminSiteApp, AdminSiteApps, AdminSiteAppHistory } from '@/lib/api';
import Page from './page';

const listSiteApps = vi.fn();
const siteAppHistory = vi.fn();
const uploadSiteApp = vi.fn();
const withdrawSiteApp = vi.fn();

vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api');
  return {
    ...actual,
    api: {
      ...actual.api,
      admin: {
        ...actual.api.admin,
        listSiteApps: () => listSiteApps(),
        siteAppHistory: (id: string) => siteAppHistory(id),
        uploadSiteApp: (f: FormData) => uploadSiteApp(f),
        withdrawSiteApp: (id: string) => withdrawSiteApp(id),
      },
    },
  };
});

function app(over: Partial<AdminSiteApp> = {}): AdminSiteApp {
  return {
    id: 'cryoem',
    name: 'CryoEM Pipeline',
    groups: ['smith_lab'],
    home: false,
    attested: true,
    digest: 'a3f9c1d2e4b50000',
    version: '2.1.0',
    origin: 'HTTP_API_SITE_APP_CRYOEM_GROUPS',
    managed: false,
    url: '/site/cryoem/',
    ...over,
  };
}

function listing(over: Partial<AdminSiteApps> = {}): AdminSiteApps {
  return {
    enabled: true,
    upload_allowed: false,
    directory: '/etc/condor/webapps',
    apps: [app()],
    ...over,
  };
}

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <Page />
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  listSiteApps.mockReset();
  siteAppHistory.mockReset();
  uploadSiteApp.mockReset();
  withdrawSiteApp.mockReset();
});

describe('site apps admin page', () => {
  it('says the feature is off rather than showing an empty table', async () => {
    // A server with no HTTP_API_SITE_APPS_DIR is not a server with no
    // apps: an empty table would have the administrator looking for
    // bundles that were never going to be read.
    listSiteApps.mockResolvedValue({ enabled: false, upload_allowed: false, apps: [] });
    renderPage();
    expect(await screen.findByTestId('site-apps-off')).toHaveTextContent(
      'HTTP_API_SITE_APPS_DIR',
    );
  });

  it('shows what is published and who published it', async () => {
    listSiteApps.mockResolvedValue(listing());
    renderPage();
    const row = await screen.findByTestId('app-cryoem');
    expect(row).toHaveTextContent('CryoEM Pipeline');
    expect(row).toHaveTextContent('smith_lab');
    // The origin is the point of the column: it says which decision
    // published this, which is the first thing to check when an app is
    // visible to the wrong people.
    expect(row).toHaveTextContent('HTTP_API_SITE_APP_CRYOEM_GROUPS');
  });

  // The upload form is the privilege. It must not be reachable when
  // the server would refuse it, or an administrator fills it in and
  // gets a 403 for their trouble.
  it('offers no upload form when the server does not accept uploads', async () => {
    listSiteApps.mockResolvedValue(listing({ upload_allowed: false }));
    renderPage();
    await screen.findByTestId('apps-table');
    expect(screen.queryByTestId('upload-form')).toBeNull();
    // And says what to do instead, including the knob to turn it on.
    expect(screen.getByTestId('upload-off')).toHaveTextContent('HTTP_API_SITE_APPS_UPLOAD');
  });

  it('offers the upload form when the server accepts uploads', async () => {
    listSiteApps.mockResolvedValue(listing({ upload_allowed: true }));
    renderPage();
    expect(await screen.findByTestId('upload-form')).toBeInTheDocument();
  });

  // A configured app is not withdrawable here however the upload
  // setting stands: the configuration decided it, and the server
  // refuses. Offering the button would be offering a 409.
  it('does not offer to withdraw an app the configuration publishes', async () => {
    listSiteApps.mockResolvedValue(listing({ upload_allowed: true, apps: [app({ managed: false })] }));
    renderPage();
    await screen.findByTestId('app-cryoem');
    expect(screen.queryByText('Withdraw')).toBeNull();
  });

  it('offers to withdraw an uploaded app', async () => {
    listSiteApps.mockResolvedValue(
      listing({ upload_allowed: true, apps: [app({ managed: true, origin: 'uploaded through the web interface' })] }),
    );
    renderPage();
    await screen.findByTestId('app-cryoem');
    expect(screen.getByText('Withdraw')).toBeInTheDocument();
  });

  it('shows the periods an app was served', async () => {
    listSiteApps.mockResolvedValue(listing());
    const history: AdminSiteAppHistory[] = [
      {
        digest: 'bbbb2222cccc',
        attested: true,
        version: '2.1.0',
        groups: ['smith_lab'],
        home: false,
        origin: 'HTTP_API_SITE_APP_CRYOEM_GROUPS',
        first_seen: '2026-11-03T10:00:00Z',
        last_seen: '2026-11-12T09:00:00Z',
      },
      {
        digest: 'aaaa1111dddd',
        attested: false,
        version: '2.0.0',
        groups: ['smith_lab', 'jones_lab'],
        home: false,
        origin: 'HTTP_API_SITE_APP_CRYOEM_GROUPS',
        first_seen: '2026-09-28T10:00:00Z',
        last_seen: '2026-11-03T10:00:00Z',
      },
    ];
    siteAppHistory.mockResolvedValue({ id: 'cryoem', history });

    renderPage();
    fireEvent.click(await screen.findByTestId('history-cryoem'));

    const table = await screen.findByTestId('history-table');
    expect(table).toHaveTextContent('2.1.0');
    expect(table).toHaveTextContent('2.0.0');
    // The earlier period's wider groups are the whole reason the
    // policy is recorded per period rather than read from the
    // configuration, which only says what is true now.
    expect(table).toHaveTextContent('jones_lab');
    expect(siteAppHistory).toHaveBeenCalledWith('cryoem');
  });

  it('explains an empty history rather than showing a bare table', async () => {
    listSiteApps.mockResolvedValue(listing());
    siteAppHistory.mockResolvedValue({ id: 'cryoem', history: [] });
    renderPage();
    fireEvent.click(await screen.findByTestId('history-cryoem'));
    expect(await screen.findByTestId('history-empty')).toBeInTheDocument();
  });

  // The server's refusal is the useful message -- "published by this
  // access point's configuration, which takes precedence" names the
  // parameter to edit. Swallowing it for a generic failure would throw
  // away the only instruction the administrator needs.
  it('surfaces the server refusal when an upload collides with the configuration', async () => {
    listSiteApps.mockResolvedValue(listing({ upload_allowed: true }));
    uploadSiteApp.mockRejectedValue(
      new Error('"cryoem" is published by this access point\'s configuration'),
    );
    renderPage();
    const form = await screen.findByTestId('upload-form');

    fireEvent.change(screen.getByTestId('upload-id'), { target: { value: 'cryoem' } });
    fireEvent.change(screen.getByTestId('upload-groups'), { target: { value: 'smith_lab' } });
    fireEvent.submit(form);

    await waitFor(() =>
      expect(screen.getByTestId('upload-error')).toHaveTextContent(
        'published by this access point',
      ),
    );
  });
});
