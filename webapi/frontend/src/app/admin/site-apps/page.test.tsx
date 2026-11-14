import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { describe, expect, it, vi, beforeEach } from 'vitest';
import type {
  AdminSiteApp,
  AdminSiteApps,
  AdminSiteAppConfig,
  AdminSiteAppHistory,
} from '@/lib/api';
import Page from './page';
import { validateSiteAppID } from '@/lib/siteapps';

const listSiteApps = vi.fn();
const siteAppHistory = vi.fn();
const uploadSiteApp = vi.fn();
const withdrawSiteApp = vi.fn();
const siteAppConfig = vi.fn();
const setSiteAppConfig = vi.fn();

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
        siteAppConfig: (id: string) => siteAppConfig(id),
        setSiteAppConfig: (id: string, settings: Record<string, string>) =>
          setSiteAppConfig(id, settings),
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

// config is the settings panel's answer: the app's configuration
// parameters, named as the configuration names them.
function config(over: Partial<AdminSiteAppConfig> = {}): AdminSiteAppConfig {
  return {
    id: 'cryoem',
    origin: 'HTTP_API_SITE_APP_CRYOEM_GROUPS',
    stored_here: false,
    editable: false,
    settings: [
      {
        key: 'HTTP_API_SITE_APP_CRYOEM_GROUPS',
        setting: 'GROUPS',
        value: 'smith_lab',
        editable: false,
      },
      { key: 'HTTP_API_SITE_APP_CRYOEM_HOME', setting: 'HOME', value: '', editable: false },
      {
        key: 'HTTP_API_SITE_APP_CRYOEM_ENABLED',
        setting: 'ENABLED',
        value: '',
        effective: 'true',
        effective_from: 'default',
        editable: false,
      },
      {
        key: 'HTTP_API_SITE_APP_CRYOEM_NAME',
        setting: 'NAME',
        value: '',
        effective: 'CryoEM Pipeline',
        effective_from: 'bundle',
        editable: false,
      },
      {
        key: 'HTTP_API_SITE_APP_CRYOEM_DESCRIPTION',
        setting: 'DESCRIPTION',
        value: '',
        editable: false,
      },
      { key: 'HTTP_API_SITE_APP_CRYOEM_ICON', setting: 'ICON', value: '', editable: false },
    ],
    ...over,
  };
}

// editableConfig is the same app as one published from this page:
// stored by the server, and changeable without a restart.
function editableConfig(): AdminSiteAppConfig {
  const c = config({
    stored_here: true,
    editable: true,
    origin: 'uploaded through the web interface',
  });
  return {
    ...c,
    settings: c.settings.map((s) =>
      s.setting === 'ENABLED' ? s : { ...s, editable: true },
    ),
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
  siteAppConfig.mockReset();
  setSiteAppConfig.mockReset();
  siteAppConfig.mockResolvedValue(config());
  siteAppHistory.mockResolvedValue({ id: 'cryoem', history: [] });
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

  // "*" is what the configuration writes, and a reader of the column
  // should not have to know that. Both tables show the same list, so
  // both are checked here.
  it('names everyone rather than printing the configuration\u2019s star', async () => {
    listSiteApps.mockResolvedValue(listing({ apps: [app({ groups: ['*'] })] }));
    const history: AdminSiteAppHistory[] = [
      {
        digest: 'bbbb2222cccc',
        attested: true,
        version: '2.1.0',
        groups: ['*'],
        home: false,
        origin: 'HTTP_API_SITE_APP_CRYOEM_GROUPS',
        first_seen: '2026-11-03T10:00:00Z',
        last_seen: '2026-11-12T09:00:00Z',
      },
    ];
    siteAppHistory.mockResolvedValue({ id: 'cryoem', history });

    renderPage();
    const row = await screen.findByTestId('app-cryoem');
    expect(row).toHaveTextContent('Everyone');
    expect(row).not.toHaveTextContent('*');

    fireEvent.click(await screen.findByTestId('history-cryoem'));
    const table = await screen.findByTestId('history-table');
    expect(table).toHaveTextContent('Everyone');
    expect(table).not.toHaveTextContent('*');
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

// --- Opening a row -------------------------------------------------

describe('opening an app', () => {
  it('opens the detail from a click on the row itself', async () => {
    // The row was inert: everything an administrator wanted to know
    // about an app -- what it is set to, what has been served -- was
    // behind one small button at the far right.
    listSiteApps.mockResolvedValue(listing());
    renderPage();
    fireEvent.click(await screen.findByTestId('app-cryoem'));
    expect(await screen.findByTestId('details-cryoem')).toBeInTheDocument();
    expect(await screen.findByTestId('config-table')).toBeInTheDocument();
    expect(siteAppHistory).toHaveBeenCalledWith('cryoem');
  });

  it('closes the detail on a second click', async () => {
    listSiteApps.mockResolvedValue(listing());
    renderPage();
    const row = await screen.findByTestId('app-cryoem');
    fireEvent.click(row);
    await screen.findByTestId('details-cryoem');
    fireEvent.click(row);
    await waitFor(() => expect(screen.queryByTestId('details-cryoem')).toBeNull());
  });

  it('follows the app link rather than opening the row', async () => {
    // The app's own name is a link to the app. A click on it that also
    // expanded the row would leave the page mid-navigation in a state
    // nobody asked for.
    listSiteApps.mockResolvedValue(listing());
    renderPage();
    await screen.findByTestId('app-cryoem');
    const link = screen.getByRole('link', { name: 'CryoEM Pipeline' });
    fireEvent.click(link);
    await waitFor(() => expect(screen.queryByTestId('details-cryoem')).toBeNull());
  });
});

// --- Settings ------------------------------------------------------

describe('an app’s settings', () => {
  it('names the configuration parameters, and what is in force', async () => {
    // Not a vocabulary of this page's own: the administrator has to be
    // able to put the same string into condor_config_val.
    listSiteApps.mockResolvedValue(listing());
    renderPage();
    fireEvent.click(await screen.findByTestId('app-cryoem'));

    const groups = await screen.findByTestId('config-groups');
    expect(groups).toHaveTextContent('HTTP_API_SITE_APP_CRYOEM_GROUPS');
    expect(groups).toHaveTextContent('smith_lab');
    // An unset NAME is not the same as a NAME that matches the bundle:
    // one is a parameter to maintain, the other is the author's label.
    const name = screen.getByTestId('config-name');
    expect(name).toHaveTextContent('not set');
    expect(name).toHaveTextContent('CryoEM Pipeline');
    expect(name).toHaveTextContent('app.yaml');
  });

  it('says a configured app must be changed in the configuration', async () => {
    // The server refuses a change for such an id. Offering an editor
    // would be offering a 409, and worse, implying the value typed
    // into it had taken effect.
    listSiteApps.mockResolvedValue(listing({ upload_allowed: true }));
    renderPage();
    fireEvent.click(await screen.findByTestId('app-cryoem'));

    expect(await screen.findByTestId('config-readonly')).toHaveTextContent('condor_reconfig');
    expect(screen.queryByTestId('config-edit')).toBeNull();
  });

  it('offers no editor for an uploaded app while uploads are off', async () => {
    listSiteApps.mockResolvedValue(
      listing({ upload_allowed: false, apps: [app({ managed: true })] }),
    );
    siteAppConfig.mockResolvedValue({ ...editableConfig(), editable: false });
    renderPage();
    fireEvent.click(await screen.findByTestId('app-cryoem'));

    expect(await screen.findByTestId('config-note')).toHaveTextContent(
      'HTTP_API_SITE_APPS_UPLOAD',
    );
    expect(screen.queryByTestId('config-edit')).toBeNull();
  });

  it('saves an uploaded app’s settings under their parameter names', async () => {
    listSiteApps.mockResolvedValue(
      listing({ upload_allowed: true, apps: [app({ managed: true })] }),
    );
    siteAppConfig.mockResolvedValue(editableConfig());
    setSiteAppConfig.mockResolvedValue(listing({ upload_allowed: true }));
    renderPage();
    fireEvent.click(await screen.findByTestId('app-cryoem'));

    fireEvent.click(await screen.findByTestId('config-edit'));
    fireEvent.change(await screen.findByTestId('config-input-groups'), {
      target: { value: 'smith_lab, jones_lab' },
    });
    fireEvent.change(screen.getByTestId('config-input-home'), { target: { value: 'true' } });
    fireEvent.click(screen.getByTestId('config-save'));

    await waitFor(() =>
      expect(setSiteAppConfig).toHaveBeenCalledWith('cryoem', {
        HTTP_API_SITE_APP_CRYOEM_GROUPS: 'smith_lab, jones_lab',
        HTTP_API_SITE_APP_CRYOEM_HOME: 'true',
        HTTP_API_SITE_APP_CRYOEM_NAME: '',
        HTTP_API_SITE_APP_CRYOEM_DESCRIPTION: '',
        HTTP_API_SITE_APP_CRYOEM_ICON: '',
      }),
    );
  });

  it('says the configuration file wins, for a stored app', async () => {
    listSiteApps.mockResolvedValue(
      listing({ upload_allowed: true, apps: [app({ managed: true })] }),
    );
    siteAppConfig.mockResolvedValue(editableConfig());
    renderPage();
    fireEvent.click(await screen.findByTestId('app-cryoem'));
    const note = await screen.findByTestId('config-note');
    expect(note).toHaveTextContent('configuration file take precedence');
  });

  it('will not save an empty group list', async () => {
    // The server reads an empty GROUPS as a mistake rather than as
    // "nobody", and refuses it. Saying so here saves the round trip
    // and keeps the two answers the same.
    listSiteApps.mockResolvedValue(
      listing({ upload_allowed: true, apps: [app({ managed: true })] }),
    );
    siteAppConfig.mockResolvedValue(editableConfig());
    renderPage();
    fireEvent.click(await screen.findByTestId('app-cryoem'));
    fireEvent.click(await screen.findByTestId('config-edit'));
    fireEvent.change(await screen.findByTestId('config-input-groups'), {
      target: { value: '  ,  ' },
    });

    expect(await screen.findByTestId('config-groups-error')).toHaveTextContent(
      'HTTP_API_SITE_APP_CRYOEM_GROUPS',
    );
    fireEvent.click(screen.getByTestId('config-save'));
    expect(setSiteAppConfig).not.toHaveBeenCalled();
  });

  it('surfaces the server’s refusal of a settings change', async () => {
    listSiteApps.mockResolvedValue(
      listing({ upload_allowed: true, apps: [app({ managed: true })] }),
    );
    siteAppConfig.mockResolvedValue(editableConfig());
    setSiteAppConfig.mockRejectedValue(new Error('is published by this access point'));
    renderPage();
    fireEvent.click(await screen.findByTestId('app-cryoem'));
    fireEvent.click(await screen.findByTestId('config-edit'));
    fireEvent.click(await screen.findByTestId('config-save'));

    expect(await screen.findByTestId('config-save-error')).toHaveTextContent(
      'is published by this access point',
    );
  });
});

// --- The publish form ----------------------------------------------

describe('the publish form', () => {
  const zip = () => new File(['PK'], 'cryoem.zip', { type: 'application/zip' });

  function fillBundle() {
    const input = screen.getByTestId('upload-bundle') as HTMLInputElement;
    fireEvent.change(input, { target: { files: [zip()] } });
  }

  it('refuses an id the server would refuse, before sending the bundle', async () => {
    // A bundle is megabytes. Learning from a 400 that a capital letter
    // is not allowed is a slow way to be told.
    listSiteApps.mockResolvedValue(listing({ upload_allowed: true }));
    renderPage();
    const form = await screen.findByTestId('upload-form');
    fillBundle();
    fireEvent.change(screen.getByTestId('upload-id'), { target: { value: 'CryoEM' } });
    fireEvent.change(screen.getByTestId('upload-groups'), { target: { value: 'smith_lab' } });
    fireEvent.submit(form);

    expect(await screen.findByTestId('upload-id-error')).toHaveTextContent('lowercase');
    expect(uploadSiteApp).not.toHaveBeenCalled();
  });

  it.each([
    ['_shell', 'underscore'],
    ['ends-', 'begin and end'],
    ['a/b', 'only lowercase letters'],
    ['', 'id'],
  ])('refuses the id %s', async (id, message) => {
    listSiteApps.mockResolvedValue(listing({ upload_allowed: true }));
    renderPage();
    const form = await screen.findByTestId('upload-form');
    fireEvent.change(screen.getByTestId('upload-id'), { target: { value: id } });
    fireEvent.change(screen.getByTestId('upload-groups'), { target: { value: 'smith_lab' } });
    fireEvent.submit(form);

    expect(await screen.findByTestId('upload-id-error')).toHaveTextContent(message);
    expect(uploadSiteApp).not.toHaveBeenCalled();
  });

  it('says so on the way out of the id field, not only on submit', async () => {
    // The bundle input is required, so a real browser refuses the
    // submit before the form's own checks run. jsdom does not, which
    // is how an id error that only fires on submit looks tested.
    listSiteApps.mockResolvedValue(listing({ upload_allowed: true }));
    renderPage();
    await screen.findByTestId('upload-form');
    const field = screen.getByTestId('upload-id');
    fireEvent.change(field, { target: { value: 'CryoEM' } });
    fireEvent.blur(field);

    expect(await screen.findByTestId('upload-id-error')).toHaveTextContent('lowercase');
  });

  it('agrees with the server about what an id may be', () => {
    // The rules are siteapps.ValidateID's. Mirrored here so the form
    // can say so first; wrong in either direction is worse than not
    // checking at all.
    expect(validateSiteAppID('cryoem')).toBeNull();
    expect(validateSiteAppID('seq-qc_2')).toBeNull();
    expect(validateSiteAppID('a')).toBeNull();
    expect(validateSiteAppID('_shell')).not.toBeNull();
    expect(validateSiteAppID('-lead')).not.toBeNull();
    expect(validateSiteAppID('trail_')).not.toBeNull();
    expect(validateSiteAppID('Upper')).not.toBeNull();
    expect(validateSiteAppID('has space')).not.toBeNull();
    expect(validateSiteAppID('a'.repeat(65))).not.toBeNull();
    expect(validateSiteAppID('a'.repeat(64))).toBeNull();
  });

  it('refuses to publish to nobody', async () => {
    listSiteApps.mockResolvedValue(listing({ upload_allowed: true }));
    renderPage();
    const form = await screen.findByTestId('upload-form');
    fireEvent.change(screen.getByTestId('upload-id'), { target: { value: 'cryoem' } });
    fireEvent.submit(form);

    expect(await screen.findByTestId('upload-groups-error')).toBeInTheDocument();
    expect(uploadSiteApp).not.toHaveBeenCalled();
  });

  it('makes typed groups into pills, and removes one', async () => {
    listSiteApps.mockResolvedValue(listing({ upload_allowed: true }));
    uploadSiteApp.mockResolvedValue(listing({ upload_allowed: true }));
    renderPage();
    const form = await screen.findByTestId('upload-form');
    fireEvent.change(screen.getByTestId('upload-id'), { target: { value: 'cryoem' } });

    const groups = screen.getByTestId('upload-groups');
    fireEvent.change(groups, { target: { value: 'smith_lab' } });
    fireEvent.keyDown(groups, { key: 'Enter' });
    fireEvent.change(groups, { target: { value: 'jones_lab' } });
    fireEvent.keyDown(groups, { key: 'Enter' });
    expect(await screen.findByTestId('group-pill-smith_lab')).toBeInTheDocument();

    fireEvent.click(screen.getByTestId('group-remove-smith_lab'));
    await waitFor(() => expect(screen.queryByTestId('group-pill-smith_lab')).toBeNull());

    fireEvent.submit(form);
    await waitFor(() => expect(uploadSiteApp).toHaveBeenCalled());
    const sent = uploadSiteApp.mock.calls[0][0] as FormData;
    expect(sent.get('groups')).toBe('jones_lab');
  });

  it('sends * for everyone signed in, and does not ask for groups as well', async () => {
    listSiteApps.mockResolvedValue(listing({ upload_allowed: true }));
    uploadSiteApp.mockResolvedValue(listing({ upload_allowed: true }));
    renderPage();
    const form = await screen.findByTestId('upload-form');
    fireEvent.change(screen.getByTestId('upload-id'), { target: { value: 'cryoem' } });
    fireEvent.click(screen.getByTestId('upload-everyone'));
    // The group box is gone: "everyone" and "these groups" are one
    // decision, and a form offering both invites a list nobody reads.
    expect(screen.queryByTestId('upload-groups')).toBeNull();
    fireEvent.submit(form);

    await waitFor(() => expect(uploadSiteApp).toHaveBeenCalled());
    const sent = uploadSiteApp.mock.calls[0][0] as FormData;
    expect(sent.get('groups')).toBe('*');
  });

  it('will not take * as a group name', async () => {
    // Typing it is far more likely a misunderstanding than a request
    // to publish to the whole access point, and the checkbox is the
    // way to mean it.
    listSiteApps.mockResolvedValue(listing({ upload_allowed: true }));
    renderPage();
    await screen.findByTestId('upload-form');
    const groups = screen.getByTestId('upload-groups');
    fireEvent.change(groups, { target: { value: '*' } });
    fireEvent.keyDown(groups, { key: 'Enter' });

    expect(await screen.findByTestId('upload-groups-note')).toBeInTheDocument();
    expect(screen.queryByTestId('group-pill-*')).toBeNull();
  });

  it('does not list one group twice', async () => {
    listSiteApps.mockResolvedValue(listing({ upload_allowed: true }));
    renderPage();
    await screen.findByTestId('upload-form');
    const groups = screen.getByTestId('upload-groups');
    // The server compares group names case-insensitively, so these
    // are one group and not two.
    fireEvent.change(groups, { target: { value: 'smith_lab, Smith_Lab, smith_lab' } });

    await screen.findByTestId('group-pill-smith_lab');
    expect(screen.getAllByTestId(/^group-pill-/)).toHaveLength(1);
  });

  it('shows the publish happening, and what was published', async () => {
    // Re-publishing an app that is already in the table changes
    // nothing else visible about the row, so without this the page
    // looks like it did nothing.
    listSiteApps.mockResolvedValue(listing({ upload_allowed: true }));
    let release: (v: AdminSiteApps) => void = () => {};
    uploadSiteApp.mockImplementation(
      () => new Promise<AdminSiteApps>((resolve) => (release = resolve)),
    );
    renderPage();
    const form = await screen.findByTestId('upload-form');
    fireEvent.change(screen.getByTestId('upload-id'), { target: { value: 'cryoem' } });
    fireEvent.change(screen.getByTestId('upload-groups'), { target: { value: 'smith_lab' } });
    fireEvent.submit(form);

    const button = await screen.findByTestId('upload-submit');
    await waitFor(() => expect(button).toBeDisabled());
    expect(screen.getByTestId('upload-busy')).toBeInTheDocument();

    release(
      listing({
        upload_allowed: true,
        apps: [
          app({
            managed: true,
            version: '2.2.0',
            uploaded_at: '2026-11-13T09:30:00Z',
            uploaded_by: 'alice',
          }),
        ],
      }),
    );

    const result = await screen.findByTestId('upload-result');
    expect(result).toHaveTextContent('2.2.0');
    expect(result).toHaveTextContent('cryoem');
    expect(button).not.toBeDisabled();
  });

  it('says when a published version went up, in the row', async () => {
    listSiteApps.mockResolvedValue(
      listing({
        upload_allowed: true,
        apps: [app({ managed: true, uploaded_at: '2026-11-13T09:30:00Z', uploaded_by: 'alice' })],
      }),
    );
    renderPage();
    expect(await screen.findByTestId('published-cryoem')).toBeInTheDocument();
    expect(screen.getByTestId('app-cryoem')).toHaveTextContent('alice');
  });
});
