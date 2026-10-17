import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type {
  DirAccount,
  DirAuthorization,
  DirIdentity,
  DirProject,
  EditResponse,
  MapfileStatus,
  PlacementKind,
} from '@/lib/placementAdmin';

const list = vi.fn();
const update = vi.fn();
const create = vi.fn();
const remove = vi.fn();
const adopt = vi.fn();
const adoptAll = vi.fn();
const batch = vi.fn();
const mapfileStatus = vi.fn();

vi.mock('@/lib/placementAdmin', async () => {
  const actual = await vi.importActual<typeof import('@/lib/placementAdmin')>('@/lib/placementAdmin');
  return {
    ...actual,
    placementAdmin: {
      list: (...a: unknown[]) => list(...a),
      get: vi.fn(),
      create: (...a: unknown[]) => create(...a),
      update: (...a: unknown[]) => update(...a),
      remove: (...a: unknown[]) => remove(...a),
      adopt: (...a: unknown[]) => adopt(...a),
      adoptAll: () => adoptAll(),
      batch: (...a: unknown[]) => batch(...a),
      mapfileStatus: () => mapfileStatus(),
    },
  };
});

const { PlacementAdminError } = await import('@/lib/placementAdmin');
const { Directory } = await import('./Directory');
const { MapfileStatusBanner } = await import('./MapfileStatusBanner');
const { onboardOperations } = await import('./OnboardWizard');
const { changedFields } = await import('./EntityForm');

const identities: DirIdentity[] = [
  {
    id: 'i-map',
    source: 'mapfile',
    version: 3,
    identity: 'alice@wisc.edu',
    account: 'alice@ap.example',
    expired: false,
    authorizations: ['READ'],
    projects: ['ProjA'],
  },
  {
    id: 'i-int',
    source: 'internal',
    version: 5,
    identity: 'bob@cilogon',
    account: 'bob@ap.example',
    display_name: 'Bob',
    expired: false,
    authorizations: ['READ', 'WRITE'],
    projects: [],
  },
];
const accounts: DirAccount[] = [
  {
    id: 'a-bob',
    source: 'internal',
    version: 2,
    name: 'bob@ap.example',
    authorizations: ['READ', 'WRITE'],
    projects: ['ProjA'],
    default_project: 'ProjA',
    identities: ['bob@cilogon'],
  },
];
const projects: DirProject[] = [{ id: 'p1', source: 'internal', version: 1, name: 'ProjA', accounts: [] }];
const authorizations: DirAuthorization[] = [
  { id: 'z1', source: 'mapfile', version: 1, name: 'READ', label: 'Read', color: '#2563eb', requestable: true },
  { id: 'z2', source: 'mapfile', version: 1, name: 'WRITE', label: 'Write', requestable: true },
];
const ok: EditResponse = { committed: true, dry_run: false, results: [{ index: 0, id: 'x', version: 1 }] };

function renderDirectory() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <Directory />
    </QueryClientProvider>,
  );
}

const rowFor = (id: string) => screen.findByTestId(`dir-row-${id}`);

describe('Directory', () => {
  beforeEach(() => {
    for (const m of [list, update, create, remove, adopt, adoptAll, batch, mapfileStatus]) m.mockReset();
    list.mockImplementation((kind: PlacementKind) =>
      Promise.resolve(
        { identities, accounts, projects, authorizations }[kind],
      ),
    );
  });

  it('shows the source of each row, with Adopt for map file rows and Edit for internal ones', async () => {
    renderDirectory();
    const mapRow = await rowFor('i-map');
    expect(within(mapRow).getByText('mapfile')).toBeInTheDocument();
    expect(within(mapRow).getByRole('button', { name: 'Adopt' })).toBeInTheDocument();
    expect(within(mapRow).queryByRole('button', { name: 'Edit' })).toBeNull();

    const intRow = await rowFor('i-int');
    expect(within(intRow).getByText('internal')).toBeInTheDocument();
    expect(within(intRow).getByRole('button', { name: 'Edit' })).toBeInTheDocument();
    expect(within(intRow).queryByRole('button', { name: 'Adopt' })).toBeNull();
    // Authorization chips use the operator's labels.
    expect(within(intRow).getByText('Write')).toBeInTheDocument();
  });

  it('adopts a map file row at the version it was loaded at', async () => {
    adopt.mockResolvedValue({ ...ok, results: [{ index: 0, id: 'i-map', version: 4, warning: 'Still in the map file.' }] });
    renderDirectory();
    fireEvent.click(within(await rowFor('i-map')).getByRole('button', { name: 'Adopt' }));
    await waitFor(() => expect(adopt).toHaveBeenCalledWith('identities', 'i-map', 3));
    expect(await screen.findByText('Still in the map file.')).toBeInTheDocument();
  });

  it('switches sub-views and filters by text', async () => {
    renderDirectory();
    await rowFor('i-map');
    fireEvent.click(screen.getByRole('tab', { name: 'Accounts' }));
    expect(await rowFor('a-bob')).toBeInTheDocument();
    expect(list).toHaveBeenCalledWith('accounts', undefined);

    fireEvent.click(screen.getByRole('tab', { name: 'Identities' }));
    await rowFor('i-map');
    fireEvent.change(screen.getByPlaceholderText('Filter identities'), { target: { value: 'cilogon' } });
    await waitFor(() => expect(screen.queryByTestId('dir-row-i-map')).toBeNull());
    expect(screen.getByTestId('dir-row-i-int')).toBeInTheDocument();
  });

  it('sends a ClassAd expression filter to the server', async () => {
    renderDirectory();
    await rowFor('i-map');
    fireEvent.click(screen.getByRole('button', { name: 'ClassAd expression' }));
    fireEvent.change(screen.getByPlaceholderText('Source == "internal"'), { target: { value: 'Expired' } });
    fireEvent.click(screen.getByRole('button', { name: 'Apply' }));
    await waitFor(() => expect(list).toHaveBeenCalledWith('identities', { constraint: 'Expired' }));
  });

  it('edits only the changed fields, with the expected version', async () => {
    update.mockResolvedValue(ok);
    renderDirectory();
    fireEvent.click(within(await rowFor('i-int')).getByRole('button', { name: 'Edit' }));
    const dialog = await screen.findByRole('dialog', { name: 'Edit identity' });
    fireEvent.change(within(dialog).getByLabelText('Display name'), { target: { value: '' } });
    fireEvent.change(within(dialog).getByLabelText('Comment'), { target: { value: 'TA' } });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Save' }));
    await waitFor(() =>
      expect(update).toHaveBeenCalledWith('identities', 'i-int', 5, { display_name: null, comment: 'TA' }),
    );
  });

  it('says to reload when the row changed since it was loaded', async () => {
    update.mockRejectedValue(
      new PlacementAdminError(409, 'version mismatch', { placement_code: 14, results: [] }),
    );
    renderDirectory();
    fireEvent.click(within(await rowFor('i-int')).getByRole('button', { name: 'Edit' }));
    const dialog = await screen.findByRole('dialog');
    fireEvent.change(within(dialog).getByLabelText('Comment'), { target: { value: 'x' } });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Save' }));
    expect(await within(dialog).findByText(/changed since you loaded it/)).toBeInTheDocument();
    fireEvent.click(within(dialog).getByRole('button', { name: 'Reload' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
  });

  it('offers a delete with references when the row is still referenced', async () => {
    remove
      .mockRejectedValueOnce(
        new PlacementAdminError(409, 'still referenced', { placement_code: 17, cascade_required: true }),
      )
      .mockResolvedValueOnce(ok);
    renderDirectory();
    fireEvent.click(screen.getByRole('tab', { name: 'Accounts' }));
    const row = await rowFor('a-bob');
    fireEvent.click(within(row).getByRole('button', { name: 'Delete' }));
    // Armed: the first button is now Cancel, the second confirms.
    fireEvent.click(within(row).getByRole('button', { name: 'Delete' }));
    await waitFor(() =>
      expect(remove).toHaveBeenCalledWith('accounts', 'a-bob', { cascade: false, expectedVersion: 2 }),
    );
    const cascade = await within(row).findByRole('button', { name: 'Delete with references' });
    fireEvent.click(cascade);
    fireEvent.click(within(row).getByRole('button', { name: 'Delete all' }));
    await waitFor(() =>
      expect(remove).toHaveBeenLastCalledWith('accounts', 'a-bob', { cascade: true, expectedVersion: 2 }),
    );
  });

  it('onboards a user in one batch', async () => {
    batch.mockResolvedValue(ok);
    renderDirectory();
    await rowFor('i-map');
    fireEvent.click(screen.getByRole('button', { name: 'Onboard user' }));
    const dialog = await screen.findByRole('dialog', { name: 'Onboard user' });
    fireEvent.change(within(dialog).getByLabelText('Identity'), { target: { value: 'carol@wisc.edu' } });
    fireEvent.change(within(dialog).getByLabelText(/^Account/), { target: { value: 'carol@ap.example' } });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Onboard' }));
    await waitFor(() => expect(batch).toHaveBeenCalledTimes(1));
    const [ops, dryRun] = batch.mock.calls[0];
    expect(dryRun).toBe(false);
    expect(ops.map((o: { operation: string; target_type: string }) => `${o.operation} ${o.target_type}`)).toEqual([
      'Create Account',
      'Create Identity',
    ]);
    expect(ops[0].fields.authorizations).toEqual(['READ', 'WRITE']);
    expect(ops[1].fields).toEqual({ identity: 'carol@wisc.edu', account: 'carol@ap.example' });
  });
});

describe('onboardOperations', () => {
  const base = {
    identity: 'dan@wisc.edu',
    displayName: '',
    account: 'bob@ap.example',
    expiresAt: null,
    authorizations: ['READ', 'WRITE'],
    projects: ['ProjA'],
    defaultProject: 'ProjA',
  };
  it('reuses an existing account with unchanged grants', () => {
    expect(onboardOperations(base, accounts[0]).map((o) => o.operation)).toEqual(['Create']);
  });
  it('updates an internal account whose grants changed, at its version', () => {
    const ops = onboardOperations({ ...base, authorizations: ['READ'] }, accounts[0]);
    expect(ops[0]).toMatchObject({ operation: 'Update', id: 'a-bob', expected_version: 2 });
    expect(ops[1]).toMatchObject({ operation: 'Create', target_type: 'Identity' });
  });
  it('never changes the grants of a map file account', () => {
    const ops = onboardOperations({ ...base, authorizations: ['READ'] }, { ...accounts[0], source: 'mapfile' });
    expect(ops.map((o) => o.target_type)).toEqual(['Identity']);
  });
});

describe('changedFields', () => {
  it('sends null to clear on update and omits blanks on create', () => {
    const start = { display_name: 'Bob', comment: '', expires_at: '2027-01-01T00:00:00Z' };
    expect(changedFields(start, { ...start, display_name: '', expires_at: null }, false)).toEqual({
      display_name: null,
      expires_at: null,
    });
    expect(changedFields(start, { ...start, display_name: '' }, true)).toEqual({
      expires_at: '2027-01-01T00:00:00Z',
    });
  });
});

describe('MapfileStatusBanner', () => {
  it('shows the load time, counts and problems', async () => {
    const status: MapfileStatus = {
      load_time: '2026-10-16T12:00:00Z',
      ok: false,
      quarantined: 2,
      conflicts: 1,
      user_mapfile: '/etc/condor/placementd.map',
      problems: [{ kind: 'malformed', file: '/etc/condor/placementd.map', line: 7, key: 'carol', message: 'bad expiry' }],
    };
    mapfileStatus.mockResolvedValue(status);
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(
      <QueryClientProvider client={client}>
        <MapfileStatusBanner />
      </QueryClientProvider>,
    );
    const banner = await screen.findByTestId('mapfile-status');
    expect(within(banner).getByText('2')).toBeInTheDocument();
    expect(within(banner).getByText('1')).toBeInTheDocument();
    expect(within(banner).getByText('1 problem')).toBeInTheDocument();
    expect(within(banner).getByText(/bad expiry/)).toBeInTheDocument();
  });
});
