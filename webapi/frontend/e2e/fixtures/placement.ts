import type { Page } from '@playwright/test';
import type { PlacementAuthorization, PlacementStatus } from '../../src/lib/api';
import type {
  DirAccount,
  DirAuthorization,
  DirIdentity,
  DirProject,
  EditResponse,
  MapfileStatus,
} from '../../src/lib/placementAdmin';
import { SMOKE_NOW } from './clock';

// The placementd directory, as a daemon advertising API version 2 serves it.

const at = (secondsFromNow: number) => new Date((SMOKE_NOW + secondsFromNow) * 1000).toISOString();

export const placementStatusV2: PlacementStatus = {
  available: true,
  address: '<127.0.0.1:9620>',
  api_version: 2,
};

export const placementIdentitiesFixture: DirIdentity[] = [
  {
    id: '6f1c2c1e-1111-4a3b-9c1d-000000000001',
    source: 'mapfile',
    version: 2,
    identity: 'alice@wisc.edu',
    account: 'alice@ap.smoke.example',
    expired: false,
    authorizations: ['READ', 'WRITE'],
    projects: ['Chem101'],
    default_project: 'Chem101',
  },
  {
    id: '6f1c2c1e-1111-4a3b-9c1d-000000000002',
    source: 'internal',
    version: 5,
    identity: 'bob@cilogon.org',
    account: 'bob@ap.smoke.example',
    display_name: 'Bob',
    expires_at: at(30 * 86400),
    expired: false,
    authorizations: ['READ'],
    projects: [],
  },
];

export const placementAccountsFixture: DirAccount[] = [
  {
    id: '6f1c2c1e-2222-4a3b-9c1d-000000000001',
    source: 'internal',
    version: 3,
    name: 'bob@ap.smoke.example',
    authorizations: ['READ'],
    projects: [],
    identities: ['bob@cilogon.org'],
  },
];

export const placementProjectsFixture: DirProject[] = [
  { id: '6f1c2c1e-3333-4a3b-9c1d-000000000001', source: 'mapfile', version: 1, name: 'Chem101', accounts: ['alice@ap.smoke.example'] },
];

export const placementAuthorizationsFixture: DirAuthorization[] = [
  { id: '6f1c2c1e-4444-4a3b-9c1d-000000000001', source: 'mapfile', version: 1, name: 'READ', label: 'Read', color: '#2563eb', requestable: true },
  { id: '6f1c2c1e-4444-4a3b-9c1d-000000000002', source: 'mapfile', version: 1, name: 'WRITE', label: 'Write', color: 'green', requestable: true },
];

export const mapfileStatusFixture: MapfileStatus = {
  load_time: at(-120),
  load_attempt_time: at(-120),
  ok: false,
  quarantined: 1,
  conflicts: 0,
  user_mapfile: '/etc/condor/placementd.map',
  problems: [
    { kind: 'malformed', file: '/etc/condor/placementd.map', line: 12, key: 'carol@wisc.edu', message: 'expiry is not a number' },
  ],
};

const legacyAuthz: PlacementAuthorization[] = placementAuthorizationsFixture.map((a) => ({
  name: a.name,
  label: a.label,
  color: a.color,
  description: a.description,
}));

// installPlacementFixtures answers /api/v1/placement/*; install it after
// installApiFixtures so these routes take precedence. Returns the edit
// requests the page sent.
export async function installPlacementFixtures(page: Page): Promise<{ edits: { method: string; path: string; body: unknown }[] }> {
  const edits: { method: string; path: string; body: unknown }[] = [];
  const lists: Record<string, unknown[]> = {
    identities: placementIdentitiesFixture,
    accounts: placementAccountsFixture,
    projects: placementProjectsFixture,
    authorizations: placementAuthorizationsFixture,
  };
  const ok: EditResponse = { committed: true, dry_run: false, results: [{ index: 0, id: 'new', version: 1 }] };

  await page.route('**/api/v1/placement/**', async (route) => {
    const req = route.request();
    const path = new URL(req.url()).pathname;
    if (req.method() !== 'GET') {
      edits.push({ method: req.method(), path, body: req.postDataJSON?.() ?? null });
      await route.fulfill({ status: req.method() === 'POST' && /admin\/[a-z]+$/.test(path) ? 201 : 200, json: ok });
      return;
    }
    if (path === '/api/v1/placement/status') return route.fulfill({ json: placementStatusV2 });
    if (path === '/api/v1/placement/authorizations') return route.fulfill({ json: { authorizations: legacyAuthz } });
    if (path === '/api/v1/placement/tokens') return route.fulfill({ json: { tokens: [] } });
    if (path === '/api/v1/placement/users') return route.fulfill({ json: { users: [] } });
    if (path === '/api/v1/placement/admin/mapfile-status') return route.fulfill({ json: mapfileStatusFixture });
    const kind = path.match(/^\/api\/v1\/placement\/admin\/([a-z]+)$/)?.[1];
    if (kind && kind in lists) return route.fulfill({ json: { [kind]: lists[kind] } });
    await route.fulfill({ status: 404, json: { error: 'Not Found', message: 'no fixture' } });
  });
  return { edits };
}
