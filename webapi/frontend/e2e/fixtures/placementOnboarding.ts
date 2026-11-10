import type { Page } from '@playwright/test';
import type { PlacementDeviceRequest, PlacementIssued, PlacementMe, Session } from '../../src/lib/api';
import { SMOKE_NOW } from './clock';

// Placement onboarding fixtures. Installed after installApiFixtures, so
// these routes win (Playwright tries the most recently added route first).

export const placementOnlySession: Session = {
  authenticated: true,
  is_admin: false,
  placement_only: true,
  placement: { identity: 'zoe@uni.example', display_name: 'Zoe Q' },
};

// The same person once an administrator has onboarded them: a full session
// as their account.
export const onboardedSession: Session = {
  authenticated: true,
  is_admin: false,
  username: 'zoe@ap.smoke.example',
  placement: {
    identity: 'zoe@uni.example',
    display_name: 'Zoe Q',
    account: 'zoe@ap.smoke.example',
    levels: ['READ', 'WRITE'],
    projects: ['SmokeProject'],
    project: 'SmokeProject',
  },
};

export const placementMeFixture: PlacementMe = {
  identity: 'zoe@uni.example',
  display_name: 'Zoe Q',
  authorized: true,
  expired: false,
  account: 'zoe@ap.smoke.example',
  authorizations: [
    { name: 'READ', label: 'Read', color: 'normal', description: 'Get a list of jobs, examine jobs' },
    { name: 'WRITE', label: 'Write', color: 'warning', description: 'Submit and manage jobs' },
  ],
  projects: [
    { name: 'SmokeProject', default: true, enabled: true },
    { name: 'RetiredProject', default: false, enabled: false },
  ],
  account_enabled: true,
  records_available: true,
};

// An unsigned token with iat/exp claims, as the page never verifies one.
function smokeToken(): string {
  const enc = (o: object) => Buffer.from(JSON.stringify(o)).toString('base64url');
  return `${enc({ alg: 'HS256' })}.${enc({ sub: 'zoe@ap.smoke.example', iat: SMOKE_NOW, exp: SMOKE_NOW + 86400 })}.sig`;
}

export const placementIssuedFixture: PlacementIssued = {
  token: smokeToken(),
  ap_user_id: 'zoe@ap.smoke.example',
  issued_at: new Date(SMOKE_NOW * 1000).toISOString(),
  expires_at: new Date((SMOKE_NOW + 86400) * 1000).toISOString(),
  project: 'SmokeProject',
  authorizations: ['READ', 'WRITE'],
  user_config: 'SCHEDD_HOST = ap.smoke.example\nCOLLECTOR_HOST = cm.smoke.example',
};

export const placementDeviceFixture: PlacementDeviceRequest = {
  user_code: 'BCDF-GHJK',
  client_id: 'placement_client',
  client_name: 'Placement Client',
  state: 'pending',
  expires_at: new Date((SMOKE_NOW + 1800) * 1000).toISOString(),
};

export async function installPlacementFixtures(page: Page, opts: { placementOnly?: boolean } = {}) {
  if (opts.placementOnly) {
    await page.route('**/api/v1/auth/me', (route) => route.fulfill({ json: placementOnlySession }));
  }
  await page.route('**/api/v1/placement/me**', async (route) => {
    const req = route.request();
    const path = new URL(req.url()).pathname;
    if (path === '/api/v1/placement/me') {
      await route.fulfill({ json: placementMeFixture });
      return;
    }
    if (path === '/api/v1/placement/me/token' && req.method() === 'POST') {
      const body = req.postDataJSON() as { user_code?: string };
      if (body.user_code) {
        const { token: _token, ...rest } = placementIssuedFixture;
        void _token;
        await route.fulfill({ status: 201, json: { ...rest, device: { ...placementDeviceFixture, state: 'approved' } } });
        return;
      }
      await route.fulfill({ status: 201, json: placementIssuedFixture });
      return;
    }
    if (path === '/api/v1/placement/me/device/BCDF-GHJK') {
      await route.fulfill({ json: placementDeviceFixture });
      return;
    }
    if (path === '/api/v1/placement/me/device/BCDF-GHJK/deny' && req.method() === 'POST') {
      await route.fulfill({ json: { status: 'canceled' } });
      return;
    }
    await route.fulfill({ status: 404, json: { error: 'Not Found', message: 'That code was not recognized.' } });
  });
}
