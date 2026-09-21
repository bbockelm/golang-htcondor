import { expect, test } from '@playwright/test';

import { adminPassword, loginAs, loginAsAdmin, userPassword } from './fixtures/login';
import { serverLog } from './fixtures/serverlog';

// Taking a scope off somebody else's grant, driven by a browser.
//
// This is the case the feature exists for: an agent was authorized with
// more than it needed, and an operator wants to cut it back without
// revoking it -- revoking means somebody has to be present to authorize
// the agent again.
//
// The server tests post the scope set they assume the page sends. That
// assumption is the thing a browser has to check: the page sends the
// scopes to KEEP, computed by filtering the row's own chips, so a wrong
// filter removes the wrong scope while every server test still passes.
//
// The property is the one the page's copy claims -- removal applies to
// the whole grant, so it is still gone after the client refreshes. A
// narrowing a refresh undoes looks correct in the UI right up until the
// scope reappears.

const log = serverLog();
const password = adminPassword(log);
const userPw = userPassword(log);

const REQUESTED = ['openid', 'offline_access', 'mcp:read', 'mcp:write'];

// Nothing listens here; the spec answers the redirect itself so the
// authorization code can be read off the Location header.
const REDIRECT_URI = 'http://127.0.0.1:39519/callback';

type Client = { clientId: string; clientSecret: string };

async function registerClient(request: any, baseURL: string): Promise<Client> {
  const resp = await request.post(`${baseURL}/mcp/oauth2/register`, {
    data: {
      redirect_uris: [REDIRECT_URI],
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      scope: REQUESTED.join(' '),
      client_name: 'admin-token-scope-browser-test',
    },
  });
  expect(resp.status(), await resp.text()).toBe(201);
  const body = await resp.json();
  return { clientId: body.client_id, clientSecret: body.client_secret };
}

// authorizeAsUser produces a real grant belonging to somebody other than
// the operator who will narrow it.
async function authorizeAsUser(page: any, baseURL: string, client: Client): Promise<string> {
  const authorize =
    `${baseURL}/mcp/oauth2/authorize?response_type=code` +
    `&client_id=${encodeURIComponent(client.clientId)}` +
    `&redirect_uri=${encodeURIComponent(REDIRECT_URI)}` +
    `&scope=${encodeURIComponent(REQUESTED.join(' '))}` +
    `&state=admintokentest`;

  await page.route(/^http:\/\/127\.0\.0\.1:39519\//, (route: any) =>
    route.fulfill({ status: 200, contentType: 'text/html', body: '<html>callback</html>' }),
  );
  await page.goto(authorize, { waitUntil: 'domcontentloaded' });

  const approve = page.locator('#approveBtn');
  await expect(approve, 'expected the consent page').toHaveCount(1);

  const [resp] = await Promise.all([
    page.waitForResponse(
      (r: any) => r.url().includes('/mcp/oauth2/consent') && r.request().method() === 'POST',
    ),
    approve.click(),
  ]);
  const codeURL = resp.headers()['location'] ?? '';
  expect(codeURL, `consent did not redirect (status ${resp.status()})`).toContain(REDIRECT_URI);
  const code = new URL(codeURL).searchParams.get('code');
  expect(code, `no authorization code in ${codeURL}`).toBeTruthy();
  return code as string;
}

async function exchange(request: any, baseURL: string, client: Client, code: string) {
  const resp = await request.post(`${baseURL}/mcp/oauth2/token`, {
    form: {
      grant_type: 'authorization_code',
      code,
      redirect_uri: REDIRECT_URI,
      client_id: client.clientId,
      client_secret: client.clientSecret,
    },
  });
  expect(resp.status(), await resp.text()).toBe(200);
  return resp.json();
}

async function refresh(request: any, baseURL: string, client: Client, refreshToken: string) {
  const resp = await request.post(`${baseURL}/mcp/oauth2/token`, {
    form: {
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
      client_id: client.clientId,
      client_secret: client.clientSecret,
    },
  });
  return { status: resp.status(), body: await resp.json() };
}

test('an operator removes a scope and the client cannot refresh it back', async ({
  page,
  context,
  request,
  baseURL,
}) => {
  // The grant belongs to the ordinary user, so the operator is acting on
  // somebody else's access -- which is the whole point of the page.
  //
  // One browser context, two identities in turn: a context made by hand
  // inherits neither baseURL nor ignoreHTTPSErrors from the config, and
  // every relative navigation in the login fixture then fails for a
  // reason that has nothing to do with this test.
  const client = await registerClient(request, baseURL!);
  await loginAs(page, 'user', userPw);
  const code = await authorizeAsUser(page, baseURL!, client);
  const issued = await exchange(request, baseURL!, client, code);
  expect(String(issued.scope ?? ''), 'the fixture grant lacks mcp:write').toContain('mcp:write');

  // Become the operator. Both the SPA session and the IDP's own cookie
  // have to go, or the next /login silently reuses the user's identity
  // and the test would assert an admin action it never performed.
  await context.clearCookies();
  await loginAsAdmin(page, password);
  await page.goto('/admin/tokens');
  await expect(page.getByRole('heading', { name: 'OAuth2 Tokens' })).toBeVisible();

  // Filter to this client so the chips below belong to the grant just
  // made, not to whatever else the demo server has issued.
  await page.getByPlaceholder(/client/i).fill(client.clientId);

  const off = page.getByRole('button', { name: 'Switch mcp:write off for this grant and its paired token' }).first();
  await expect(off, 'no switchable mcp:write chip for the new grant').toBeVisible();
  await off.click();

  // The chip stays, and now offers to switch the scope back on. It
  // vanishing is what made a mis-click unrecoverable -- there was nothing
  // left to click -- so its continued presence IS the fix.
  // One grant, two rows -- the access token and the refresh token -- and
  // narrowing applies to both, so do not be precise about how many chips
  // that is. What matters is that the scope is still there to click.
  await expect(
    page.getByRole('button', { name: 'Switch mcp:write back on' }).first(),
    'the scope disappeared instead of switching off, so it cannot be restored',
  ).toBeVisible();

  // The client still works -- narrowing is not revocation -- but cannot
  // get the scope back by refreshing, which is what writing only the
  // access-token row would have allowed.
  const after = await refresh(request, baseURL!, client, issued.refresh_token);
  expect(after.status, `the grant stopped working entirely: ${JSON.stringify(after.body)}`).toBe(200);
  expect(String(after.body.scope ?? ''), 'the client refreshed mcp:write back').not.toContain(
    'mcp:write',
  );
  expect(String(after.body.scope ?? ''), 'refreshing dropped the scopes that were kept').toContain(
    'mcp:read',
  );

  // Switch it back on. This is the half that makes the control a toggle
  // rather than a one-way door: an operator who mis-clicks can undo it,
  // instead of revoking the grant and finding somebody to authorize the
  // agent again.
  await page.getByRole('button', { name: 'Switch mcp:write back on' }).first().click();
  await expect(
    page.getByRole('button', { name: 'Switch mcp:write off for this grant and its paired token' }).first(),
    'the scope did not come back on',
  ).toBeVisible();

  const restored = await refresh(request, baseURL!, client, after.body.refresh_token);
  expect(restored.status, `the grant broke after restoring: ${JSON.stringify(restored.body)}`).toBe(200);
  expect(
    String(restored.body.scope ?? ''),
    'the restored scope did not survive the refresh',
  ).toContain('mcp:write');
});
