import { expect, test } from '@playwright/test';
import { loginAs, userPassword } from './fixtures/login';
import { serverLog } from './fixtures/serverlog';

// What the consent page actually grants, driven by a browser.
//
// The server-side tests here post the scope fields they assume the page
// posts, so they agree with a page that submits nothing: the scope
// checkboxes once sat outside the <form>, every login granted "openid"
// alone, and the whole server suite stayed green. Only a browser decides
// which controls are submitted, so only a browser can check this.
//
// Two properties, and the second has never been covered anywhere:
//   - approving with everything ticked grants everything requested;
//   - UNticking a box actually withholds that scope. A consent UI that
//     appears to restrict something and does not is worse than one that
//     grants too much visibly.

const log = serverLog();
const userPw = userPassword(log);

// Nothing listens here. The spec intercepts requests to it and answers
// them itself, so the browser completes the navigation and the
// authorization code is readable from the URL -- rather than the run
// depending on how a dead port happens to fail.
// Port chosen to be one Chromium will navigate to: it blocks a set of
// well-known ports (9/discard among them) with ERR_UNSAFE_PORT before
// the request is ever made.
const REDIRECT_URI = 'http://127.0.0.1:39517/callback';
const REDIRECT_GLOB = 'http://127.0.0.1:39517/**';
const REQUESTED = ['openid', 'profile', 'email', 'offline_access', 'mcp:read', 'mcp:write'];

type Client = { clientId: string; clientSecret: string };

// registerClient creates an OAuth2 client through Dynamic Client
// Registration (RFC 7591), which needs no admin session.
async function registerClient(request: any, baseURL: string): Promise<Client> {
  const resp = await request.post(`${baseURL}/mcp/oauth2/register`, {
    data: {
      redirect_uris: [REDIRECT_URI],
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      scope: REQUESTED.join(' '),
      client_name: 'consent-scope-browser-test',
    },
  });
  expect(resp.status(), await resp.text()).toBe(201);
  const body = await resp.json();
  expect(body.client_id, 'DCR returned no client_id').toBeTruthy();
  return { clientId: body.client_id, clientSecret: body.client_secret };
}

// approveConsent walks the browser through /authorize, optionally
// unticking scopes, and returns the authorization code.
async function approveConsent(page: any, baseURL: string, client: Client, untick: string[]) {
  const authorize =
    `${baseURL}/mcp/oauth2/authorize?response_type=code` +
    `&client_id=${encodeURIComponent(client.clientId)}` +
    `&redirect_uri=${encodeURIComponent(REDIRECT_URI)}` +
    `&scope=${encodeURIComponent(REQUESTED.join(' '))}` +
    `&state=browsertest`;

  // Absorb the redirect target so a failed navigation to it cannot fail
  // the test; the code is read from the Location header below regardless.
  await page.route(/^http:\/\/127\.0\.0\.1:39517\//, (route: any) =>
    route.fulfill({ status: 200, contentType: 'text/html', body: '<html>callback</html>' }),
  );

  await page.goto(authorize, { waitUntil: 'domcontentloaded' });

  // The consent page, not an error or the SPA shell: a wrong path here
  // is served index.html with a 200, and every assertion below would be
  // about nothing.
  const approve = page.locator('#approveBtn');
  await expect(approve, 'expected the consent page').toHaveCount(1);

  for (const scope of untick) {
    const box = page.locator(`input[type="checkbox"][name="scope"][value="${scope}"]`);
    await expect(box, `no checkbox for ${scope}`).toHaveCount(1);
    await box.uncheck();
  }

  // Read the code off the consent POST's Location rather than following
  // the browser to a host nothing serves: the redirect target is not the
  // subject of this test, and depending on it is how the run becomes
  // about Chromium's behaviour toward dead ports.
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

// grantedScopes exchanges the code and returns what the token carries.
async function grantedScopes(request: any, baseURL: string, client: Client, code: string) {
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
  const body = await resp.json();
  expect(body.access_token, 'no access token').toBeTruthy();
  return String(body.scope ?? '').split(/\s+/).filter(Boolean);
}

test('approving grants every scope that was ticked', async ({ page, request, baseURL }) => {
  const client = await registerClient(request, baseURL!);
  await loginAs(page, 'user', userPw);

  const code = await approveConsent(page, baseURL!, client, []);
  const granted = await grantedScopes(request, baseURL!, client, code);

  // The regression: this came back as ["openid"] alone while the page
  // showed every box ticked.
  for (const scope of ['mcp:read', 'mcp:write']) {
    expect(granted, `approving with everything ticked did not grant ${scope}`).toContain(scope);
  }
});

test('unticking a scope withholds it', async ({ page, request, baseURL }) => {
  const client = await registerClient(request, baseURL!);
  await loginAs(page, 'user', userPw);

  const code = await approveConsent(page, baseURL!, client, ['mcp:write']);
  const granted = await grantedScopes(request, baseURL!, client, code);

  expect(granted, 'unticking mcp:write did not withhold it').not.toContain('mcp:write');
  // And it narrows rather than collapsing: what stayed ticked survives.
  expect(granted, 'unticking one scope dropped the others too').toContain('mcp:read');
});
