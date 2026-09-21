import { expect, test } from '@playwright/test';

import { adminPassword, loginAs, userPassword } from './fixtures/login';
import { serverLog } from './fixtures/serverlog';

// The privileged scopes on the consent page, driven by a browser.
//
// Two properties, and neither is visible to a server test:
//
//   - a privileged scope is offered UNCHECKED. Rendered checked like the
//     others, an admin grants every client power over everyone's jobs
//     unless they remember to decline, on every authorization, and
//     having forgotten once is not visible afterwards. Only the browser
//     decides what a form submits, so only the browser can show that
//     approving without touching the box withholds it.
//
//   - a user who cannot be granted it is not offered it at all. The
//     policy drops it either way, so a checkbox there would read as a
//     privilege they hold and do not.
//
// Demo mode puts both scopes on the "admin" group, so the seeded admin
// is eligible and the seeded user is not.

const log = serverLog();
const adminPw = adminPassword(log);
const userPw = userPassword(log);

const REQUESTED = ['openid', 'offline_access', 'mcp:read', 'mcp:admin', 'mcp:superuser'];
const REDIRECT_URI = 'http://127.0.0.1:39521/callback';

type Client = { clientId: string; clientSecret: string };

async function registerClient(request: any, baseURL: string): Promise<Client> {
  const resp = await request.post(`${baseURL}/mcp/oauth2/register`, {
    data: {
      redirect_uris: [REDIRECT_URI],
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      scope: REQUESTED.join(' '),
      client_name: 'privileged-consent-browser-test',
    },
  });
  expect(resp.status(), await resp.text()).toBe(201);
  const body = await resp.json();
  return { clientId: body.client_id, clientSecret: body.client_secret };
}

async function openConsent(page: any, baseURL: string, client: Client) {
  await page.route(/^http:\/\/127\.0\.0\.1:39521\//, (route: any) =>
    route.fulfill({ status: 200, contentType: 'text/html', body: '<html>callback</html>' }),
  );
  await page.goto(
    `${baseURL}/mcp/oauth2/authorize?response_type=code` +
      `&client_id=${encodeURIComponent(client.clientId)}` +
      `&redirect_uri=${encodeURIComponent(REDIRECT_URI)}` +
      `&scope=${encodeURIComponent(REQUESTED.join(' '))}` +
      `&state=privtest`,
    { waitUntil: 'domcontentloaded' },
  );
  await expect(page.locator('#approveBtn'), 'expected the consent page').toHaveCount(1);
}

async function approveAndExchange(page: any, request: any, baseURL: string, client: Client) {
  const [resp] = await Promise.all([
    page.waitForResponse(
      (r: any) => r.url().includes('/mcp/oauth2/consent') && r.request().method() === 'POST',
    ),
    page.locator('#approveBtn').click(),
  ]);
  const codeURL = resp.headers()['location'] ?? '';
  expect(codeURL, `consent did not redirect (status ${resp.status()})`).toContain(REDIRECT_URI);
  const code = new URL(codeURL).searchParams.get('code');

  const token = await request.post(`${baseURL}/mcp/oauth2/token`, {
    form: {
      grant_type: 'authorization_code',
      code: code as string,
      redirect_uri: REDIRECT_URI,
      client_id: client.clientId,
      client_secret: client.clientSecret,
    },
  });
  expect(token.status(), await token.text()).toBe(200);
  return String((await token.json()).scope ?? '')
    .split(/\s+/)
    .filter(Boolean);
}

test('an eligible admin is offered the privileged scopes unchecked, and approving withholds them', async ({
  page,
  request,
  baseURL,
}) => {
  const client = await registerClient(request, baseURL!);
  await loginAs(page, 'admin', adminPw);
  await openConsent(page, baseURL!, client);

  for (const scope of ['mcp:admin', 'mcp:superuser']) {
    const box = page.locator(`input[type="checkbox"][name="scope"][value="${scope}"]`);
    await expect(box, `${scope} was not offered to a member of its group`).toHaveCount(1);
    await expect(box, `${scope} is pre-checked; granting it would be the default`).not.toBeChecked();
  }
  // An ordinary scope keeps the old behaviour.
  await expect(
    page.locator('input[type="checkbox"][name="scope"][value="mcp:read"]'),
    'mcp:read is no longer pre-checked',
  ).toBeChecked();

  await expect(page.getByText(/asking for administrative access/i)).toBeVisible();

  // Approving without touching them must not grant them. This is the
  // whole point: an omission grants nothing.
  const granted = await approveAndExchange(page, request, baseURL!, client);
  expect(granted, 'approving without ticking granted mcp:admin').not.toContain('mcp:admin');
  expect(granted, 'approving without ticking granted mcp:superuser').not.toContain('mcp:superuser');
  expect(granted, 'approving dropped a scope that was ticked').toContain('mcp:read');
});

test('ticking a privileged scope grants it', async ({ page, request, baseURL }) => {
  const client = await registerClient(request, baseURL!);
  await loginAs(page, 'admin', adminPw);
  await openConsent(page, baseURL!, client);

  await page.locator('input[type="checkbox"][name="scope"][value="mcp:admin"]').check();

  const granted = await approveAndExchange(page, request, baseURL!, client);
  expect(granted, 'ticking mcp:admin did not grant it').toContain('mcp:admin');
  expect(granted, 'ticking one privileged scope granted the other too').not.toContain(
    'mcp:superuser',
  );
});

test('a user outside the group is not offered them at all', async ({ page, request, baseURL }) => {
  const client = await registerClient(request, baseURL!);
  await loginAs(page, 'user', userPw);
  await openConsent(page, baseURL!, client);

  for (const scope of ['mcp:admin', 'mcp:superuser']) {
    await expect(
      page.locator(`input[type="checkbox"][name="scope"][value="${scope}"]`),
      `${scope} was offered to a user who cannot be granted it`,
    ).toHaveCount(0);
  }
  await expect(
    page.getByText(/asking for administrative access/i),
    'a warning about administrative access with none on offer',
  ).toHaveCount(0);
  await expect(
    page.locator('input[type="checkbox"][name="scope"][value="mcp:read"]'),
    'filtering removed a scope the user can have',
  ).toHaveCount(1);
});
