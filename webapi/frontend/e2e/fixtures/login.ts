import type { Page } from '@playwright/test';

// Log in through the real OAuth flow the deployed UI uses.
//
// The server runs with -demo, which enables the built-in IDP and wires
// the server up as an OAuth2 client of it. The browser therefore walks
// the same path a user does:
//
//   /login -> 302 /idp/authorize -> 302 /idp/login
//     -> POST username/password -> callback -> htcondor_session
//
// htcondor_session is the cookie GET /api/v1/auth/me resolves, and it
// resolves that cookie ONLY -- it does not consult a bearer token or a
// user header. That is why this exists: without a real session the SPA
// considers itself logged out and redirects every page to /login, and
// assertions as loose as "the body is visible" pass against the error
// document that produces.
export async function loginAsAdmin(page: Page, password: string) {
  await page.goto('/login');

  // Landed on the IDP's form. If the server were misconfigured we would
  // be looking at a JSON error instead, so assert the form is here
  // rather than letting fill() fail with a less obvious message.
  const username = page.locator('input[name="username"]');
  if (!(await username.count())) {
    throw new Error(
      `expected the IDP login form, got: ${(await page.locator('body').innerText()).slice(0, 200)}`,
    );
  }

  await username.fill('admin');
  await page.locator('input[name="password"]').fill(password);

  // Watch the POST itself rather than only waiting for the URL to
  // change. Bad credentials do not re-render the form -- the IDP answers
  // 401 with a JSON body and the browser stays on /idp/login -- so a
  // URL-only wait burns its full timeout and then reports "timeout"
  // instead of "the password was wrong", once per test.
  const [resp] = await Promise.all([
    page.waitForResponse(
      (r) => r.url().includes('/idp/login') && r.request().method() === 'POST',
    ),
    page.locator('form[action="/idp/login"] [type="submit"]').click(),
  ]);
  if (resp.status() >= 400) {
    throw new Error(
      `IDP rejected the login (${resp.status()}): ${(await resp.text()).slice(0, 200)}`,
    );
  }

  await page.waitForURL((u) => !u.pathname.startsWith('/idp/'), { timeout: 30_000 });
}

// adminPassword reads the credentials demo mode prints on startup.
// Generated per run, so it cannot be a constant; the workflow captures
// the server's output to a file and passes the path.
export function adminPassword(serverLog: string): string {
  const m = serverLog.match(/^Password:\s*(\S+)\s*$/m);
  if (!m) {
    throw new Error('no "Password:" line in the server log; did demo mode start?');
  }
  return m[1];
}
