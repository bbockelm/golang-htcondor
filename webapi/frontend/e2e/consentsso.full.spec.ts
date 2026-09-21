import { expect, test } from "@playwright/test";

import { adminPassword } from "./fixtures/login";
import { serverLog } from "./fixtures/serverlog";

// Consent when the user has to LOG IN first.
//
// The other consent specs call loginAs() before visiting /authorize, so
// the browser already holds a session and the authorize endpoint takes
// its "already authenticated" branch straight to the consent page. That
// branch worked. The other one did not: with no session, /authorize
// redirects to the IDP, and the callback used to grant scopes and write
// the authorize response itself -- so a user's FIRST authorization of a
// client, the one most worth asking about, was the only one never asked.
//
// Nothing caught it because every consent test had logged in first. The
// distinguishing act here is the ABSENCE of that login: the flow must
// drive itself through the IDP and still stop at consent.
//
// The privileged-scope assertions are repeated rather than assumed,
// because skipping consent skipped them too: mcp:admin and mcp:superuser
// were granted on group membership alone, with no unchecked box and no
// act by anyone.

const log = serverLog();
const adminPw = adminPassword(log);

const REQUESTED = [
  "openid",
  "offline_access",
  "mcp:read",
  "mcp:admin",
  "mcp:superuser",
];
const REDIRECT_URI = "http://127.0.0.1:39533/callback";

type Client = { clientId: string; clientSecret: string };

async function registerClient(request: any, baseURL: string): Promise<Client> {
  const resp = await request.post(`${baseURL}/mcp/oauth2/register`, {
    data: {
      redirect_uris: [REDIRECT_URI],
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      scope: REQUESTED.join(" "),
      client_name: "sso-consent-browser-test",
    },
  });
  expect(resp.status(), await resp.text()).toBe(201);
  const body = await resp.json();
  return { clientId: body.client_id, clientSecret: body.client_secret };
}

// authorizeWithoutSession starts the flow with no cookie, so the server
// must send the browser through the IDP before anything else.
async function authorizeWithoutSession(
  page: any,
  baseURL: string,
  client: Client,
) {
  await page.context().clearCookies();
  await page.route(/^http:\/\/127\.0\.0\.1:39533\//, (route: any) =>
    route.fulfill({
      status: 200,
      contentType: "text/html",
      body: "<html>callback</html>",
    }),
  );
  await page.goto(
    `${baseURL}/mcp/oauth2/authorize?response_type=code` +
      `&client_id=${encodeURIComponent(client.clientId)}` +
      `&redirect_uri=${encodeURIComponent(REDIRECT_URI)}` +
      `&scope=${encodeURIComponent(REQUESTED.join(" "))}` +
      `&state=ssoconsenttest&prompt=consent`,
    { waitUntil: "domcontentloaded" },
  );
}

// completeIdpLogin fills the IDP form the authorize redirect landed on.
// It is deliberately not loginAs(): that helper starts at /login, which
// would establish the very session this test must not have.
async function completeIdpLogin(page: any, username: string, password: string) {
  const usernameField = page.locator('input[name="username"]');
  if (!(await usernameField.count())) {
    throw new Error(
      `expected the IDP login form after /authorize, got: ${(
        await page.locator("body").innerText()
      ).slice(0, 300)}`,
    );
  }
  await usernameField.fill(username);
  await page.locator('input[name="password"]').fill(password);
  await Promise.all([
    page.waitForURL((u: URL) => !u.pathname.startsWith("/idp/login"), {
      timeout: 15_000,
    }),
    page.locator('button[type="submit"], input[type="submit"]').first().click(),
  ]);
}

test("logging in through the IDP still stops at consent", async ({
  page,
  request,
  baseURL,
}) => {
  const client = await registerClient(request, baseURL!);
  await authorizeWithoutSession(page, baseURL!, client);
  await completeIdpLogin(page, "admin", adminPw);

  // The regression. Before the fix the callback completed the grant and
  // this landed on the client's redirect_uri with a code already issued.
  await expect(
    page.locator("#approveBtn"),
    "authenticating through the IDP skipped the consent page and granted the request outright",
  ).toHaveCount(1);
  expect(page.url(), "expected to be on the consent page").toContain(
    "/mcp/oauth2/consent",
  );
});

test("privileged scopes are still withheld by default on the SSO path", async ({
  page,
  request,
  baseURL,
}) => {
  const client = await registerClient(request, baseURL!);
  await authorizeWithoutSession(page, baseURL!, client);
  await completeIdpLogin(page, "admin", adminPw);
  await expect(
    page.locator("#approveBtn"),
    "expected the consent page",
  ).toHaveCount(1);

  for (const scope of ["mcp:admin", "mcp:superuser"]) {
    const box = page.locator(
      `input[type="checkbox"][name="scope"][value="${scope}"]`,
    );
    await expect(
      box,
      `${scope} was not offered to a member of its group`,
    ).toHaveCount(1);
    await expect(
      box,
      `${scope} is pre-checked on the SSO path`,
    ).not.toBeChecked();
  }

  const [resp] = await Promise.all([
    page.waitForResponse(
      (r: any) =>
        r.url().includes("/mcp/oauth2/consent") &&
        r.request().method() === "POST",
    ),
    page.locator("#approveBtn").click(),
  ]);
  const codeURL = resp.headers()["location"] ?? "";
  expect(
    codeURL,
    `consent did not redirect (status ${resp.status()})`,
  ).toContain(REDIRECT_URI);
  const code = new URL(codeURL).searchParams.get("code");

  const token = await request.post(`${baseURL}/mcp/oauth2/token`, {
    form: {
      grant_type: "authorization_code",
      code: code as string,
      redirect_uri: REDIRECT_URI,
      client_id: client.clientId,
      client_secret: client.clientSecret,
    },
  });
  expect(token.status(), await token.text()).toBe(200);
  const granted = String((await token.json()).scope ?? "")
    .split(/\s+/)
    .filter(Boolean);

  // This is what the old path handed over without asking.
  expect(
    granted,
    "the SSO path granted mcp:admin without it being ticked",
  ).not.toContain("mcp:admin");
  expect(
    granted,
    "the SSO path granted mcp:superuser without it being ticked",
  ).not.toContain("mcp:superuser");
  expect(granted, "an ordinary requested scope was dropped").toContain(
    "mcp:read",
  );
});
