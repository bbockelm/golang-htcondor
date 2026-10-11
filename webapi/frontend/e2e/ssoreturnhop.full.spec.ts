import { expect, test } from "@playwright/test";

import { adminPassword } from "./fixtures/login";
import { serverLog } from "./fixtures/serverlog";

// Coming back from the identity provider must not finish with a 302.
//
// A logged-out person opening an SSH device code URL bounced through
// CILogon forever. The session cookie is SameSite=Strict, and a browser
// attributes a whole redirect chain to whoever started it -- the IdP,
// cross-site -- so the 302 the callback used to finish with arrived at
// the destination WITHOUT the cookie the callback had just set. The page
// saw no session and sent the user back to the IdP.
//
// Nothing caught it, and the reason is this harness: its IdP lives at
// /idp/* on the SAME ORIGIN as the app, so every chain is same-site and
// Strict is never exercised. consentsso.full.spec.ts already drives a
// logged-out SSO login in a real browser and passes either way.
//
// So this test makes the chain genuinely cross-site. The harness serves
// on localhost; 127.0.0.1 reaches the same server and is a DIFFERENT
// site as far as SameSite is concerned. Running the IdP's leg under the
// other name reproduces production's shape exactly: a chain begun
// cross-site, with the callback and its destination same-site with each
// other. The login itself starts on localhost, as it does in production
// on the host the callback names: the callback accepts only the browser
// holding the cookie set when the login began, and a cookie set on
// 127.0.0.1 is not sent to localhost.
//
// Two things only a browser can check, which is why this is not just the
// Go test again: that Strict really is applied to the chain, and that
// the page the callback returns actually navigates -- Go asserts the
// HTML contains location.replace, it never runs it.

const log = serverLog();
const adminPw = adminPassword(log);

// otherSite is the same server under a name the browser treats as a
// different site.
function otherSite(url: string): string {
  return url.replace("//localhost:", "//127.0.0.1:");
}

test("the session survives coming back from a cross-site identity provider", async ({
  page,
  request,
  baseURL,
}) => {
  // A device code to approve, so the landing page is one that requires a
  // session -- the shape the bug was reported against.
  const reg = await request.post(`${baseURL}/mcp/oauth2/register`, {
    data: {
      client_name: "sso-return-hop-test",
      redirect_uris: ["http://127.0.0.1:39534/callback"],
      grant_types: ["urn:ietf:params:oauth:grant-type:device_code"],
      token_endpoint_auth_method: "none",
    },
  });
  expect(reg.status(), await reg.text()).toBe(201);
  const clientId = (await reg.json()).client_id;

  const auth = await request.post(`${baseURL}/mcp/oauth2/device/authorize`, {
    form: { client_id: clientId, scope: "openid" },
  });
  expect(auth.status(), await auth.text()).toBe(200);
  const { user_code: userCode } = await auth.json();
  expect(userCode).toBeTruthy();

  // Nothing remembered: this is the reported scenario, a completely
  // logged-out browser.
  await page.context().clearCookies();

  // Watch what the callback answers with. A redirect there is the bug.
  const callbackStatuses: number[] = [];
  const seen: string[] = [];
  page.on("response", (resp) => {
    const u = resp.url();
    seen.push("resp:" + resp.status() + " " + u);
    if (/\/(mcp\/)?oauth2\/callback\?/.test(u)) {
      callbackStatuses.push(resp.status());
    }
  });

  // Start on this server's own name. This sets the cookie that binds
  // the login to this browser, and sends it to the IdP.
  await page.goto(`${baseURL}/oauth2/device/verify?user_code=${userCode}`, {
    waitUntil: "domcontentloaded",
  });
  const username = page.locator('input[name="username"]');
  await expect(username).toBeVisible();

  // Move the IdP's leg to the OTHER name for this same server, which is
  // what makes the chain cross-site -- and makes this test able to fail.
  //
  // The IdP's own redirects are relative, so from here it stays on
  // 127.0.0.1. The server builds its OAuth redirect_uri from the base URL
  // it was configured with, so the IdP sends the browser to an ABSOLUTE
  // localhost callback: that hop is cross-site, exactly as the hop back
  // from CILogon is. No request interception is involved.
  //
  // The return URL is stored as a path, so it resolves against the
  // callback's own host -- callback and destination stay same-site with
  // each other, as in production.
  await page.goto(otherSite(page.url()), { waitUntil: "domcontentloaded" });

  // The IdP form, on the other site.
  await expect(username).toBeVisible();
  await username.fill("admin");
  await page.locator('input[name="password"]').fill(adminPw);
  await page
    .locator('button[type="submit"], input[type="submit"]')
    .first()
    .click();

  // Where the browser ends up is the whole test. With the fix it is the
  // approval screen; without it, back at the IdP login form, forever.
  await page.waitForURL((u: URL) => u.pathname.includes("/device/verify"), {
    timeout: 20_000,
  });

  await expect(
    page.locator('input[name="username"]'),
    "bounced back to the IdP login form: the session cookie did not survive the return hop",
  ).toHaveCount(0);

  // The code is on the page, which is what the person is asked to check.
  await expect(page.locator("body")).toContainText(userCode);

  // And the callback itself did not redirect onward. This is the
  // regression: a 302 continues the IdP's chain and loses the cookie.
  expect(
    callbackStatuses,
    "the callback answered with a redirect; the cookie does not survive that hop",
  ).not.toContain(302);
  expect(
    callbackStatuses.some((s) => s === 200),
    "the callback never answered with a page; saw:\n" + seen.join("\n"),
  ).toBeTruthy();
});
