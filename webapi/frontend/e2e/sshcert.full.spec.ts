import { expect, test } from "@playwright/test";

import { adminPassword, loginAsAdmin } from "./fixtures/login";
import { serverLog } from "./fixtures/serverlog";

// The SSH certificate panel on /info.
//
// Both branches are driven with a stubbed /ssh/ca, because which one a
// real server takes depends on whether it can mint a CA -- demo mode
// cannot, so against the live harness only the absent branch would ever
// run, and the half that matters would go untested.
//
// Stubbing is safe here in a way it was not for the SSO return hop:
// these are ordinary XHRs the page makes, not redirect hops inside a
// navigation, which Playwright does not route.

const password = adminPassword(serverLog());

const CA = {
  public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAACAFAKECAKEY ca@ap",
  known_hosts_line:
    "@cert-authority ap.example.edu ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAACAFAKECAKEY",
  fingerprint: "SHA256:f4k3f1ng3rpr1nt0000000000000000000000000000",
  gateway_host: "ap.example.edu",
  gateway_port: 22,
};

test("no certificate authority means no panel at all", async ({ page }) => {
  // 503 is this deployment saying it has no CA, not a failure. An access
  // point with no gateway must not show a broken-looking panel about one.
  await page.route("**/api/v1/ssh/ca", (route) =>
    route.fulfill({
      status: 503,
      contentType: "application/json",
      body: JSON.stringify({ error: "no certificate authority configured" }),
    }),
  );

  await loginAsAdmin(page, password);
  await page.goto("/info");

  await expect(page.getByText("Info", { exact: true }).first()).toBeVisible();
  await expect(page.getByText("SSH access")).toHaveCount(0);
  // And no error leaked onto the page in its place.
  await expect(page.locator("body")).not.toContainText("certificate authority");
});

test("a certificate can be issued for a pasted public key", async ({
  page,
}) => {
  await page.route("**/api/v1/ssh/ca", (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(CA),
    }),
  );

  // Capture what the page sends, so the test proves the pasted key is
  // what gets signed -- and that nothing resembling a private key is in
  // the request.
  let posted: Record<string, unknown> | null = null;
  await page.route("**/api/v1/ssh/certificate", async (route) => {
    posted = JSON.parse(route.request().postData() ?? "{}");
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        certificate: "ssh-ed25519-cert-v01@openssh.com AAAAIGZ4a2Vj3Jo=",
        principal: "bbockelm",
        valid_before: new Date(Date.now() + 12 * 3600_000).toISOString(),
        fingerprint: "SHA256:c3rt1f1c4t3",
      }),
    });
  });

  await loginAsAdmin(page, password);
  await page.goto("/info");

  await expect(page.getByText("SSH access")).toBeVisible();
  // Step 1 gives the user something to trust.
  await expect(page.locator("body")).toContainText(CA.known_hosts_line);
  await expect(page.locator("body")).toContainText(CA.fingerprint);

  const pub = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMYPUBLICKEY me@laptop";
  await page.locator("textarea").fill(pub);
  await page.getByRole("button", { name: /issue certificate/i }).click();

  // The certificate comes back and is offered as a file, because a line
  // this long pasted wrong fails silently later.
  await expect(page.locator("body")).toContainText("id_ed25519-cert.pub");
  const download = page.getByRole("link", { name: /download/i });
  await expect(download).toBeVisible();
  await expect(download).toHaveAttribute("download", "id_ed25519-cert.pub");

  // The pasted key is what was sent, and nothing else was.
  expect(posted).toBeTruthy();
  expect(posted!.public_key).toBe(pub);
  expect(JSON.stringify(posted)).not.toContain("PRIVATE");

  // And the connect command names the gateway the CA reported.
  await expect(page.locator("body")).toContainText("ssh ap.example.edu");
});
