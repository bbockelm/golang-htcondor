import { expect, test } from '@playwright/test';

import { adminPassword, loginAsAdmin } from './fixtures/login';
import { serverLog } from './fixtures/serverlog';

// Site apps, end to end against the real server.
//
// The harness deploys one as a directory bundle before starting the
// server (scripts/e2e-server.sh). Everything here is reachable only
// because the server published it: the gate, the mount-point injection,
// the switcher and the sidebar link are all server-side decisions, and
// a fixture would assert the SPA's opinion of them rather than the
// server's.
const APP_ID = 'e2eapp';
const APP_URL = `/site/${APP_ID}/`;
const APP_NAME = 'E2E Example App';

test.beforeEach(async ({ page }) => {
  await loginAsAdmin(page, adminPassword(serverLog()));
});

test('the sidebar offers the app, and it opens', async ({ page }) => {
  await page.goto('/');

  const link = page.getByTestId(`site-app-${APP_ID}`);
  await expect(link).toBeVisible();
  await expect(link).toHaveText(APP_NAME);

  await link.click();
  await page.waitForURL((u) => u.pathname.startsWith(APP_URL));
  await expect(page.getByTestId('app-heading')).toHaveText(APP_NAME);
});

test('the bundle is told where it is mounted', async ({ page }) => {
  await page.goto(APP_URL);

  // Not just "the page rendered". Without the injected global the
  // bundle's router builds wrong URLs, and nothing about the rendered
  // page would show it.
  const injected = await page.evaluate(
    () => (window as unknown as { __HTCONDOR_APP__?: Record<string, string> }).__HTCONDOR_APP__,
  );
  expect(injected).toBeTruthy();
  expect(injected?.id).toBe(APP_ID);
  expect(injected?.base).toBe(APP_URL);
  expect(injected?.name).toBe(APP_NAME);
});

test('a relative asset resolves against the injected base', async ({ page }) => {
  await page.goto(APP_URL);

  // index.html asks for ./assets/app.js. If <base> were missing or
  // wrong the browser would request it from the site root, the script
  // would 404, and this text would never be written. That makes this
  // the assertion that the base tag actually works, rather than merely
  // being present in the markup.
  await expect(page.getByTestId('app-base')).toHaveText(APP_URL);
});

test('the switcher lists the app', async ({ page }) => {
  await page.goto('/site/');

  await expect(page.getByRole('heading', { name: 'Your apps' })).toBeVisible();
  const link = page.getByRole('link', { name: new RegExp(APP_NAME) });
  await expect(link).toBeVisible();
  await expect(link).toHaveAttribute('href', APP_URL);
});

test('app responses are not cacheable by a shared proxy', async ({ page }) => {
  // These bytes are group-scoped. A cache in front of the access point
  // holding them would hand one lab's app to the next caller.
  const res = await page.request.get(APP_URL);
  expect(res.status()).toBe(200);
  expect(res.headers()['cache-control'] ?? '').toContain('no-store');
});

test('a signed-out browser is sent to log in, and gets nothing', async ({ browser }) => {
  // A fresh context: no session cookie at all.
  const ctx = await browser.newContext({ ignoreHTTPSErrors: true });
  try {
    const page = await ctx.newPage();
    const res = await page.goto(APP_URL + 'assets/app.js');
    // Either we were redirected to the login page, or the request was
    // refused outright. What must NOT happen is the asset coming back.
    const body = res ? await res.text() : '';
    expect(body).not.toContain('__HTCONDOR_APP__');
    expect(page.url()).not.toContain('/assets/app.js');
  } finally {
    await ctx.close();
  }
});

// The overlay bar. Only a real browser can show whether a shadow root
// actually isolates the bar from the page's own CSS, which is the
// whole reason it is built that way.
test.describe('the shell overlay', () => {
  // The bar lives in a shadow root, so page-level selectors cannot see
  // into it. Reach it the way the browser does.
  async function barLinks(page: import('@playwright/test').Page) {
    return page.evaluate(() => {
      const host = document.querySelector('[data-htcondor-shell]');
      if (!host || !host.shadowRoot) return null;
      return Array.from(host.shadowRoot.querySelectorAll('a')).map((a) => ({
        text: (a.textContent ?? '').trim(),
        href: a.getAttribute('href') ?? '',
      }));
    });
  }

  test('renders in a shadow root and points at the other app', async ({ page }) => {
    await page.goto(APP_URL);

    await page.waitForFunction(
      () => !!document.querySelector('[data-htcondor-shell]')?.shadowRoot,
      undefined,
      { timeout: 15_000 },
    );

    const links = await barLinks(page);
    expect(links).not.toBeNull();
    // It must offer the OTHER app, not the one we are standing in: a
    // bar that only names where you already are is clutter.
    expect(links!.some((l) => l.href === '/site/e2eother/')).toBe(true);
    expect(links!.some((l) => l.href === APP_URL)).toBe(false);
  });

  // The admin this suite signs in as is not app-only: they have the
  // whole console, and before this they got no way back to it from an
  // app -- the bar rendered only when there were other apps or an
  // expert door.
  test('offers the way back to the full console', async ({ page }) => {
    await page.goto(APP_URL);
    await page.waitForFunction(
      () => !!document.querySelector('[data-htcondor-shell]')?.shadowRoot,
      undefined,
      { timeout: 15_000 },
    );

    const back = (await barLinks(page))!.find((l) => l.href === '/');
    expect(back).toBeTruthy();
    expect(back!.text).toBe('Full console');
  });

  test('the page cannot restyle the bar', async ({ page }) => {
    await page.goto(APP_URL);
    await page.waitForFunction(
      () => !!document.querySelector('[data-htcondor-shell]')?.shadowRoot,
      undefined,
      { timeout: 15_000 },
    );

    // Inject a page-level rule that would wreck an un-isolated bar.
    // Shadow DOM is the reason this is a no-op; without it the bar is
    // at the mercy of whatever CSS the app happens to ship.
    await page.addStyleTag({ content: 'a, div, span { display: none !important; }' });

    const visible = await page.evaluate(() => {
      const root = document.querySelector('[data-htcondor-shell]')?.shadowRoot;
      const bar = root?.querySelector('.bar') as HTMLElement | null;
      if (!bar) return false;
      return getComputedStyle(bar).display !== 'none';
    });
    expect(visible).toBe(true);
  });

  test('navigating the bar reaches the other app', async ({ page }) => {
    await page.goto(APP_URL);
    await page.waitForFunction(
      () => !!document.querySelector('[data-htcondor-shell]')?.shadowRoot,
      undefined,
      { timeout: 15_000 },
    );

    await page.evaluate(() => {
      const root = document.querySelector('[data-htcondor-shell]')!.shadowRoot!;
      const link = Array.from(root.querySelectorAll('a')).find(
        (a) => a.getAttribute('href') === '/site/e2eother/',
      ) as HTMLAnchorElement;
      link.click();
    });

    await page.waitForURL((u) => u.pathname.startsWith('/site/e2eother/'));
    await expect(page.getByTestId('other-heading')).toBeVisible();
  });

  test('an app that declines the overlay does not get one', async ({ page }) => {
    await page.goto('/site/e2ebare/');
    await expect(page.getByTestId('bare-heading')).toBeVisible();

    // Give the script the same chance it gets elsewhere before
    // concluding it stayed away.
    await page.waitForTimeout(2000);
    const host = await page.evaluate(
      () => !!document.querySelector('[data-htcondor-shell]'),
    );
    expect(host).toBe(false);
  });
})
