import { readFileSync } from 'node:fs';
import path from 'node:path';
import { beforeEach, describe, expect, test, vi } from 'vitest';

// The site-app overlay bar, run as a browser runs it.
//
// The script is served by the Go side (webapi/siteapps/shell.js) and
// decorates pages this export never renders, so there is no component to
// mount: the test loads the file the server embeds and executes it
// against jsdom. That is the only way to answer the question that
// matters -- given this /api/v1/auth/me answer, what does the bar offer?
// -- without building a container and driving a browser.
//
// The Playwright suite (e2e/siteapps.full.spec.ts) still covers what
// only a real browser can: that the shadow root actually isolates the
// bar from the page's own CSS.
// Resolved against this suite's root (webapi/frontend), not against
// import.meta.url: under jsdom that is an http: URL and not a path.
const shellSource = readFileSync(path.resolve(process.cwd(), '../siteapps/shell.js'), 'utf8');

interface MeAnswer {
  authenticated: boolean;
  app_only?: boolean;
  site_apps?: { id: string; name: string; url: string }[];
}

function serve(me: MeAnswer | null, branding: Record<string, unknown> | null = null) {
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string) => {
      const body = url.startsWith('/api/v1/auth/me') ? me : branding;
      if (body === null) return { ok: false, status: 404, json: async () => ({}) };
      return { ok: true, status: 200, json: async () => body };
    }),
  );
}

/** Run the overlay and wait for it to have decided. */
async function runShell(app?: { id: string; name: string }) {
  (window as unknown as { __HTCONDOR_APP__?: unknown }).__HTCONDOR_APP__ = app
    ? { id: app.id, name: app.name, base: `/site/${app.id}/` }
    : undefined;
  new Function(shellSource)();
  // Two fetches and their continuations: let every pending microtask and
  // timer run rather than guessing at a number of ticks.
  for (let i = 0; i < 50 && !document.querySelector('[data-htcondor-shell]'); i++) {
    await new Promise((r) => setTimeout(r, 0));
  }
}

function bar(): ShadowRoot | null {
  return document.querySelector('[data-htcondor-shell]')?.shadowRoot ?? null;
}

function links() {
  const root = bar();
  if (!root) return [];
  return Array.from(root.querySelectorAll('a')).map((a) => ({
    text: (a.textContent ?? '').trim(),
    href: a.getAttribute('href') ?? '',
  }));
}

const APP = { id: 'cryoem', name: 'CryoEM' };
const ONE_APP = [{ id: 'cryoem', name: 'CryoEM', url: '/site/cryoem/' }];

beforeEach(() => {
  // The script refuses to run twice in a page, which is right in a
  // browser and would make every case after the first a no-op here.
  delete (window as unknown as { __HTCONDOR_SHELL__?: boolean }).__HTCONDOR_SHELL__;
  document.body.innerHTML = '';
  document.body.removeAttribute('style');
  document.documentElement.removeAttribute('style');
  document.head.innerHTML = '';
});

describe('the site-app shell', () => {
  // The bug this was written for: a user with the whole console, on an
  // access point that publishes one app, got no bar at all -- the old
  // script drew one only when there were other apps to list or an
  // expert door to offer -- and was stranded in the simple UI.
  test('offers the full console to a session that is not app-only', async () => {
    serve({ authenticated: true, site_apps: ONE_APP });
    await runShell(APP);

    expect(bar()).not.toBeNull();
    const back = links().find((l) => l.href === '/');
    expect(back).toBeDefined();
    expect(back!.text).toBe('Full console');
  });

  // An app-only session reaches the console through the expert door,
  // which is what sets the cookie that stops the redirect back.
  test('offers the expert door to an app-only session', async () => {
    serve({ authenticated: true, app_only: true, site_apps: ONE_APP });
    await runShell(APP);

    expect(links().map((l) => l.href)).toContain('/site/expert');
    expect(links().map((l) => l.href)).not.toContain('/');
  });

  test('lists the caller’s other apps, but not the one they are in', async () => {
    serve({
      authenticated: true,
      site_apps: [...ONE_APP, { id: 'seqqc', name: 'SeqQC', url: '/site/seqqc/' }],
    });
    await runShell(APP);

    const hrefs = links().map((l) => l.href);
    expect(hrefs).toContain('/site/seqqc/');
    expect(hrefs).not.toContain('/site/cryoem/');
  });

  test('draws nothing at all without a session', async () => {
    serve({ authenticated: false });
    await runShell(APP);

    expect(bar()).toBeNull();
  });

  test('stays away from an app that declined it', async () => {
    document.head.innerHTML = '<meta name="htcondor-shell" content="none">';
    serve({ authenticated: true, site_apps: ONE_APP });
    await runShell(APP);

    expect(bar()).toBeNull();
  });

  // Apps clear the bar by reading this, so its value is a contract.
  test('declares its height to the page', async () => {
    serve({ authenticated: true, site_apps: ONE_APP });
    await runShell(APP);

    expect(document.documentElement.style.getPropertyValue('--htcondor-shell-height')).toBe('36px');
    expect(document.body.style.paddingTop).toBe('36px');
  });

  // The site's own name, from the same endpoint the console's sidebar
  // heads itself with, so the bar reads as part of this access point.
  test('names the site, and falls back when branding is unavailable', async () => {
    serve({ authenticated: true, site_apps: ONE_APP }, { site_name: 'CHTC Access Point' });
    await runShell(APP);
    expect(bar()!.textContent).toContain('CHTC Access Point');
    expect(bar()!.textContent).toContain('CryoEM');

    delete (window as unknown as { __HTCONDOR_SHELL__?: boolean }).__HTCONDOR_SHELL__;
    document.body.innerHTML = '';
    serve({ authenticated: true, site_apps: ONE_APP }, null);
    await runShell(APP);
    expect(bar()!.textContent).toContain('HTCondor');
  });
});
