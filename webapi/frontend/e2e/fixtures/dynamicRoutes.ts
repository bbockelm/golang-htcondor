import { statSync } from 'node:fs';
import path from 'node:path';
import type { Page } from '@playwright/test';

// The smoke suite serves the static export with `npx serve out`, which
// knows nothing of dynamic routes: /jobs/12.0 is a 404 there. The Go
// server answers it from jobs/_.html (httpserver/webui/handler.go,
// resolveDynamicRoute). A page that links to /jobs/12.0 or /users/e2e has
// Next fetch that route in the background as the link scrolls into view,
// so under `serve` the page logged a failed resource now and then --
// whenever a link landed in view before the test finished -- and the
// suite's "no page errors" checks failed at random.
//
// serveDynamicRoutes answers those background requests the way the Go
// server would. Documents are left alone: tests that open a dynamic page
// route its document themselves.

const OUT = path.join(__dirname, '..', '..', 'out');

function isFile(rel: string): boolean {
  try {
    return statSync(path.join(OUT, rel)).isFile();
  } catch {
    return false;
  }
}

function isDir(rel: string): boolean {
  try {
    return statSync(path.join(OUT, rel)).isDirectory();
  } catch {
    return false;
  }
}

// resolveDynamicRoute is handler.go's: each segment that is not a
// directory of the export is replaced by the `_` placeholder, and the
// last segment is tried as itself, then as `_`.
export function resolveDynamicRoute(urlPath: string): string | undefined {
  let p = urlPath.replace(/^\/+/, '');
  let suffix = '.html';
  if (p.endsWith('.txt')) {
    suffix = '.txt';
    p = p.slice(0, -'.txt'.length);
  }
  const segments = p.split('/');
  const resolved: string[] = [];
  for (let i = 0; i < segments.length; i++) {
    const seg = segments[i];
    if (i === segments.length - 1) {
      for (const candidate of [seg, '_']) {
        const file = [...resolved, candidate].join('/') + suffix;
        if (isFile(file)) return file;
      }
      return undefined;
    }
    if (isDir([...resolved, seg].join('/'))) resolved.push(seg);
    else if (isDir([...resolved, '_'].join('/'))) resolved.push('_');
    else return undefined;
  }
  return undefined;
}

export async function serveDynamicRoutes(page: Page) {
  await page.route(
    (url) => {
      const p = url.pathname;
      if (p.startsWith('/api/') || p.startsWith('/_next/') || p === '/') return false;
      const rel = p.replace(/^\/+/, '');
      // What `serve` already has: a file, or a page by its clean URL.
      return !isFile(rel) && !isFile(`${rel}.html`);
    },
    async (route) => {
      const req = route.request();
      const file = req.resourceType() === 'document' ? undefined : resolveDynamicRoute(new URL(req.url()).pathname);
      if (!file) {
        await route.fallback();
        return;
      }
      await route.fulfill({
        path: path.join(OUT, file),
        contentType: file.endsWith('.html') ? 'text/html; charset=utf-8' : 'text/plain; charset=utf-8',
      });
    },
  );
}
