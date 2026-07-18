'use client';

import { useParams, usePathname } from 'next/navigation';

/**
 * Works around a Next.js static-export limitation: when a dynamic
 * route's `generateStaticParams()` returns a placeholder (we use `_`),
 * direct page loads from the SPA handler see `useParams()` return the
 * placeholder, not the real URL segment.
 *
 * Pass the route pattern (e.g. `/jobs/[id]`) and this returns the same
 * shape `useParams` would, but with each `[name]` segment replaced by
 * the actual value from `usePathname()` whenever `useParams` would have
 * returned `_`.
 *
 * Mirrors the helper used by github.com/bbockelm/swamp.
 */
export function useResolvedParams<T extends Record<string, string>>(
  pattern: string,
): T {
  const params = useParams();
  const pathname = usePathname();

  const patternParts = pattern.split('/').filter(Boolean);
  const pathParts = (pathname ?? '').split('/').filter(Boolean);

  const resolved: Record<string, string> = {};

  for (let i = 0; i < patternParts.length; i++) {
    const match = patternParts[i].match(/^\[(.+)\]$/);
    if (match) {
      const name = match[1];
      const fromParams = params[name];
      resolved[name] =
        typeof fromParams === 'string' && fromParams !== '_'
          ? fromParams
          : pathParts[i] ?? '';
    }
  }

  return resolved as T;
}
