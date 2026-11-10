// Site branding: what this deployment calls itself, and whose logos sit
// at the foot of every page.
//
// The server splices the configured values into the HTML it serves, as
// `window.__HTCONDOR_BRANDING__`, so they are there before the first
// render. Read through useSyncExternalStore rather than directly, so the
// hydration pass still matches the prerendered markup and React swaps in
// the site's own values immediately afterwards.
//
// Nothing injected means one of three things, all of which want the
// values below: an unconfigured deployment (the server injects nothing
// when the branding is the default), `next dev` against a Go server on
// another port, or the export served statically in a test. The last two
// can still ask the server, so we do.

import { useQuery } from '@tanstack/react-query';
import { useSyncExternalStore } from 'react';

export interface BrandingLogo {
  src: string;
  alt: string;
  href?: string;
}

export interface Branding {
  // The sidebar heading, the line under it, and the browser tab.
  site_name: string;
  site_tagline: string;
  page_title: string;
  // The institutional band in the footer. null (or absent) is the band
  // the UI ships with; [] is no logos at all.
  footer_logos: BrandingLogo[] | null;
  // Name HTCondor and CHTC in a line under the band. Set whenever the
  // shipped band is not shown, so who wrote the software is still said
  // where the band says who runs the service.
  software_credit?: boolean;
  favicon?: string;
  custom_css?: boolean;
}

export const DEFAULT_BRANDING: Branding = {
  site_name: 'HTCondor',
  site_tagline: 'Access Point',
  page_title: 'HTCondor Access Point',
  footer_logos: null,
};

declare global {
  interface Window {
    __HTCONDOR_BRANDING__?: Branding;
  }
}

// The injected value never changes within a page load, so there is
// nothing to subscribe to.
const noSubscribe = () => () => {};
const injected = (): Branding | null =>
  (typeof window !== 'undefined' && window.__HTCONDOR_BRANDING__) || null;
const notInjected = (): Branding | null => null;

async function fetchBranding(): Promise<Branding> {
  const res = await fetch('/api/v1/webui/branding', { credentials: 'include' });
  if (!res.ok) throw new Error(`branding: ${res.status}`);
  return res.json();
}

export function useBranding(): Branding {
  const fromPage = useSyncExternalStore(noSubscribe, injected, notInjected);
  const { data } = useQuery({
    queryKey: ['branding'],
    queryFn: fetchBranding,
    // Only worth asking when the page did not arrive carrying it.
    enabled: typeof window !== 'undefined' && !window.__HTCONDOR_BRANDING__,
    staleTime: Infinity,
    retry: false,
  });
  return fromPage ?? data ?? DEFAULT_BRANDING;
}
