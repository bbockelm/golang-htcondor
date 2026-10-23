'use client';

import { useQuery, useQueryClient } from '@tanstack/react-query';
import { usePathname, useRouter, useSearchParams } from 'next/navigation';
import { useEffect, useRef, useState } from 'react';
import { api } from '@/lib/api';
import { DEFAULT_BRANDING, useBranding } from '@/lib/branding';
import { Sidebar } from './Sidebar';
import { SuperuserBanner } from './SuperuserBanner';
import { Footer } from './Footer';

// Pages that render without an authenticated session. The dashboard ('/')
// is included so unauthenticated visitors see a "Sign In" prompt instead
// of an instant redirect loop.
const publicPaths = ['/'];

export function AppShell({ children }: { children: React.ReactNode }) {
  useBrandedDocument();
  const pathname = usePathname();
  const searchParams = useSearchParams();
  const router = useRouter();

  const [sidebarOpen, setSidebarOpen] = useState(false);

  // Auto-close the mobile drawer on route change. Without this, tapping
  // a nav link on a phone navigates but leaves the drawer covering the
  // page that was just loaded. The functional updater is a no-op when
  // the drawer was already closed, but the lint rule flags any
  // setState-in-effect; the navigation-reset pattern is exactly the
  // case the rule is heuristically wrong about.
  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setSidebarOpen((prev) => (prev ? false : prev));
  }, [pathname]);

  const queryClient = useQueryClient();
  const { data: session, isLoading } = useQuery({
    queryKey: ['session'],
    queryFn: api.auth.me,
  });

  const isPublic = publicPaths.includes(pathname);
  const isAuthenticated = !!session?.authenticated;

  const search = searchParams?.toString() ?? '';
  const fullPath = search ? `${pathname}?${search}` : pathname;

  useEffect(() => {
    if (!isLoading && !isAuthenticated && !isPublic) {
      // Send to the Go-side login (OAuth2 SSO redirect). The path is owned
      // by the backend, not by Next.js, so we use a hard navigation.
      window.location.href = `/login?return_to=${encodeURIComponent(fullPath)}`;
    }
  }, [isLoading, isAuthenticated, isPublic, fullPath, router]);

  // A session with no local account reaches only the placement pages, in
  // a shell without the access point's navigation.
  const placementOnly = !!session?.placement_only;
  const onPlacementPage = pathname === '/placement' || pathname.startsWith('/placement/');
  useEffect(() => {
    if (placementOnly && !onPlacementPage) router.replace('/placement');
  }, [placementOnly, onPlacementPage, router]);

  // The session became a full one (the person was onboarded while signed
  // in): the normal shell renders from the same answer, and everything read
  // under the placement-only session is read again.
  const wasPlacementOnly = useRef(false);
  useEffect(() => {
    if (placementOnly) {
      wasPlacementOnly.current = true;
    } else if (wasPlacementOnly.current && isAuthenticated) {
      wasPlacementOnly.current = false;
      void queryClient.invalidateQueries({ predicate: (q) => q.queryKey[0] !== 'session' });
    }
  }, [placementOnly, isAuthenticated, queryClient]);

  if (!isPublic && !isAuthenticated) {
    // While the redirect is in flight, render nothing.
    return null;
  }

  if (placementOnly) {
    if (!onPlacementPage) return null;
    return (
      <PlacementShell
        name={session?.placement?.display_name || session?.placement?.identity}
      >
        {children}
      </PlacementShell>
    );
  }

  return (
    <div className="flex min-h-screen">
      <Sidebar
        userName={session?.username}
        isAdmin={session?.is_admin}
        superuserAllowed={session?.superuser_allowed}
        superuserActive={session?.superuser_active}
        multiAP={session?.multi_ap}
        placement={!!session?.placement}
        placementProjects={session?.placement?.projects}
        placementProject={session?.placement?.project}
        open={sidebarOpen}
        onClose={() => setSidebarOpen(false)}
      />
      {/* Right column: scrollable main + sticky-bottom footer. The
          flex-col + flex-1 on main pushes the footer to the bottom of
          short pages while keeping it scroll-along on long pages. */}
      <div className="flex min-w-0 flex-1 flex-col overflow-auto">
        <MobileTopBar onOpen={() => setSidebarOpen(true)} />
        {/* Above <main> and inside the scroll container, so the warning is
            the first thing on every page and stays pinned while scrolling.
            Renders nothing unless the mode is armed. */}
        <SuperuserBanner session={session} />
        <main className="flex-1 px-4 py-6 lg:px-8 lg:py-8">{children}</main>
        <Footer />
      </div>
    </div>
  );
}

// useBrandedDocument keeps the tab's title and icon on the site's own.
//
// The server writes both into the HTML it serves. A client-side
// navigation then re-applies the root layout's metadata over them --
// the title goes back to "HTCondor Access Point" the moment somebody
// clicks a nav link -- and it does so after React has committed, so
// setting them once per render loses the race. Watching the head and
// putting them back is what actually holds. Writing the same value
// changes nothing, so the observer does not retrigger itself.
//
// Only for a deployment that renamed itself: an unconfigured one wants
// exactly what the metadata says, and no observer.
function useBrandedDocument() {
  const { page_title: title, favicon } = useBranding();
  const branded = (!!title && title !== DEFAULT_BRANDING.page_title) || !!favicon;
  useEffect(() => {
    if (!branded) return;
    const apply = () => {
      if (title && document.title !== title) document.title = title;
      if (!favicon) return;
      let link = document.querySelector<HTMLLinkElement>('link[rel="icon"]');
      if (!link) {
        link = document.createElement('link');
        link.rel = 'icon';
        document.head.appendChild(link);
      }
      if (link.getAttribute('href') !== favicon) link.setAttribute('href', favicon);
    };
    apply();
    const observer = new MutationObserver(apply);
    observer.observe(document.head, { childList: true, subtree: true, characterData: true });
    return () => observer.disconnect();
  }, [branded, title, favicon]);
}

// MobileTopBar shows a hamburger button and the app title on screens
// narrower than `lg`, where the sidebar is hidden by default. It's
// hidden entirely on lg+ since the sidebar is always visible there.
function MobileTopBar({ onOpen }: { onOpen: () => void }) {
  const branding = useBranding();
  return (
    <div className="sticky top-0 z-20 flex items-center gap-3 border-b border-white/10 bg-ink-950 px-3 py-2 text-gray-100 lg:hidden">
      <button
        type="button"
        onClick={onOpen}
        className="rounded-sm p-1 text-gray-200 hover:bg-white/10 hover:text-white"
        aria-label="Open menu"
      >
        <svg
          xmlns="http://www.w3.org/2000/svg"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
          className="h-6 w-6"
        >
          <line x1="3" y1="6" x2="21" y2="6" />
          <line x1="3" y1="12" x2="21" y2="12" />
          <line x1="3" y1="18" x2="21" y2="18" />
        </svg>
      </button>
      <div className="truncate text-sm font-semibold">{branding.page_title}</div>
    </div>
  );
}

// PlacementShell is the reduced frame for a placement-only session: a title
// bar with the person's name and Sign out, and nothing to navigate to.
function PlacementShell({ name, children }: { name?: string; children: React.ReactNode }) {
  const branding = useBranding();
  return (
    <div className="flex min-h-screen flex-col">
      <header className="flex items-center justify-between gap-3 bg-ink-950 px-4 py-3 text-gray-100">
        <div className="min-w-0">
          <div className="truncate text-sm font-semibold">{branding.page_title}</div>
        </div>
        <div className="flex items-center gap-3 text-xs">
          {name && <span className="truncate text-gray-300">{name}</span>}
          <button
            type="button"
            onClick={async () => {
              try {
                await api.auth.logout();
              } catch {
                // Leaving anyway; the next /auth/me says signed out.
              }
              window.location.href = '/';
            }}
            className="text-gray-400 hover:text-white"
          >
            Sign out
          </button>
        </div>
      </header>
      <main className="flex-1 px-4 py-6 lg:px-8 lg:py-8">{children}</main>
      <Footer />
    </div>
  );
}
