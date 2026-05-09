'use client';

import { useQuery } from '@tanstack/react-query';
import { usePathname, useRouter, useSearchParams } from 'next/navigation';
import { useEffect, useState } from 'react';
import { api } from '@/lib/api';
import { Sidebar } from './Sidebar';
import { Footer } from './Footer';

// Pages that render without an authenticated session. The dashboard ('/')
// is included so unauthenticated visitors see a "Sign In" prompt instead
// of an instant redirect loop.
const publicPaths = ['/'];

export function AppShell({ children }: { children: React.ReactNode }) {
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

  if (!isPublic && !isAuthenticated) {
    // While the redirect is in flight, render nothing.
    return null;
  }

  return (
    <div className="flex min-h-screen">
      <Sidebar
        userName={session?.username}
        isAdmin={session?.is_admin}
        open={sidebarOpen}
        onClose={() => setSidebarOpen(false)}
      />
      {/* Right column: scrollable main + sticky-bottom footer. The
          flex-col + flex-1 on main pushes the footer to the bottom of
          short pages while keeping it scroll-along on long pages. */}
      <div className="flex min-w-0 flex-1 flex-col overflow-auto">
        <MobileTopBar onOpen={() => setSidebarOpen(true)} />
        <main className="flex-1 px-4 py-6 lg:px-8 lg:py-8">{children}</main>
        <Footer />
      </div>
    </div>
  );
}

// MobileTopBar shows a hamburger button and the app title on screens
// narrower than `lg`, where the sidebar is hidden by default. It's
// hidden entirely on lg+ since the sidebar is always visible there.
function MobileTopBar({ onOpen }: { onOpen: () => void }) {
  return (
    <div className="sticky top-0 z-20 flex items-center gap-3 border-b border-white/10 bg-ink-950 px-3 py-2 text-gray-100 lg:hidden">
      <button
        type="button"
        onClick={onOpen}
        className="rounded p-1 text-gray-200 hover:bg-white/10 hover:text-white"
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
      <div className="text-sm font-semibold">HTCondor Access Point</div>
    </div>
  );
}
