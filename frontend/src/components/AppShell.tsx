'use client';

import { useQuery } from '@tanstack/react-query';
import { usePathname, useRouter, useSearchParams } from 'next/navigation';
import { useEffect } from 'react';
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
      <Sidebar userName={session?.username} isAdmin={session?.is_admin} />
      {/* Right column: scrollable main + sticky-bottom footer. The
          flex-col + flex-1 on main pushes the footer to the bottom of
          short pages while keeping it scroll-along on long pages. */}
      <div className="flex-1 min-w-0 flex flex-col overflow-auto">
        <main className="flex-1 px-4 py-6 lg:px-8 lg:py-8">
          {children}
        </main>
        <Footer />
      </div>
    </div>
  );
}
