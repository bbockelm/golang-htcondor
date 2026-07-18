import type { Metadata } from 'next';
import { Suspense } from 'react';
import './globals.css';
import { Providers } from './providers';
import { AppShell } from '@/components/AppShell';

export const metadata: Metadata = {
  title: 'HTCondor Access Point',
  description: 'Web UI for the HTCondor HTTP API',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body className="min-h-screen bg-gray-50">
        <Providers>
          <Suspense
            fallback={
              <div className="min-h-screen flex items-center justify-center text-gray-400">
                Loading...
              </div>
            }
          >
            <AppShell>{children}</AppShell>
          </Suspense>
        </Providers>
      </body>
    </html>
  );
}
