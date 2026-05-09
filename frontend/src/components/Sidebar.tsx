'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';

interface SidebarProps {
  userName?: string;
  isAdmin?: boolean;
  // Mobile drawer state. On lg+ the sidebar is always visible and these
  // are ignored.
  open: boolean;
  onClose: () => void;
}

const NAV = [
  { href: '/', label: 'Dashboard' },
  { href: '/jobs', label: 'Jobs' },
  { href: '/submit', label: 'Submit' },
  { href: '/interactive', label: 'Interactive' },
  { href: '/info', label: 'Info' },
];

const ADMIN_NAV = [
  { href: '/admin/clients', label: 'OAuth2 Clients' },
  { href: '/admin/tokens', label: 'OAuth2 Tokens' },
  { href: '/admin/logs', label: 'Logs' },
];

export function Sidebar({ userName, isAdmin, open, onClose }: SidebarProps) {
  const pathname = usePathname();

  return (
    <>
      {/* Mobile-only backdrop. On lg+ the sidebar is part of the layout
          flow and nothing dims behind it. */}
      <div
        className={`fixed inset-0 z-30 bg-black/50 transition-opacity lg:hidden ${
          open ? 'opacity-100' : 'pointer-events-none opacity-0'
        }`}
        aria-hidden="true"
        onClick={onClose}
      />

      <aside
        className={`fixed inset-y-0 left-0 z-40 flex w-60 shrink-0 flex-col border-r bg-ink-950 text-gray-100 transition-transform lg:static lg:translate-x-0 ${
          open ? 'translate-x-0' : '-translate-x-full'
        }`}
      >
        <div className="flex items-center justify-between border-b border-white/10 px-4 py-5">
          <div>
            <div className="text-base font-semibold">HTCondor</div>
            <div className="text-xs text-gray-400">Access Point</div>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="rounded p-1 text-gray-300 hover:bg-white/10 hover:text-white lg:hidden"
            aria-label="Close menu"
          >
            <svg
              xmlns="http://www.w3.org/2000/svg"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
              className="h-5 w-5"
            >
              <line x1="18" y1="6" x2="6" y2="18" />
              <line x1="6" y1="6" x2="18" y2="18" />
            </svg>
          </button>
        </div>

        <nav className="flex-1 space-y-0.5 overflow-y-auto px-2 py-3">
          {NAV.map((item) => (
            <NavLink
              key={item.href}
              href={item.href}
              active={pathname === item.href}
              onNavigate={onClose}
            >
              {item.label}
            </NavLink>
          ))}

          {isAdmin && (
            <>
              <div className="mb-1 mt-5 px-3 text-[10px] uppercase tracking-wider text-gray-500">
                Admin
              </div>
              {ADMIN_NAV.map((item) => (
                <NavLink
                  key={item.href}
                  href={item.href}
                  active={pathname === item.href}
                  onNavigate={onClose}
                >
                  {item.label}
                </NavLink>
              ))}
            </>
          )}
        </nav>

        <div className="border-t border-white/10 px-4 py-3 text-xs">
          {userName ? (
            <>
              <div className="truncate text-gray-300">{userName}</div>
              <a href="/logout" className="text-gray-400 hover:text-white">
                Sign out
              </a>
            </>
          ) : (
            <a href="/login" className="text-brand-300 hover:text-white">
              Sign in
            </a>
          )}
        </div>
      </aside>
    </>
  );
}

function NavLink({
  href,
  active,
  children,
  onNavigate,
}: {
  href: string;
  active: boolean;
  children: React.ReactNode;
  onNavigate: () => void;
}) {
  return (
    <Link
      href={href}
      onClick={onNavigate}
      className={`block rounded px-3 py-2 text-sm transition ${
        active
          ? 'bg-white/10 text-white'
          : 'text-gray-300 hover:bg-white/5 hover:text-white'
      }`}
    >
      {children}
    </Link>
  );
}
