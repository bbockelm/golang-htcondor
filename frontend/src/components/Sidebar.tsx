'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';

interface SidebarProps {
  userName?: string;
  isAdmin?: boolean;
}

const NAV = [
  { href: '/', label: 'Dashboard' },
  { href: '/jobs', label: 'Jobs' },
  { href: '/submit', label: 'Submit' },
  { href: '/interactive', label: 'Interactive' },
];

const ADMIN_NAV = [
  { href: '/admin/clients', label: 'OAuth2 Clients' },
  { href: '/admin/tokens', label: 'OAuth2 Tokens' },
  { href: '/admin/logs', label: 'Logs' },
];

export function Sidebar({ userName, isAdmin }: SidebarProps) {
  const pathname = usePathname();

  return (
    <aside className="w-60 shrink-0 border-r bg-navy-950 text-gray-100 flex flex-col">
      <div className="px-4 py-5 border-b border-white/10">
        <div className="text-base font-semibold">HTCondor</div>
        <div className="text-xs text-gray-400">Access Point</div>
      </div>

      <nav className="flex-1 px-2 py-3 space-y-0.5">
        {NAV.map((item) => (
          <NavLink key={item.href} href={item.href} active={pathname === item.href}>
            {item.label}
          </NavLink>
        ))}

        {isAdmin && (
          <>
            <div className="mt-5 mb-1 px-3 text-[10px] uppercase tracking-wider text-gray-500">
              Admin
            </div>
            {ADMIN_NAV.map((item) => (
              <NavLink
                key={item.href}
                href={item.href}
                active={pathname === item.href}
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
            <div className="text-gray-300 truncate">{userName}</div>
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
  );
}

function NavLink({
  href,
  active,
  children,
}: {
  href: string;
  active: boolean;
  children: React.ReactNode;
}) {
  return (
    <Link
      href={href}
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
