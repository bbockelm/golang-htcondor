'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api, type InteractiveApp, type SiteApp } from '@/lib/api';
import { useBranding } from '@/lib/branding';
import { placementAdmin } from '@/lib/placementAdmin';
import { CountBadge } from './CountBadge';
import { ProjectSwitcher } from './ProjectSwitcher';

interface SidebarProps {
  userName?: string;
  isAdmin?: boolean;
  // May this session arm superuser mode, and is it armed? Distinct from
  // isAdmin: reading the admin pages and acting as other users are separate
  // privileges gated on separate groups.
  superuserAllowed?: boolean;
  superuserActive?: boolean;
  // Several access points behind this server: only the pages that mode
  // serves are offered.
  multiAP?: boolean;
  // This server runs the reservation subsystem, so its admin page is
  // offered. Off unless configured.
  reservations?: boolean;
  // The built-in interactive applications this access point offers. None
  // of them, and the Interactive item goes: a link to a page that can
  // only explain that nothing can be started is worse than no link. The
  // page itself stays reachable if typed, the way every other collapsed
  // item does, so a session still running can be found.
  interactive?: InteractiveApp[];
  // Operator-deployed web apps this session may see. Server-filtered;
  // the sidebar renders what it is given and decides nothing.
  siteApps?: SiteApp[];
  // Collapse the general-purpose navigation: this session is meant to
  // be in its app. Presentation only -- nothing here restricts access.
  appOnly?: boolean;
  // The session opened the full console deliberately, so show the way
  // back rather than only the way out.
  expertActive?: boolean;
  // This session can request a placement token.
  placement?: boolean;
  // A placement-assigned account's projects and the selected one.
  placementProjects?: string[];
  placementProject?: string;
  // Mobile drawer state. On lg+ the sidebar is always visible -- pinned
  // to the viewport's height, so the account controls at its foot stay on
  // screen however long the page -- and these are ignored.
  open: boolean;
  onClose: () => void;
}

const NAV = [
  { href: '/', label: 'Dashboard' },
  { href: '/jobs', label: 'Jobs' },
  { href: '/issues', label: 'Issues' },
  { href: '/archive', label: 'Archive' },
  { href: '/utilization', label: 'Utilization' },
  { href: '/submit', label: 'Submit' },
  { href: '/interactive', label: 'Interactive' },
  { href: '/pool', label: 'Pool' },
  { href: '/info', label: 'Info' },
];

// Multi-AP mode serves job and history reads, job actions, submit and
// interactive work.
const MULTI_AP_NAV = [
  { href: '/', label: 'Dashboard' },
  { href: '/jobs', label: 'Jobs' },
  { href: '/archive', label: 'Archive' },
  { href: '/utilization', label: 'Utilization' },
  { href: '/submit', label: 'Submit' },
  { href: '/interactive', label: 'Interactive' },
  { href: '/aps', label: 'Access Points' },
];

// Offered when this server issues placement tokens and the session has a
// placement identity.
const PLACEMENT_NAV = [{ href: '/placement', label: 'Placement token' }];

const ADMIN_NAV = [
  { href: '/admin/placement', label: 'Placement' },
  { href: '/admin/reservations', label: 'Reservations' },
  { href: '/admin/clients', label: 'OAuth2 Clients' },
  { href: '/admin/tokens', label: 'OAuth2 Tokens' },
  { href: '/admin/api-keys', label: 'API Keys' },
  { href: '/admin/usage', label: 'Usage' },
  { href: '/admin/logs', label: 'Logs' },
];

export function Sidebar({
  userName,
  isAdmin,
  superuserAllowed,
  superuserActive,
  multiAP,
  reservations,
  interactive,
  siteApps,
  appOnly,
  expertActive,
  placement,
  placementProjects,
  placementProject,
  open,
  onClose,
}: SidebarProps) {
  const pathname = usePathname();
  const branding = useBranding();
  // Pending access requests, beside the admin Placement link.
  const pendingRequests = useQuery({
    queryKey: ['placement', 'requests', 'count'],
    queryFn: placementAdmin.pendingRequests,
    enabled: !!isAdmin && !multiAP,
    refetchInterval: 60_000,
    retry: false,
  });

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
        className={`fixed inset-y-0 left-0 z-40 flex w-60 shrink-0 flex-col border-r bg-ink-950 text-gray-100 transition-transform lg:sticky lg:top-0 lg:h-screen lg:translate-x-0 ${
          open ? 'translate-x-0' : '-translate-x-full'
        }`}
      >
        <div className="flex items-center justify-between border-b border-white/10 px-4 py-5">
          <div className="min-w-0">
            <div className="truncate text-base font-semibold" title={branding.site_name}>
              {branding.site_name}
            </div>
            {branding.site_tagline && (
              <div className="truncate text-xs text-gray-400">{branding.site_tagline}</div>
            )}
          </div>
          <button
            type="button"
            onClick={onClose}
            className="rounded-sm p-1 text-gray-300 hover:bg-white/10 hover:text-white lg:hidden"
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
          {/* An app-only session does not get the general-purpose
              console in its navigation unless it asked for it. The
              pages still exist and still work if typed. */}
          {(!appOnly || expertActive) &&
            [...(multiAP ? MULTI_AP_NAV : NAV), ...(placement ? PLACEMENT_NAV : [])]
              // Undefined is a session answered by a server too old to
              // say so, or one still loading: offer the item, which is
              // what happened before this was published.
              .filter(
                (item) =>
                  item.href !== '/interactive' ||
                  interactive === undefined ||
                  interactive.length > 0,
              )
              .map((item) => (
                <NavLink
                  key={item.href}
                  href={item.href}
                  active={pathname === item.href}
                  onNavigate={onClose}
                >
                  {item.label}
                </NavLink>
              ))}

          {appOnly && !expertActive && (
            // The door out. A visible link rather than a query
            // parameter somebody has to be told about: the mechanism is
            // the same, and a hidden one becomes folklore.
            <a
              href="/site/expert"
              data-testid="expert-mode"
              className="mt-5 block rounded-sm px-3 py-2 text-sm text-gray-400 hover:bg-white/10 hover:text-white"
            >
              Expert mode
            </a>
          )}

          {appOnly && expertActive && (
            <a
              href="/site/expert?close=1"
              data-testid="leave-expert-mode"
              className="mt-5 block rounded-sm px-3 py-2 text-sm text-gray-400 hover:bg-white/10 hover:text-white"
            >
              Back to my apps
            </a>
          )}

          {siteApps && siteApps.length > 0 && (
            <>
              <div className="mb-1 mt-5 px-3 text-[10px] uppercase tracking-wider text-gray-500">
                Apps
              </div>
              {siteApps.map((app) => (
                // A plain anchor, not next/link: a site app is a
                // separate document served by the access point, not a
                // route in this export. Routing to it client-side would
                // ask Next for a page that does not exist here.
                <a
                  key={app.id}
                  href={app.url}
                  onClick={onClose}
                  title={app.description}
                  data-testid={`site-app-${app.id}`}
                  className="block rounded-sm px-3 py-2 text-sm text-gray-300 hover:bg-white/10 hover:text-white"
                >
                  {app.name}
                </a>
              ))}
            </>
          )}

          {isAdmin && (
            <>
              <div className="mb-1 mt-5 px-3 text-[10px] uppercase tracking-wider text-gray-500">
                Admin
              </div>
              {ADMIN_NAV.filter(
                (item) =>
                  (!multiAP || item.href !== '/admin/placement') &&
                  // Reservations are off unless the server runs them.
                  (reservations || item.href !== '/admin/reservations'),
              ).map((item) => (
                <NavLink
                  key={item.href}
                  href={item.href}
                  active={pathname === item.href}
                  onNavigate={onClose}
                >
                  {item.label}
                  {item.href === '/admin/placement' && (
                    <CountBadge count={pendingRequests.data} label="pending access requests" />
                  )}
                </NavLink>
              ))}
            </>
          )}
        </nav>

        {superuserAllowed && <SuperuserToggle active={!!superuserActive} />}

        <div className="border-t border-white/10 px-4 py-3 text-xs">
          {userName ? (
            <>
              <div className="truncate text-gray-300">{userName}</div>
              {placementProjects && (
                <ProjectSwitcher projects={placementProjects} project={placementProject} />
              )}
              <button
                type="button"
                onClick={async () => {
                  // Logout is a POST (the GET form was removed for
                  // CSRF safety in 2026-05). After the API clears the
                  // session cookie, hard-navigate to root so the
                  // session-aware UI re-fetches /auth/me and shows
                  // "Sign in" instead of stale user data.
                  try {
                    await api.auth.logout();
                  } catch {
                    // Ignore — even if the API call fails, the user
                    // wants to leave; the next /auth/me will fail
                    // and the SPA will redirect them to /login.
                  }
                  window.location.href = '/';
                }}
                className="text-left text-gray-400 hover:text-white"
              >
                Sign out
              </button>
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

// SuperuserToggle arms superuser mode. Only rendered for sessions that are
// permitted to use it.
//
// Arming asks for confirmation; disarming does not. The asymmetry is the
// point: taking on the ability to act as anyone deserves a deliberate moment,
// while giving it up should never be discouraged by friction.
function SuperuserToggle({ active }: { active: boolean }) {
  const qc = useQueryClient();
  const toggle = useMutation({
    mutationFn: (enabled: boolean) => api.auth.setSuperuserMode(enabled),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['session'] }),
  });

  return (
    <div className="border-t border-white/10 px-4 py-3">
      <button
        type="button"
        disabled={toggle.isPending}
        onClick={() => {
          if (active) {
            toggle.mutate(false);
            return;
          }
          if (
            confirm(
              'Turn on superuser mode?\n\n' +
                "While it is on, actions you take can apply to other users' jobs. " +
                'Every action is logged against your name and recorded in the job.\n\n' +
                'It turns itself off after 30 minutes.',
            )
          ) {
            toggle.mutate(true);
          }
        }}
        className={`w-full rounded px-3 py-2 text-left text-xs font-medium transition ${
          active
            ? 'bg-red-600 text-white hover:bg-red-500'
            : 'bg-white/5 text-gray-300 hover:bg-white/10 hover:text-white'
        }`}
      >
        {toggle.isPending
          ? 'Working…'
          : active
            ? 'Superuser mode: ON'
            : 'Superuser mode: off'}
      </button>
      {toggle.isError && (
        <p className="mt-1 text-[11px] text-red-300">
          {(toggle.error as Error).message}
        </p>
      )}
    </div>
  );
}
