'use client';

import { useQuery } from '@tanstack/react-query';
import { api } from '@/lib/api';

// Job applications (VS Code, JupyterLab) are served from this site's own
// origin, so the server refuses to open them while superuser mode is on.
// The pages that embed one ask this and show the notice instead of an
// iframe of the refusal.
export function useAppsBlockedBySuperuser(): boolean {
  const { data } = useQuery({ queryKey: ['session'], queryFn: api.auth.me });
  return !!data?.superuser_active;
}

export function AppsBlockedNotice() {
  return (
    <div className="rounded-sm border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">
      Job applications cannot be opened while superuser mode is on. Turn off
      superuser mode to open this one.
    </div>
  );
}
