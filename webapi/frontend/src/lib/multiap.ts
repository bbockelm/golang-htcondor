// Multi-AP mode: one server in front of several access points. The server
// says so in the session (`multi_ap`); job rows then name their access
// point (`schedd`) and carry `job_id`, the text form of a complete job id
// for URLs. Pages read this hook to show the access point column and
// filter, and to leave out actions the server does not offer in this mode.

import { useQuery } from '@tanstack/react-query';
import { api, type Sources } from '@/lib/api';

export function useMultiAP(): boolean {
  return useMultiAPMode() === true;
}

// useMultiAPMode is undefined until the session has loaded, for a page
// whose first request depends on the mode.
export function useMultiAPMode(): boolean | undefined {
  const { data } = useQuery({ queryKey: ['session'], queryFn: api.auth.me });
  return data === undefined ? undefined : !!data.multi_ap;
}

// The access points, for the filter and the /aps page. Only fetched in
// multi-AP mode.
export function useAccessPoints(enabled: boolean) {
  return useQuery({
    queryKey: ['aps'],
    queryFn: api.aps,
    enabled,
    refetchInterval: 30_000,
  });
}

// describeDegraded renders one degraded access point for a banner:
// "ap17.example.org (stale, 412 s behind)".
export function describeDegraded(d: Sources['degraded'][number]): string {
  const parts: string[] = [d.state];
  if (d.staleness_seconds !== undefined) {
    parts.push(`${d.staleness_seconds} s behind`);
  } else if (d.last_seen) {
    parts.push(`last seen ${new Date(d.last_seen).toLocaleString()}`);
  }
  return `${d.schedd} (${parts.join(', ')})`;
}
