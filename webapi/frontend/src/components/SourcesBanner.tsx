'use client';

import type { Sources } from '@/lib/api';
import { describeDegraded } from '@/lib/multiap';

// SourcesBanner lists the access points whose jobs may be out of date or
// missing from the page. Renders nothing when every access point is
// current, or outside multi-AP mode (no sources block).
export function SourcesBanner({ sources }: { sources?: Sources }) {
  const degraded = sources?.degraded ?? [];
  if (degraded.length === 0) return null;
  return (
    <div
      role="status"
      className="rounded border border-amber-200 bg-amber-50 px-3 py-2 text-sm text-amber-900"
    >
      {degraded.length === 1
        ? 'Jobs on one access point may be out of date or missing: '
        : `Jobs on ${degraded.length} of ${sources?.aps ?? degraded.length} access points may be out of date or missing: `}
      {degraded.map(describeDegraded).join('; ')}.
    </div>
  );
}
