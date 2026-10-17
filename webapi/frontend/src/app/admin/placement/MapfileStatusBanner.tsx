'use client';

// The outcome of the placementd's last map file load.

import { useQuery } from '@tanstack/react-query';
import { placementAdmin } from '@/lib/placementAdmin';
import { formatWhen } from './directoryShared';

export function MapfileStatusBanner() {
  const status = useQuery({
    queryKey: ['placement', 'mapfile-status'],
    queryFn: placementAdmin.mapfileStatus,
    refetchInterval: 60_000,
  });

  if (status.error) {
    return (
      <p className="text-sm text-red-600">
        Failed to read the map file status: {(status.error as Error).message}
      </p>
    );
  }
  const s = status.data;
  if (!s) return null;

  const clean = s.ok && s.quarantined === 0 && s.conflicts === 0;
  return (
    <div
      data-testid="mapfile-status"
      className={`rounded-lg border p-3 text-sm ${
        clean ? 'border-gray-200 bg-white text-gray-700' : 'border-amber-300 bg-amber-50 text-amber-900'
      }`}
    >
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1">
        <span>
          Map file loaded <span className="font-medium">{formatWhen(s.load_time, 'never')}</span>
        </span>
        {s.load_attempt_time && s.load_attempt_time !== s.load_time && (
          <span>Last attempt {formatWhen(s.load_attempt_time)}</span>
        )}
        <span>
          Quarantined <span className="font-medium">{s.quarantined}</span>
        </span>
        <span>
          Reclaimed <span className="font-medium">{s.conflicts}</span>
        </span>
        {s.user_mapfile && <span className="font-mono text-xs text-gray-500">{s.user_mapfile}</span>}
      </div>
      {s.problems.length > 0 && (
        <details className="mt-2">
          <summary className="cursor-pointer text-xs font-medium">
            {s.problems.length} problem{s.problems.length === 1 ? '' : 's'}
          </summary>
          <ul className="mt-1 space-y-0.5 text-xs">
            {s.problems.map((p, i) => (
              <li key={i}>
                <span className="font-mono">
                  {p.file ? `${p.file}${p.line ? `:${p.line}` : ''}` : ''}
                </span>{' '}
                {p.kind && <span className="font-medium">{p.kind}</span>}
                {p.key && <span className="font-mono"> {p.key}</span>}
                {p.message && <span>: {p.message}</span>}
              </li>
            ))}
          </ul>
        </details>
      )}
    </div>
  );
}
