// How a finished job is described, and the filters the archive page
// applies over the records it has loaded.
//
// History only ever holds terminal-state jobs, so the vocabulary is
// much narrower than the queue's — and more useful, because "completed"
// and "completed with exit code 127" are the same JobStatus and very
// different outcomes.

import type { ClassAd } from '@/lib/api';

export type ArchiveStatus = 'completed' | 'failed' | 'killed' | 'removed' | 'unknown';

// Stable order so the strip and the counts read the same way between
// renders. Succeeded first, then the ways of not succeeding.
export const ARCHIVE_STATUS_ORDER: ArchiveStatus[] = [
  'completed',
  'failed',
  'killed',
  'removed',
  'unknown',
];

export const ARCHIVE_STATUS_LABEL: Record<ArchiveStatus, string> = {
  completed: 'Completed',
  failed: 'Failed',
  killed: 'Killed',
  removed: 'Removed',
  unknown: 'Unknown',
};

export function archiveStatusCls(key: ArchiveStatus): string {
  switch (key) {
    case 'completed':
      return 'bg-emerald-100 text-emerald-800';
    case 'failed':
    case 'removed':
      return 'bg-rose-100 text-rose-800';
    case 'killed':
      return 'bg-amber-100 text-amber-800';
    default:
      return 'bg-gray-100 text-gray-700';
  }
}

export interface ArchiveStatusInfo {
  key: ArchiveStatus;
  label: string;
  cls: string;
}

// archiveStatus collapses the (JobStatus, ExitCode, ExitBySignal) tuple
// of a history entry into one user-readable outcome.
//
// A missing ExitCode counts as success: the schedd does not always
// record one, and a job that finished without a recorded failure is not
// a failure.
export function archiveStatus(ad: ClassAd): ArchiveStatusInfo {
  const status = num(ad.JobStatus);
  const exitCode = num(ad.ExitCode);
  const bySignal = ad.ExitBySignal === true || ad.ExitBySignal === 'true';
  const info = (key: ArchiveStatus, label?: string): ArchiveStatusInfo => ({
    key,
    label: label ?? ARCHIVE_STATUS_LABEL[key],
    cls: archiveStatusCls(key),
  });

  if (status === 3) return info('removed');
  if (status === 4) {
    if (bySignal) return info('killed');
    if (exitCode !== undefined && exitCode !== 0) {
      // The code is the whole point of the label: "Failed" tells you
      // nothing you could act on, "Failed (127)" says the executable
      // was not found.
      return info('failed', `Failed (${exitCode})`);
    }
    return info('completed');
  }
  return info('unknown');
}

export function countArchiveStatuses(ads: ClassAd[]): Record<ArchiveStatus, number> {
  const counts = {} as Record<ArchiveStatus, number>;
  for (const ad of ads) {
    const k = archiveStatus(ad).key;
    counts[k] = (counts[k] ?? 0) + 1;
  }
  return counts;
}

// An empty selection means "no filter" rather than "nothing" — the
// strip has no way to express the empty set and it is not a state a
// user would ask for.
export function filterAdsByArchiveStatus(
  ads: ClassAd[],
  selected: Set<ArchiveStatus>,
): ClassAd[] {
  if (selected.size === 0) return ads;
  return ads.filter((ad) => selected.has(archiveStatus(ad).key));
}

export function filterAdsByOwner(ads: ClassAd[], owner: string): ClassAd[] {
  if (!owner) return ads;
  return ads.filter((ad) => str(ad.Owner) === owner);
}

// The users present in what has been loaded, for the owner picker.
// `keep` is the currently-selected owner: a filter that narrows the
// loaded set to one user must not make its own control disappear.
export function ownersOf(ads: ClassAd[], keep?: string): string[] {
  const owners = new Set<string>();
  for (const ad of ads) {
    const o = str(ad.Owner);
    if (o) owners.add(o);
  }
  if (keep) owners.add(keep);
  return Array.from(owners).sort((a, b) => a.localeCompare(b));
}

// filterAdsByText runs a multi-token AND substring match against a flat
// haystack built from each record's user-visible fields, matching the
// semantics of the queue page's filter.
export function filterAdsByText(ads: ClassAd[], query: string): ClassAd[] {
  const q = query.trim().toLowerCase();
  if (q === '') return ads;
  const tokens = q.split(/\s+/);
  return ads.filter((ad) => {
    const haystack = [
      String(num(ad.ClusterId) ?? ''),
      String(num(ad.ProcId) ?? ''),
      str(ad.Owner) ?? '',
      str(ad.JobBatchName) ?? '',
      str(ad.Cmd) ?? '',
      str(ad.Args) ?? '',
      archiveStatus(ad).label.toLowerCase(),
    ]
      .join(' ')
      .toLowerCase();
    return tokens.every((t) => haystack.includes(t));
  });
}

function num(v: unknown): number | undefined {
  if (typeof v === 'number') return v;
  if (typeof v === 'string') {
    const n = Number(v);
    if (!Number.isNaN(n)) return n;
  }
  return undefined;
}

function str(v: unknown): string | undefined {
  if (typeof v === 'string' && v !== '') return v;
  if (v === undefined || v === null) return undefined;
  if (typeof v === 'string') return undefined;
  return String(v);
}
