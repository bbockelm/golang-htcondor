// Links from a number on the dashboard to the jobs behind it.
//
// Every panel shows a count, and the question a count immediately raises
// is "which ones". Answering it should not require composing a ClassAd
// expression by hand, so each figure carries the constraint that
// produced it.
//
// Two rules run through all of this:
//
// The drill-down must ask the SAME question the panel did, window
// included. A list whose length disagrees with the number that was
// clicked reads as a bug in the data rather than a difference of
// definition, and the reader has no way to tell which it is.
//
// It must also point at a page that will resolve. A finished job lives
// in the queue for seconds and in the archive thereafter, so anything
// about completed work belongs on /archive -- the same split that had
// "recently completed" linking to "not found".

/** Build a /jobs URL narrowed by a server-side constraint. */
export function jobsDrilldown(constraint: string, why: string): string {
  return `/jobs?constraint=${encodeURIComponent(constraint)}&why=${encodeURIComponent(why)}`;
}

/** Build an /archive URL narrowed by a server-side constraint. */
export function archiveDrilldown(constraint: string, why: string): string {
  return `/archive?constraint=${encodeURIComponent(constraint)}&why=${encodeURIComponent(why)}`;
}

/** The constraint behind one status tile.
 *
 *  Mirrors dashboardStatusName on the server, which is the only reason
 *  these tiles add up: a job held solely because its input is still
 *  spooling is counted as "uploading" rather than HELD, so the HELD tile
 *  has to exclude it here too or the drill-down returns more jobs than
 *  the tile claimed. */
export function statusConstraint(key: string): string | null {
  switch (key) {
    case 'idle':
      return 'JobStatus == 1';
    case 'running':
      return 'JobStatus == 2';
    case 'removed':
      return 'JobStatus == 3';
    case 'completed':
      return 'JobStatus == 4';
    case 'held':
      // =!= rather than !=: an undefined HoldReasonCode makes != undefined
      // rather than true, which would drop the row.
      return 'JobStatus == 5 && HoldReasonCode =!= 16';
    case 'uploading':
      return 'JobStatus == 5 && HoldReasonCode == 16';
    case 'transferring_output':
      return 'JobStatus == 6';
    case 'suspended':
      return 'JobStatus == 7';
    default:
      // An unmapped bucket: better no link than one that quietly shows
      // the wrong jobs.
      return null;
  }
}
