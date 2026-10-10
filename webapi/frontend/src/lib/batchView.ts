// What a batch listing shows, from the job ads it loaded and the filters
// the user set. Shared by /jobs and /users/<owner>.
//
// One function rather than three calls in each page because the order of
// operations is the point and is easy to get wrong in place: the rows
// come from the status-filtered ads, and progress must NOT -- a batch
// whose running jobs the "Held" chip has hidden is not nearly done, which
// is what counting the survivors would say (see batchProgress.ts).

import type { ClassAd, DisplayStatus } from '@/lib/api';
import { progressByBatch, type BatchProgressResult } from '@/lib/batchProgress';
import {
  applyBatchFilter,
  filterAdsByStatus,
  groupIntoBatches,
  type Batch,
} from '@/lib/batches';

export interface BatchView {
  // The ads the status chips kept, for the summary panel.
  statusFiltered: ClassAd[];
  batches: Batch[];
  // Keyed by Batch.groupKey; computed over every ad.
  progress: Map<string, BatchProgressResult>;
}

// batchView: `allLoaded` says the ads are every queued job of each batch
// they touch; see progressByBatch.
export function batchView(
  ads: ClassAd[],
  statuses: Set<DisplayStatus>,
  textFilter: string,
  allLoaded: boolean,
): BatchView {
  const statusFiltered = filterAdsByStatus(ads, statuses);
  return {
    statusFiltered,
    batches: applyBatchFilter(groupIntoBatches(statusFiltered), textFilter),
    progress: progressByBatch(ads, allLoaded),
  };
}

// What the table's last column describes. The command is what a batch
// IS; once the view is narrowed to one status, there is a better answer
// to "what about these jobs".
export type BatchDetail = 'command' | 'hold';

// batchDetailFor: what the table's last column describes under a status
// selection. With exactly "Held" selected, the question becomes why the
// held jobs are held. Exactly "Held" --
// jobs held while their input uploads are a separate chip, and are not
// stuck.
export function batchDetailFor(statuses: Set<DisplayStatus>): BatchDetail {
  if (statuses.size !== 1) return 'command';
  if (statuses.has('held')) return 'hold';
  return 'command';
}
