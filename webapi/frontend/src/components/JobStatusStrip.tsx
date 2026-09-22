'use client';

import type { DisplayStatus } from '@/lib/api';
import { statusPillCls } from '@/app/jobs/[id]/JobDetailClient';
import { DISPLAY_STATUS_LABEL, DISPLAY_STATUS_ORDER } from '@/lib/batches';

// JobStatusStrip is the row of status chips above a job listing: click
// "Running" and the listing narrows to running jobs.
//
// The empty selection means "show everything" rather than "show nothing".
// That is what makes a single click on Running do the obvious thing — with
// chips that start switched on, the first click on the status you care
// about would switch off the one you wanted. Clicking a second chip adds
// it; clicking the last selected chip off returns to showing everything.
export function JobStatusStrip({
  counts,
  selected,
  onToggle,
  onClear,
  total,
}: {
  counts: Record<DisplayStatus, number>;
  selected: Set<DisplayStatus>;
  onToggle: (key: DisplayStatus) => void;
  onClear: () => void;
  // Total across every status, which is not the sum of `counts` once a
  // status filter is applied — the caller passes the unfiltered total so
  // the "All" chip keeps reading as the way back.
  total: number;
}) {
  // Show a chip for every status present, plus any selected status that
  // has gone empty — without the latter, filtering down to a status that
  // then drains (the last held job released, say) would leave the user
  // looking at an empty table with no control to undo it.
  const keys = DISPLAY_STATUS_ORDER.filter(
    (k) => (counts[k] ?? 0) > 0 || selected.has(k),
  );
  if (keys.length === 0) return null;

  const filtering = selected.size > 0;

  return (
    <div className="flex flex-wrap items-center gap-1.5" role="group" aria-label="Filter by status">
      <button
        type="button"
        onClick={onClear}
        aria-pressed={!filtering}
        // Spelled out rather than left to the two adjacent spans, which
        // the accessibility tree would run together as "All6".
        aria-label={`All statuses, ${total} job${total === 1 ? '' : 's'}`}
        className={`inline-flex items-center gap-1.5 rounded-full px-3 py-1 text-xs font-medium tabular-nums transition ${
          filtering
            ? 'bg-white text-gray-500 ring-1 ring-gray-300 hover:bg-gray-50'
            : 'bg-gray-800 text-white'
        }`}
      >
        All
        <span className={filtering ? 'text-gray-400' : 'text-gray-300'}>
          {total.toLocaleString()}
        </span>
      </button>

      {keys.map((key) => {
        const on = selected.has(key);
        const count = counts[key] ?? 0;
        return (
          <button
            key={key}
            type="button"
            onClick={() => onToggle(key)}
            aria-pressed={on}
            aria-label={`${DISPLAY_STATUS_LABEL[key]}, ${count} job${count === 1 ? '' : 's'}`}
            title={
              on
                ? `Stop showing ${DISPLAY_STATUS_LABEL[key]} jobs`
                : `Show only ${DISPLAY_STATUS_LABEL[key]} jobs`
            }
            className={`inline-flex items-center gap-1.5 rounded-full px-3 py-1 text-xs font-medium tabular-nums transition ${statusPillCls(
              key,
            )} ${
              on
                ? 'ring-2 ring-gray-800 ring-offset-1'
                : filtering
                  ? // Dimmed rather than hidden: the counts are still
                    // information, and the chip is still the way to add
                    // that status to the selection.
                    'opacity-40 hover:opacity-100'
                  : 'hover:ring-1 hover:ring-gray-400'
            }`}
          >
            {DISPLAY_STATUS_LABEL[key]}
            <span className="font-semibold">{count.toLocaleString()}</span>
          </button>
        );
      })}

      {filtering && (
        <button
          type="button"
          onClick={onClear}
          className="ml-1 text-xs text-gray-500 underline hover:text-gray-800"
        >
          clear
        </button>
      )}
    </div>
  );
}
