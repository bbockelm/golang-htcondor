'use client';

// The row of status chips above a job listing: click "Running" and the
// listing narrows to running jobs.
//
// The empty selection means "show everything" rather than "show
// nothing". That is what makes a single click on the status you care
// about do the obvious thing — with chips that start switched on, the
// first click would switch off the one you wanted. Clicking a second
// chip adds it; clicking the last selected chip off returns to showing
// everything.
//
// Generic over the status vocabulary because the queue and the archive
// do not share one: the queue has seven live states, the archive has
// four terminal ones.

export interface StatusChip<K extends string> {
  key: K;
  label: string;
  // Tailwind classes for the chip's colour, so each page keeps the
  // palette its rows already use.
  cls: string;
  count: number;
}

export function StatusStrip<K extends string>({
  chips,
  selected,
  onToggle,
  onClear,
  total,
  label,
  noun = 'jobs',
}: {
  chips: StatusChip<K>[];
  selected: Set<K>;
  onToggle: (key: K) => void;
  onClear: () => void;
  // Total across every status, which is not the sum of the chips once a
  // status filter is applied — the caller passes the unfiltered total
  // so the "All" chip keeps reading as the way back.
  total: number;
  label: string;
  noun?: string;
}) {
  if (chips.length === 0) return null;
  const filtering = selected.size > 0;

  return (
    <div className="flex flex-wrap items-center gap-1.5" role="group" aria-label={label}>
      <button
        type="button"
        onClick={onClear}
        aria-pressed={!filtering}
        // Spelled out rather than left to the two adjacent spans, which
        // the accessibility tree would run together as "All6".
        aria-label={`All statuses, ${total} ${total === 1 ? noun.replace(/s$/, '') : noun}`}
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

      {chips.map((chip) => {
        const on = selected.has(chip.key);
        return (
          <button
            key={chip.key}
            type="button"
            onClick={() => onToggle(chip.key)}
            aria-pressed={on}
            aria-label={`${chip.label}, ${chip.count} ${
              chip.count === 1 ? noun.replace(/s$/, '') : noun
            }`}
            title={
              on
                ? `Stop showing ${chip.label} ${noun}`
                : `Show only ${chip.label} ${noun}`
            }
            className={`inline-flex items-center gap-1.5 rounded-full px-3 py-1 text-xs font-medium tabular-nums transition ${chip.cls} ${
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
            {chip.label}
            <span className="font-semibold">{chip.count.toLocaleString()}</span>
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
