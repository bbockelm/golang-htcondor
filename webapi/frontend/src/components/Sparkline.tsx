'use client';

// When a problem happened, across the window the page is showing.
//
// This is the question a count cannot answer and the one a facilitator
// asks second: 2,536 jobs held in a burst that ended three hours ago and
// 2,536 still arriving are the same number and different situations.
//
// It is the trend half of a stat tile, not a chart: no axes, no grid, no
// value labels. The row already carries the number; this carries the
// shape. Every row on a page shares one axis -- the server buckets
// against the window rather than against each cluster's own extent --
// so the sparklines are comparable down the list, which is the whole
// reason they sit in a column.

const WIDTH = 132;
const HEIGHT = 22;
const GAP = 2;

export function Sparkline({
  counts,
  bucketSeconds,
  endsAt,
  label,
}: {
  counts: number[];
  // How much time one bucket covers, for the per-bar tooltip.
  bucketSeconds?: number;
  // Unix seconds at the right-hand edge, which is when the answer was
  // computed rather than when it was rendered.
  endsAt?: number;
  // What the whole thing is, for a reader who cannot see it.
  label: string;
}) {
  if (counts.length === 0) return null;
  const peak = Math.max(...counts);
  if (peak <= 0) return null;

  const barWidth = Math.max(1, (WIDTH - GAP * (counts.length - 1)) / counts.length);
  const lastNonEmpty = counts.reduce((acc, n, i) => (n > 0 ? i : acc), -1);

  return (
    <svg
      width={WIDTH}
      height={HEIGHT}
      viewBox={`0 0 ${WIDTH} ${HEIGHT}`}
      role="img"
      aria-label={label}
      className="shrink-0 overflow-visible"
    >
      {counts.map((n, i) => {
        const x = i * (barWidth + GAP);
        // An empty slice draws nothing. The gap is the information --
        // it is how "it stopped" looks.
        if (n === 0) return null;
        // A floor of 2px, so one occurrence in a window whose peak is
        // four thousand is still something you can see and hover.
        const h = Math.max(2, (n / peak) * HEIGHT);
        return (
          <rect
            key={i}
            x={x}
            y={HEIGHT - h}
            width={barWidth}
            height={h}
            rx={barWidth > 3 ? 1 : 0}
            // The most recent slice with anything in it wears the
            // accent; the rest recede. That one bar is the answer to
            // "is this still happening", which is why it is the only
            // thing in the row drawn in a colour.
            // gray-400 rather than a lighter step: these are data
            // marks, not chrome, and at three pixels wide a fill one
            // shade off the surface disappears.
            className={i === lastNonEmpty ? 'fill-brand-500' : 'fill-gray-400'}
          >
            <title>{bucketTitle(n, i, counts.length, bucketSeconds, endsAt)}</title>
          </rect>
        );
      })}
    </svg>
  );
}

// bucketTitle is the hover text for one slice. Native <title> rather
// than a floating tooltip: at four pixels wide a bar cannot host a
// positioned popover without fighting the row it sits in, and the
// browser's own tooltip is reachable by keyboard and by screen reader.
function bucketTitle(
  n: number,
  index: number,
  total: number,
  bucketSeconds?: number,
  endsAt?: number,
): string {
  const jobs = `${n.toLocaleString()} job${n === 1 ? '' : 's'}`;
  if (!bucketSeconds || !endsAt) return jobs;
  const start = endsAt - (total - index) * bucketSeconds;
  const end = start + bucketSeconds;
  return `${new Date(start * 1000).toLocaleString()} – ${new Date(
    end * 1000,
  ).toLocaleTimeString()}: ${jobs}`;
}

// sparklineLabel describes the shape in words, for the aria-label and
// for anyone who would rather read it than squint at 22 pixels.
export function sparklineLabel(
  counts: number[],
  bucketSeconds?: number,
  endsAt?: number,
): string {
  const total = counts.reduce((a, b) => a + b, 0);
  const lastNonEmpty = counts.reduce((acc, n, i) => (n > 0 ? i : acc), -1);
  if (lastNonEmpty < 0) return 'No occurrences in this window';
  const parts = [`${total.toLocaleString()} occurrences across the window`];
  if (bucketSeconds && endsAt) {
    const quiet = counts.length - 1 - lastNonEmpty;
    parts.push(
      quiet === 0
        ? 'still arriving'
        : `nothing in the last ${humanSpan(quiet * bucketSeconds)}`,
    );
  }
  return parts.join('; ');
}

function humanSpan(seconds: number): string {
  if (seconds < 90) return `${Math.round(seconds)} seconds`;
  if (seconds < 90 * 60) return `${Math.round(seconds / 60)} minutes`;
  if (seconds < 48 * 3600) return `${Math.round(seconds / 3600)} hours`;
  return `${Math.round(seconds / 86400)} days`;
}
