'use client';

import {
  progressSentence,
  type BatchProgressResult,
  type ProgressPart,
} from '@/lib/batchProgress';

// The Progress cell: a short stacked bar over the batch's whole size,
// with the count beside it.
//
// The bar is a part-to-whole reading -- what share is done, and what the
// rest is doing -- so it is one stacked bar with a 2px gap between
// segments rather than a stroke around each.
//
// One colour means one state across the row: running, idle and held wear
// the hues of their pills in the Status column beside it, so the coloured
// part of the bar is the work still in flight. Done is a neutral slate --
// finished work is the bar's progress, not another state to read -- and
// dark enough to hold 3:1 on a light or a dark surface. Held is the red
// family's lighter step: next to the running green, the stronger reds
// collapse into it for deuteranopes (checked with the dataviz validator).
// A failed DAG node is the dark red, distinct from held. The text beside
// the bar is in ink, and the tooltip spells every segment out, so no
// reading depends on hue alone.
const PART_CLS: Record<ProgressPart, string> = {
  done: 'bg-slate-500',
  running: 'bg-green-600',
  // Nodes in the queue are running or waiting to: the Idle pill's hue.
  queued: 'bg-blue-500',
  idle: 'bg-blue-500',
  held: 'bg-red-400',
  failed: 'bg-red-700',
  other: 'bg-gray-300',
};

export function BatchProgressBar({ progress }: { progress: BatchProgressResult | undefined }) {
  if (!progress || !progress.known || progress.total <= 0) {
    return (
      <span className="text-gray-400" title={progress && !progress.known ? progress.why : undefined}>
        —
      </span>
    );
  }
  const sentence = progressSentence(progress);
  const parts = progress.parts.filter((p) => p.count > 0);
  return (
    <div className="flex items-center gap-2 whitespace-nowrap" title={sentence}>
      <div
        className="flex h-2 w-24 shrink-0 gap-[2px] overflow-hidden rounded-sm bg-gray-100"
        role="img"
        aria-label={sentence}
      >
        {parts.map((p) => (
          <div
            key={p.part}
            data-part={p.part}
            // flex-grow by count splits the width in proportion; the
            // minimum keeps one held job in a batch of ten thousand
            // visible, which is the job worth seeing.
            className={`h-full min-w-[2px] ${PART_CLS[p.part]}`}
            style={{ flexGrow: p.count, flexBasis: 0 }}
          />
        ))}
      </div>
      <span className="text-xs tabular-nums text-gray-700">
        {progress.done.toLocaleString()} / {progress.total.toLocaleString()}
      </span>
      {progress.failed > 0 && (
        <span className="text-xs tabular-nums text-red-700">
          {progress.failed.toLocaleString()} failed
        </span>
      )}
    </div>
  );
}
