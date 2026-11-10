'use client';

import type { UsageReading, UsageTone } from '@/lib/runningUsage';

// UsageBar is a meter: how much of its request a job (or a batch) is
// using.
//
// The track is the request -- 100% -- and the fill is the share used, so
// every bar in the column shares one scale whatever the request was. The
// track is a lighter step of the fill's own hue, so the bar reads as one
// object whose state is its colour. Anything over the request is capped
// at the end of the track and the percentage moves into the text: a bar
// drawn past its track would break the shared scale for every other row.
//
// The colour is never the only signal: a flagged job's text gains its
// percentage, and a batch's text gives its median and largest job against
// the request. A batch row adds a thin tick at its largest job, dark
// unless that job is itself flagged.
const TONE_CLS: Record<Exclude<UsageTone, 'none'>, { track: string; fill: string }> = {
  normal: { track: 'bg-[#cde2fb]', fill: 'bg-[#2a78d6]' },
  warn: { track: 'bg-amber-100', fill: 'bg-[#eda100]' },
  critical: { track: 'bg-red-100', fill: 'bg-[#d03b3b]' },
  muted: { track: 'bg-gray-100', fill: 'bg-gray-400' },
};

const TICK_CLS: Record<UsageTone, string> = {
  normal: 'bg-gray-700',
  muted: 'bg-gray-700',
  none: 'bg-gray-700',
  warn: 'bg-[#eda100]',
  critical: 'bg-[#d03b3b]',
};

export function UsageBar({
  reading,
  loading,
  stacked,
}: {
  reading: UsageReading | undefined;
  loading?: boolean;
  // Text under the bar rather than beside it, for the batch rows, whose
  // text is a sentence and would otherwise push the table wide.
  stacked?: boolean;
}) {
  if (!reading) {
    return <span className="text-xs text-gray-400">{loading ? 'loading…' : '—'}</span>;
  }
  if (reading.tone === 'none') {
    return (
      <span className="text-xs italic text-gray-400" title={reading.title}>
        {reading.text}
      </span>
    );
  }
  const cls = TONE_CLS[reading.tone];
  const clamp = (f: number) => Math.min(1, Math.max(0, f));
  return (
    <div
      className={`flex whitespace-nowrap ${stacked ? 'flex-col items-start gap-1' : 'items-center gap-2'}`}
      title={reading.title}
      data-tone={reading.tone}
    >
      {reading.fill !== undefined && (
        <div
          className={`relative h-2 w-24 shrink-0 rounded-sm ${cls.track}`}
          role="img"
          aria-label={reading.title}
        >
          <div
            className={`h-full rounded-sm ${cls.fill}`}
            // A floor of 2px so a job using almost nothing still shows
            // it is running, rather than an empty track that looks like
            // missing data.
            style={{ width: `max(2px, ${clamp(reading.fill) * 100}%)` }}
          />
          {reading.tick !== undefined && (
            <div
              className={`absolute -top-0.5 -bottom-0.5 w-[3px] -translate-x-1/2 rounded-sm ${TICK_CLS[reading.tickTone ?? 'normal']}`}
              data-tick-tone={reading.tickTone ?? 'normal'}
              style={{ left: `${clamp(reading.tick) * 100}%` }}
            />
          )}
        </div>
      )}
      <span className={`tabular-nums text-gray-700 ${stacked ? 'text-[11px]' : 'text-xs'}`}>
        {reading.text}
      </span>
    </div>
  );
}
