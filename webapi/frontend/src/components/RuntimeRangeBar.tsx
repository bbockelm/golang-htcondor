// RuntimeRangeBar draws how long a job is likely to run on an axis from
// zero: a light band over the usual range, a tick at the expected time,
// and, for a running job, a fill from zero to how long it has run.
//
// It is decorative: the text beside it states every figure it draws, so
// it is hidden from assistive technology. A rough guess hatches its band
// and greys its tick, so the difference does not rest on colour alone;
// neither does a job running longer than usual, whose card says so in
// words.
//
// The elapsed fill runs along the track itself, through the band rather
// than over it, so the usual range stays visible behind a job that has
// run past it.

export interface RuntimeRangeBarProps {
  // Fractions of the bar's width, 0..1.
  band?: { from: number; to: number };
  tick: number;
  elapsed?: number;
  // The elapsed fill was cut at the end of the axis.
  elapsedCapped?: boolean;
  rough?: boolean;
  longer?: boolean;
}

const pct = (f: number) => `${(Math.min(1, Math.max(0, f)) * 100).toFixed(2)}%`;

// Stripes for a rough guess's band: two greys, wide enough to read as a
// pattern at 10px tall.
const HATCH = 'repeating-linear-gradient(-45deg, #d1d5db 0 4px, #f3f4f6 4px 8px)';

export function RuntimeRangeBar({ band, tick, elapsed, elapsedCapped, rough, longer }: RuntimeRangeBarProps) {
  return (
    <div className="relative h-7" aria-hidden="true" data-testid="runtime-range-bar">
      <div className="absolute inset-x-0 top-3 h-1 rounded-full bg-gray-200" />
      {band && band.to > band.from && (
        <div
          data-part="band"
          className={`absolute top-2 h-3 rounded-full ${rough ? '' : 'bg-[#cde2fb]'}`}
          style={{
            left: pct(band.from),
            width: pct(band.to - band.from),
            ...(rough ? { backgroundImage: HATCH } : {}),
          }}
        />
      )}
      {elapsed !== undefined && elapsed > 0 && (
        <div
          data-part="elapsed"
          className={`absolute left-0 top-3 h-1 ${elapsedCapped ? 'rounded-l-full' : 'rounded-full'} ${
            longer ? 'bg-amber-600' : 'bg-green-700'
          }`}
          style={{ width: pct(elapsed) }}
        />
      )}
      <div
        data-part="tick"
        className={`absolute top-1 h-5 w-[3px] -translate-x-1/2 rounded-full ${rough ? 'bg-gray-500' : 'bg-[#1f5fbf]'}`}
        style={{ left: pct(tick) }}
      />
    </div>
  );
}
