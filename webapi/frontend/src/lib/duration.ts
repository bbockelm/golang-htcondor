// humanDuration renders a non-negative number of seconds as a compact
// "1d2h", "5h3m", "12m4s", or "30s" string. Negative inputs are
// clamped to 0 so a slight clock skew between the client and the
// schedd's wallclock doesn't produce nonsense like "-3s ago".
export function humanDuration(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds < 0) seconds = 0;
  const s = Math.floor(seconds);
  if (s < 60) return `${s}s`;

  const days = Math.floor(s / 86400);
  const hrs = Math.floor((s % 86400) / 3600);
  const mins = Math.floor((s % 3600) / 60);
  const secs = s % 60;

  // Two most-significant non-zero units. Pick the right pair so a
  // 3-day-2-hour-old job doesn't display "3d0h2h" or drop the hours.
  if (days > 0) return hrs > 0 ? `${days}d${hrs}h` : `${days}d`;
  if (hrs > 0) return mins > 0 ? `${hrs}h${mins}m` : `${hrs}h`;
  return secs > 0 ? `${mins}m${secs}s` : `${mins}m`;
}

// approxDuration is humanDuration for a figure that is only ever "about"
// right: rounded to the nearest minute once it is a minute or more, and
// to the nearest hour once it is a day or more, so an estimate never
// reads with more precision than it has ("12m", not "12m34s").
export function approxDuration(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds < 0) seconds = 0;
  let s = Math.round(seconds);
  if (s >= 86400) s = Math.round(s / 3600) * 3600;
  else if (s >= 60) s = Math.round(s / 60) * 60;
  return humanDuration(s);
}
