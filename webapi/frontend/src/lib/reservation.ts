// Reservation durations, in the two shapes the page needs them.
//
// The wire carries seconds (webapi/httpserver/handlers_reservations.go:
// a number input cannot sensibly round-trip "6h0m0s"). An operator
// thinks in hours and minutes -- a 50-minute class, a six-hour lead --
// so the form offers one box of each and the table prints the pair.

export interface HoursMinutes {
  hours: number;
  minutes: number;
}

// splitHoursMinutes breaks a count of seconds into whole hours and the
// remaining whole minutes. Seconds below a minute are dropped: nothing
// about a reservation is set to that precision, and keeping them would
// mean a value the form cannot show and so would silently discard on
// the next save.
export function splitHoursMinutes(seconds: number): HoursMinutes {
  if (!Number.isFinite(seconds) || seconds < 0) seconds = 0;
  const total = Math.floor(seconds / 60);
  return { hours: Math.floor(total / 60), minutes: total % 60 };
}

// hoursMinutesToSeconds is the inverse. Blank boxes read as zero, which
// is what an operator who cleared a field means; whether zero is legal
// for this particular field is the server's call, and it says so.
export function hoursMinutesToSeconds(hours: number, minutes: number): number {
  const h = Number.isFinite(hours) && hours > 0 ? Math.floor(hours) : 0;
  const m = Number.isFinite(minutes) && minutes > 0 ? Math.floor(minutes) : 0;
  return h * 3600 + m * 60;
}

// formatHoursMinutes prints seconds for reading: "6 h", "1 h 30 min",
// "45 min". Hours are not rolled up into days even past 24 -- a lead of
// "36 h" is directly comparable with the 6 h default, where "1 d 12 h"
// is not.
export function formatHoursMinutes(seconds: number): string {
  const { hours, minutes } = splitHoursMinutes(seconds);
  if (hours === 0) return `${minutes} min`;
  if (minutes === 0) return `${hours} h`;
  return `${hours} h ${minutes} min`;
}
