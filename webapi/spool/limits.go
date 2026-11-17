package spool

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)

// Operator-settable form of the limits above.
//
// Only the byte ceiling is configurable. MaxProcs and Concurrency bound
// how hard one call leans on the schedd, which is a property of the
// schedd rather than of the site's taste; the volume is the one an
// operator has a real reason to move, because it is the number that
// decides how much a single command may push through the network and
// into the spool.

// LimitsFor returns the shared defaults with the configured upload
// ceiling substituted.
//
// Zero means "not configured", and the answer is then the default
// rather than no limit. Two callers depend on that: the standalone MCP
// binary builds its config without this knob at all, and a server whose
// operator never set it must still have a cap. Turning the cap off is
// deliberately not expressible -- an unbounded fan-out is the thing the
// limit exists to prevent, so the way to raise it is to name a bigger
// number, not to clear it.
func LimitsFor(maxUploadBytes int64) Limits {
	lim := DefaultLimits()
	if maxUploadBytes > 0 {
		lim.MaxVolume = maxUploadBytes
	}
	return lim
}

// ParseSize reads a byte count written the way an operator writes one:
// a plain number of bytes, or a number with a unit suffix ("1000M",
// "2G"). Units are powers of 1024, the base this package's own defaults
// are expressed in -- DefaultLimits' 1000 << 20 is exactly "1000M".
//
// Integers only. A fractional size ("1.5G") is refused rather than
// rounded: rounding a limit quietly is how a cap ends up being a
// different number from the one written in the config file.
func ParseSize(s string) (int64, error) {
	t := strings.TrimSpace(s)
	if t == "" {
		return 0, fmt.Errorf("a size is required")
	}

	digits := 0
	for digits < len(t) && t[digits] >= '0' && t[digits] <= '9' {
		digits++
	}
	if digits == 0 {
		return 0, fmt.Errorf("%q does not begin with a number", s)
	}

	n, err := strconv.ParseInt(t[:digits], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%q is not a byte count: %w", s, err)
	}

	unit, err := sizeUnit(strings.TrimSpace(t[digits:]))
	if err != nil {
		return 0, fmt.Errorf("%q: %w", s, err)
	}
	// Checked before multiplying, not after: the product wraps silently
	// and a wrapped ceiling is a negative one, which every comparison
	// here reads as "refuse everything".
	if n > math.MaxInt64/unit {
		return 0, fmt.Errorf("%q is too large to be a byte count", s)
	}
	return n * unit, nil
}

// sizeUnit maps a suffix to its multiplier. Both spellings of each unit
// are accepted and mean the same power of 1024; a site that writes "MB"
// means the same thing by it as one that writes "MiB", and refusing one
// of them would be pedantry in a config file.
func sizeUnit(u string) (int64, error) {
	switch strings.ToUpper(u) {
	case "", "B":
		return 1, nil
	case "K", "KB", "KIB":
		return 1 << 10, nil
	case "M", "MB", "MIB":
		return 1 << 20, nil
	case "G", "GB", "GIB":
		return 1 << 30, nil
	case "T", "TB", "TIB":
		return 1 << 40, nil
	}
	return 0, fmt.Errorf("unknown unit %q; use B, K, M, G or T", u)
}
