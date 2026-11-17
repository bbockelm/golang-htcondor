package spool

import (
	"math"
	"strings"
	"testing"
)

func TestParseSizeUnits(t *testing.T) {
	cases := []struct {
		in   string
		want int64
	}{
		{"0", 0},
		{"512", 512},
		{"512B", 512},
		{"1K", 1 << 10},
		{"1KB", 1 << 10},
		{"1KiB", 1 << 10},
		{"1M", 1 << 20},
		{"2G", 2 << 30},
		{"1T", 1 << 40},
		{"  1000M  ", 1000 << 20},
		{"1000 M", 1000 << 20},
		{"1000m", 1000 << 20},
	}
	for _, c := range cases {
		got, err := ParseSize(c.in)
		if err != nil {
			t.Errorf("ParseSize(%q) returned %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("ParseSize(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

// The default has to be writable in the knob, or an operator cannot
// restate the value they already have before changing it.
func TestParseSizeRoundTripsTheDefault(t *testing.T) {
	got, err := ParseSize("1000M")
	if err != nil {
		t.Fatal(err)
	}
	if want := DefaultLimits().MaxVolume; got != want {
		t.Errorf(`ParseSize("1000M") = %d, but DefaultLimits().MaxVolume = %d; `+
			"the documented default no longer spells the real one", got, want)
	}
}

func TestParseSizeRefusals(t *testing.T) {
	cases := []struct {
		in   string
		want string // substring of the message
	}{
		{"", "a size is required"},
		{"   ", "a size is required"},
		{"M", "does not begin with a number"},
		{"-1", "does not begin with a number"},
		{"1.5G", "unknown unit"},
		{"1X", "unknown unit"},
		{"1 GB extra", "unknown unit"},
		{"99999999999999999999", "not a byte count"},
	}
	for _, c := range cases {
		_, err := ParseSize(c.in)
		if err == nil {
			t.Errorf("ParseSize(%q) was accepted; want a refusal", c.in)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("ParseSize(%q) said %q, want it to mention %q", c.in, err, c.want)
		}
	}
}

// A size that overflows when multiplied must be refused, not wrapped.
// A wrapped ceiling is negative, and every comparison against it reads
// as "refuse everything" -- a limit that silently became a denial.
func TestParseSizeRefusesOverflowRatherThanWrapping(t *testing.T) {
	for _, in := range []string{"9000000T", "8589934592G"} {
		got, err := ParseSize(in)
		if err == nil {
			t.Errorf("ParseSize(%q) = %d, want a refusal", in, got)
			continue
		}
		if !strings.Contains(err.Error(), "too large") {
			t.Errorf("ParseSize(%q) said %q, want it to say the size is too large", in, err)
		}
	}
	// The largest value that still fits must survive, so the refusal
	// above is a real boundary and not just "big numbers are rejected".
	if _, err := ParseSize("8191T"); err != nil {
		t.Errorf(`ParseSize("8191T") returned %v; it fits in an int64 (max %d)`, err, int64(math.MaxInt64))
	}
}

func TestLimitsForSubstitutesOnlyTheVolume(t *testing.T) {
	def := DefaultLimits()

	got := LimitsFor(42 << 20)
	if got.MaxVolume != 42<<20 {
		t.Errorf("MaxVolume = %d, want %d", got.MaxVolume, 42<<20)
	}
	if got.MaxProcs != def.MaxProcs || got.Concurrency != def.Concurrency {
		t.Errorf("LimitsFor changed MaxProcs/Concurrency to %d/%d, want %d/%d",
			got.MaxProcs, got.Concurrency, def.MaxProcs, def.Concurrency)
	}
}

// Zero is "not configured" -- the standalone MCP binary never sets this
// field. It must mean the default, never "no ceiling": an unbounded
// fan-out is exactly what the limit exists to prevent.
func TestLimitsForTreatsUnsetAsTheDefaultNotUnlimited(t *testing.T) {
	for _, v := range []int64{0, -1, math.MinInt64} {
		got := LimitsFor(v)
		if got.MaxVolume != DefaultLimits().MaxVolume {
			t.Errorf("LimitsFor(%d).MaxVolume = %d, want the default %d",
				v, got.MaxVolume, DefaultLimits().MaxVolume)
		}
	}
}
