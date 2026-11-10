package config

import (
	"math"
	"testing"
)

// The in-range cases are the part C++ actually defines: truncate towards
// zero. They hold on every architecture.
func TestTruncToInt64InRange(t *testing.T) {
	for _, tc := range []struct {
		in   float64
		want int64
	}{
		{0, 0},
		{1.9, 1},
		{-1.9, -1},
		{4e18, 4000000000000000000},
		{-4e18, -4000000000000000000},
		// The largest float64 that is below MaxInt64.
		{9.2e18, 9200000000000000000},
	} {
		if got := truncToInt64(tc.in); got != tc.want {
			t.Errorf("truncToInt64(%g) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

// Negative overflow is INT64_MIN on both architectures, so it is the one
// out-of-range case that can be asserted without a build tag -- and it is
// the one that agreed with the oracle before any of this.
func TestTruncToInt64NegativeOverflowIsAlwaysMin(t *testing.T) {
	for _, in := range []float64{-1e20, -1e308, math.Inf(-1)} {
		if got := truncToInt64(in); got != math.MinInt64 {
			t.Errorf("truncToInt64(%g) = %d, want %d", in, got, int64(math.MinInt64))
		}
	}
}
