//go:build arm64 || arm

package config

import (
	"math"
	"testing"
)

// Measured against HTCondor's own evaluator on arm64: $INT(1E20) is
// INT64_MAX there and $INT(0.0/0.0) is 0.
func TestTruncToInt64SaturatesOnARM(t *testing.T) {
	for _, tc := range []struct {
		in   float64
		want int64
	}{
		{1e20, math.MaxInt64},
		{1e308, math.MaxInt64},
		{math.Inf(1), math.MaxInt64},
		{math.NaN(), 0},
	} {
		if got := truncToInt64(tc.in); got != tc.want {
			t.Errorf("truncToInt64(%g) = %d, want %d", tc.in, got, tc.want)
		}
	}
}
