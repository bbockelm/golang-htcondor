//go:build !arm64 && !arm

package config

import (
	"math"
	"testing"
)

// x86-64 has one value for everything it cannot represent.
func TestTruncToInt64IsIndefiniteOnX86(t *testing.T) {
	for _, in := range []float64{1e20, 1e308, math.Inf(1), math.NaN()} {
		if got := truncToInt64(in); got != math.MinInt64 {
			t.Errorf("truncToInt64(%g) = %d, want %d", in, got, int64(math.MinInt64))
		}
	}
}
