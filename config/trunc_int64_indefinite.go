//go:build !arm64 && !arm

package config

import "math"

// truncOutOfRange is x86-64's cvttsd2si: one "integer indefinite" value,
// INT64_MIN, for everything that cannot be represented, NaN included.
func truncOutOfRange(f float64) int64 {
	switch {
	case math.IsNaN(f), f >= math.MaxInt64, f <= math.MinInt64:
		return math.MinInt64
	}
	return int64(f)
}
