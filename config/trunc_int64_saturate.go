//go:build arm64 || arm

package config

import "math"

// truncOutOfRange is arm64's fcvtzs: saturate towards the value given, and
// send NaN to zero.
func truncOutOfRange(f float64) int64 {
	switch {
	case math.IsNaN(f):
		return 0
	case f >= math.MaxInt64:
		return math.MaxInt64
	case f <= math.MinInt64:
		return math.MinInt64
	}
	return int64(f)
}
