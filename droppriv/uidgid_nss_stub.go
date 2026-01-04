//go:build !linux || cgo

package droppriv

// tryNSSStrategy is a no-op on non-Linux systems or when CGO is enabled.
//
//nolint:unused // Used in nocgo build
func tryNSSStrategy() (LookupStrategy, error) {
	return nil, ErrStrategyNotAvailable
}

// ResetNSSCache is a no-op on non-Linux systems or when CGO is enabled.
func ResetNSSCache() {}

// SetNSSSwitchPath is a no-op on non-Linux systems or when CGO is enabled.
func SetNSSSwitchPath(_ string) {}
