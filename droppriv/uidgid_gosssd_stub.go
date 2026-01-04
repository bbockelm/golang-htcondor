//go:build !linux || cgo

package droppriv

import (
	"context"
)

// trySSSD is a no-op on non-Linux systems or when CGO is enabled.
//
//nolint:unused // Used in nocgo build
func trySSSD(_ context.Context) (LookupStrategy, error) {
	return nil, ErrStrategyNotAvailable
}
