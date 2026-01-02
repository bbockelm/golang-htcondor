//go:build !linux && !cgo

package droppriv

import "fmt"

// trySSSDIfp is a no-op on non-Linux systems.
func trySSSDIfp() (LookupStrategy, error) {
	return nil, fmt.Errorf("SSSD not available on this platform")
}
