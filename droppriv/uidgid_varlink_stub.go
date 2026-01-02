//go:build !linux && !cgo

package droppriv

import "fmt"

// trySystemdUserDB is a no-op on non-Linux systems.
func trySystemdUserDB() (LookupStrategy, error) {
	return nil, fmt.Errorf("systemd-userdbd not available on this platform")
}
