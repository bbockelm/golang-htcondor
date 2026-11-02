//go:build darwin

package config

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// darwinVersion reads the product version through sysctl rather than running
// sw_vers, which is what sysapi_get_darwin_info does.
//
// The shell-out is deliberately not reproduced. This runs during config
// initialization, which every daemon and tool in this library does at startup,
// and `my_popenv` there has no timeout: on a loaded machine the exec blocked
// long enough to hit go test's 10-minute limit, with a stack that pointed at
// config.go rather than at the process it was waiting for. kern.osproductversion
// is the same number without the fork.
func darwinVersion() (major, minor int, ok bool) {
	version, err := unix.Sysctl("kern.osproductversion")
	if err != nil || version == "" {
		return 0, 0, false
	}
	// "27.0" or "10.15.7"; a patch level is read and discarded, as the
	// long name carries only major and minor.
	var patch int
	switch n, _ := fmt.Sscanf(version, "%d.%d.%d", &major, &minor, &patch); n {
	case 2, 3:
		return major, minor, true
	default:
		return 0, 0, false
	}
}
