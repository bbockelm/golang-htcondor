//go:build darwin || freebsd

package config

import "golang.org/x/sys/unix"

// sysctlPhysicalMemory returns the machine's RAM in bytes.
//
// hw.memsize is darwin's spelling and hw.physmem is freebsd's; neither exists
// on the other, so the name is chosen by build tag rather than probed.
func sysctlPhysicalMemory() (uint64, bool) {
	name := "hw.memsize"
	if physmemPlatform {
		name = "hw.physmem"
	}
	n, err := unix.SysctlUint64(name)
	if err != nil {
		return 0, false
	}
	return n, true
}
