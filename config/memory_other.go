//go:build !darwin && !freebsd

package config

// sysctlPhysicalMemory has no meaning off the BSDs. Linux is handled earlier
// by detectMemoryLinux reading /proc/meminfo; anything else simply leaves
// DETECTED_MEMORY unset, as it did before.
func sysctlPhysicalMemory() (uint64, bool) { return 0, false }
