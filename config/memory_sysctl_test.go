package config

import (
	"runtime"
	"testing"
)

// The value has to be right, not merely non-zero: this feeds DETECTED_MEMORY,
// which sizes things in a pool.
func TestSysctlPhysicalMemoryMatchesTheMachine(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "freebsd" {
		t.Skipf("sysctl memory detection does not apply on %s", runtime.GOOS)
	}
	got, ok := sysctlPhysicalMemory()
	if !ok {
		t.Fatal("sysctlPhysicalMemory failed on a platform that has it")
	}
	if got == 0 {
		t.Fatal("reported zero bytes of RAM")
	}
	// A machine with under 1 GiB or over 64 TiB is not one of ours; either
	// bound means the units are wrong, which is the failure this would
	// otherwise hide behind a plausible-looking number.
	const gib = uint64(1) << 30
	if got < gib || got > 65536*gib {
		t.Errorf("reported %d bytes of RAM, which is not a credible amount", got)
	}

	mib := detectMemorySysctl()
	if mib < 0 || uint64(mib) != got/(1024*1024) {
		t.Errorf("detectMemorySysctl = %d MiB, want %d", mib, got/(1024*1024))
	}
}

// Detection must never be slow, because it runs from initBuiltins on every
// config.New. The fork it replaced hung for eleven minutes under load.
func BenchmarkDetectMemorySysctl(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = detectMemorySysctl()
	}
}
