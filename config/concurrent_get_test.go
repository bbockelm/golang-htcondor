package config

import (
	"strings"
	"sync"
	"testing"
)

// TestConcurrentGetIsSafe reproduces a fatal error seen in production
// after a dependency upgrade:
//
//	fatal error: concurrent map writes
//	config.(*Config).expandMacrosWithFunctions
//	config.(*Config).Get
//	htcondor.GetSecurityConfig
//
// Get looks like a read and is used like one — GetSecurityConfig calls
// it per connection, from whatever goroutine is dialing — but macro
// expansion records the variables it is currently resolving in a map on
// the shared Config, to detect circular references. Two goroutines
// expanding at once write that map concurrently, which the runtime
// turns into an unrecoverable fatal error: not a panic, so no recover,
// no graceful shutdown, and the daemon is simply gone.
//
// Values must contain $(...) or expansion never touches the map.
func TestConcurrentGetIsSafe(t *testing.T) {
	c := NewEmpty()
	c.Set("BASE", "/var/lib/condor")
	c.Set("SPOOL", "$(BASE)/spool")
	c.Set("EXECUTE", "$(BASE)/execute")
	c.Set("LOG", "$(BASE)/log")
	c.Set("NESTED", "$(SPOOL)/$(EXECUTE)/$(LOG)")

	keys := []string{"SPOOL", "EXECUTE", "LOG", "NESTED"}

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for n := 0; n < 500; n++ {
				key := keys[(i+n)%len(keys)]
				got, ok := c.Get(key)
				if !ok {
					t.Errorf("%s missing", key)
					return
				}
				// Expansion must still be correct under concurrency:
				// the cycle-detection state is per-resolution, so one
				// goroutine's bookkeeping must not truncate another's.
				if strings.Contains(got, "$(") {
					t.Errorf("%s did not fully expand: %q", key, got)
					return
				}
			}
		}(i)
	}
	wg.Wait()
}
