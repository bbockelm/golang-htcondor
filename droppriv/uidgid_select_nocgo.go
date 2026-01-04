//go:build !cgo

package droppriv

// selectBestStrategy chooses the best available lookup strategy.
// Without CGO, try specialized strategies before falling back to /etc/passwd parsing.
func selectBestStrategy() LookupStrategy {
	strategies := []func() (LookupStrategy, error){
		trySystemdUserDB, // Try systemd-userdbd first
		tryNSSStrategy,   // Try NSS-based strategy (parses nsswitch.conf)
		tryGoFallback,    // Go's user.Lookup (parses /etc/passwd without CGO)
	}

	for _, tryStrategy := range strategies {
		if strategy, err := tryStrategy(); err == nil && strategy != nil {
			return strategy
		}
	}

	// Should never happen as fallback always works
	panic("no UID/GID lookup strategy available")
}
