//go:build cgo

package droppriv

// selectBestStrategy chooses the best available lookup strategy.
// When CGO is enabled, Go's built-in user.Lookup() already uses
// getpwnam_r and the best C library functions, so we use it exclusively.
func selectBestStrategy() LookupStrategy {
	strategy, _ := tryGoFallback()
	return strategy
}
