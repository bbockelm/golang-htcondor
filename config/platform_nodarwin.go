//go:build !darwin

package config

// darwinVersion has nothing to report off a Mac.
func darwinVersion() (major, minor int, ok bool) {
	return 0, 0, false
}
