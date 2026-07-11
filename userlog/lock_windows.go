//go:build windows

package userlog

import "os"

// lockFile is a no-op on Windows: the classic user-log writer relies on
// O_APPEND atomicity there, matching the C++ default of no locking.
func lockFile(f *os.File) func() { return func() {} }
