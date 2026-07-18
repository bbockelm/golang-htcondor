//go:build !embed_condor_docs

package condordocs

import "io/fs"

// docsFS returns nil when the docs are not embedded. Callers must check
// IsEmbedded first; the snippet/search APIs return a sentinel error in
// that case rather than reading from a nil filesystem.
func docsFS() (fs.FS, error) { return nil, nil }

// IsEmbedded reports whether the docs are compiled into this binary.
func IsEmbedded() bool { return false }
