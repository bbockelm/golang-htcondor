//go:build !embed_frontend

// Package webui provides the embedded Next.js static export. Without the
// embed_frontend build tag, no frontend is included and the Go server only
// handles API routes (dev mode uses a separate `next dev` process on :3000).
package webui

import "io/fs"

// DistFS returns nil when the frontend is not embedded.
func DistFS() (fs.FS, error) { return nil, nil }

// IsEmbedded reports whether the frontend is compiled into this binary.
func IsEmbedded() bool { return false }
