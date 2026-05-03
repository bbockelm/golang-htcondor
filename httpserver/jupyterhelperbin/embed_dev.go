//go:build !embed_jupyter_helper

// Package jupyterhelperbin without the embed_jupyter_helper tag is a stub
// that reports "not embedded" — this is the default for `go build ./...`
// and for dev workflows that don't want a long Makefile dance every time
// the api binary is rebuilt.
//
// In this mode, the JupyterLab submit endpoint returns 503 with a clear
// "build with -tags embed_jupyter_helper" message.
package jupyterhelperbin

import "errors"

// ErrNotEmbedded is returned when the binary was built without the
// embed_jupyter_helper tag, or when the requested GOOS variant wasn't
// built into the dist/ directory.
var ErrNotEmbedded = errors.New("jupyterhelperbin: helper not embedded; rebuild with `make build` (which runs `build-jupyter-helper` first) or set -tags embed_jupyter_helper manually")

// BytesFor returns ErrNotEmbedded in dev builds for any GOOS.
func BytesFor(_ string) ([]byte, error) { return nil, ErrNotEmbedded }

// Bytes returns ErrNotEmbedded in dev builds.
func Bytes() ([]byte, error) { return nil, ErrNotEmbedded }

// IsEmbedded reports whether the helper binary is compiled into this binary.
func IsEmbedded() bool { return false }
