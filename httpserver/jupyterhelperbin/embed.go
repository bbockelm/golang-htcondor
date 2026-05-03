//go:build embed_jupyter_helper

// Package jupyterhelperbin holds the embedded htcondor-jupyter-helper
// binaries that ship into JupyterLab jobs as transfer_input_files.
// Build with -tags embed_jupyter_helper to include them; the dist/
// directory must contain freshly cross-compiled helpers (see the
// Makefile's `build-jupyter-helper` and `build-jupyter-helper-darwin`
// targets).
//
// Two GOOSes are supported:
//
//   - linux  → dist/htcondor-jupyter-helper (always built)
//   - darwin → dist/htcondor-jupyter-helper-darwin (only built when the
//     host running `make build` is darwin; selected at submit time when
//     the API server is running on macOS and falls back to vanilla
//     universe + on-the-fly conda env, since macOS lacks Docker
//     universe support)
//
// The submit handler picks the right one for each job based on the
// universe it's about to use. We never write either to disk; the bytes
// go straight into an in-memory fs.FS that's spooled to the schedd via
// SpoolJobFilesFromFS.
package jupyterhelperbin

import (
	"embed"
	"errors"
	"fmt"
)

//go:embed all:dist
var content embed.FS

// ErrNotEmbedded mirrors the symbol exported by the !embed_jupyter_helper
// build of this package so callers can do a single errors.Is check
// without build tags.
var ErrNotEmbedded = errors.New("jupyterhelperbin: helper not embedded; rebuild with `make build` (which runs `build-jupyter-helper` first) or set -tags embed_jupyter_helper manually")

// BytesFor returns the helper binary for the given GOOS, ready to be
// dropped into an fs.FS and spooled to the schedd. Supported values:
// "linux", "darwin". Other values return ErrNotEmbedded.
//
// Returns ErrNotEmbedded specifically when the embed tag is set but the
// requested target wasn't built (e.g. asking for darwin on a Linux dev
// machine where only the linux helper is in dist/).
func BytesFor(goos string) ([]byte, error) {
	var path string
	switch goos {
	case "linux":
		path = "dist/htcondor-jupyter-helper"
	case "darwin":
		path = "dist/htcondor-jupyter-helper-darwin"
	default:
		return nil, fmt.Errorf("jupyterhelperbin: unsupported GOOS %q", goos)
	}
	b, err := content.ReadFile(path)
	if err != nil {
		// Distinguish "embedded but missing this target" from "not
		// embedded at all" for nicer error messages upstream.
		return nil, fmt.Errorf("%w: missing %s (was the right `make build-jupyter-helper*` target run?)", ErrNotEmbedded, path)
	}
	return b, nil
}

// Bytes returns the linux helper. Retained for callers that haven't been
// updated to BytesFor yet; equivalent to BytesFor("linux").
func Bytes() ([]byte, error) { return BytesFor("linux") }

// IsEmbedded reports whether the helper binaries are compiled into this
// binary at all. To know whether a *specific* GOOS is available, call
// BytesFor and check the error.
func IsEmbedded() bool { return true }
