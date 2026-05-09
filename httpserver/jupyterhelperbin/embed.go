//go:build embed_jupyter_helper

// Package jupyterhelperbin holds the embedded htcondor-jupyter-helper
// binaries that ship into JupyterLab jobs as transfer_input_files.
// Build with -tags embed_jupyter_helper to include them; the dist/
// directory must contain freshly cross-compiled helpers (see the
// Makefile's `build-jupyter-helper` target — it cross-compiles for
// every (GOOS, GOARCH) tuple in JUPYTER_HELPER_TARGETS, by default
// linux/amd64, linux/arm64, and darwin/arm64).
//
// Layout in dist/ is:
//
//	dist/htcondor-jupyter-helper-<goos>-<goarch>
//
// e.g. dist/htcondor-jupyter-helper-linux-amd64. The submit handler
// picks the right one per job based on the inferred execute-node
// platform (see jupyterUniverseForGOOS / runtimeGOARCH in
// handlers_jupyter.go). We never write either to disk on the API
// server side; the bytes go straight into an in-memory fs.FS that's
// spooled to the schedd via SpoolJobFilesFromFS.
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

// BytesFor returns the helper binary for the given (GOOS, GOARCH),
// ready to be dropped into an fs.FS and spooled to the schedd. Default
// supported tuples are linux/amd64, linux/arm64, and darwin/arm64;
// edit JUPYTER_HELPER_TARGETS in the Makefile to extend.
//
// Returns ErrNotEmbedded specifically when the embed tag is set but
// the requested target wasn't built (e.g. asking for darwin/amd64 in
// a build that only staged the three default targets).
func BytesFor(goos, goarch string) ([]byte, error) {
	if goos == "" || goarch == "" {
		return nil, fmt.Errorf("jupyterhelperbin: BytesFor requires both GOOS and GOARCH (got %q, %q)", goos, goarch)
	}
	path := fmt.Sprintf("dist/htcondor-jupyter-helper-%s-%s", goos, goarch)
	b, err := content.ReadFile(path)
	if err != nil {
		// Distinguish "embedded but missing this target" from "not
		// embedded at all" for nicer error messages upstream. The
		// upstream submit handler renders this with the operator
		// hint to extend JUPYTER_HELPER_TARGETS in the Makefile.
		return nil, fmt.Errorf("%w: missing %s (extend JUPYTER_HELPER_TARGETS in the Makefile and rebuild)", ErrNotEmbedded, path)
	}
	return b, nil
}

// IsEmbedded reports whether the helper binaries are compiled into this
// binary at all. To know whether a *specific* (GOOS, GOARCH) is
// available, call BytesFor and check the error.
func IsEmbedded() bool { return true }
