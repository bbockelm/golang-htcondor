//go:build !unix

package daemon

import "github.com/bbockelm/golang-htcondor/logging"

// captureStdoutStderr is a no-op on non-unix platforms (no dup2). Go HTCondor daemons run
// under condor_master on unix; this keeps the package buildable elsewhere.
func captureStdoutStderr(*logging.Logger) {}
