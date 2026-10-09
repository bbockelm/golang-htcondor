//go:build integration

package httpserver

import (
	"context"
	"os"
	"os/exec"
	"testing"

	"github.com/bbockelm/golang-htcondor/config"
)

// loadPoolConfig loads a test pool's HTCondor configuration straight from its
// file, leaving $CONDOR_CONFIG and the library's process-wide default alone.
// A test hands it to the server as Config.ClientConfig and to any client it
// builds itself with WithConfig, which is what lets tests that each run their
// own pool run in parallel.
func loadPoolConfig(t *testing.T, configFile string) *config.Config {
	t.Helper()
	cfg, err := config.NewWithOptions(config.ConfigOptions{ConfigFile: configFile})
	if err != nil {
		t.Fatalf("loading pool config %s: %v", configFile, err)
	}
	return cfg
}

// condorToolCommand runs an HTCondor command-line tool against the pool whose
// configuration is configFile, by naming it in the child's environment rather
// than this process's.
func condorToolCommand(ctx context.Context, configFile, name string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, name, args...) //nolint:gosec // G204: an HTCondor tool named by the test
	cmd.Env = append(os.Environ(), "CONDOR_CONFIG="+configFile)
	return cmd
}
