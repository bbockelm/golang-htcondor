package main

import (
	"testing"

	"github.com/bbockelm/golang-htcondor/config"
	"github.com/bbockelm/golang-htcondor/logging"
)

// Standalone is the case that needs streaming: a server that is not on a
// pool host generally cannot be dialed back by an execute node, so the
// CCB default leaves condor_ssh_to_job waiting for a connection that
// cannot arrive. Under condor_master the reverse-connect default is
// usually right and cheaper, so it stays.
//
// CONDOR_INHERIT is the same signal daemon.New uses, read here because
// the server is built before daemon.New runs.
func TestLoadCCBStreamingDefaultsFromDeployment(t *testing.T) {
	logger := ccbTestLogger(t)

	cases := map[string]struct {
		underMaster bool
		want        bool
	}{
		"standalone streams":           {underMaster: false, want: true},
		"under condor_master reverses": {underMaster: true, want: false},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if c.underMaster {
				t.Setenv("CONDOR_INHERIT", "1234 <10.0.0.1:9618>")
			} else {
				t.Setenv("CONDOR_INHERIT", "")
			}
			if got := loadCCBStreaming(config.NewEmpty(), logger); got != c.want {
				t.Errorf("loadCCBStreaming = %v, want %v", got, c.want)
			}
		})
	}
}

// The guess is a guess: a standalone server on a reachable host may not
// want the broker in the path, and a master-started one behind NAT may
// need it. The knob has to win in both directions.
func TestLoadCCBStreamingOverrideWinsBothWays(t *testing.T) {
	logger := ccbTestLogger(t)

	cases := map[string]struct {
		underMaster bool
		raw         string
		want        bool
	}{
		"off despite standalone":   {underMaster: false, raw: "false", want: false},
		"on despite condor_master": {underMaster: true, raw: "true", want: true},
		"whitespace is trimmed":    {underMaster: true, raw: "  true  ", want: true},
		"empty falls back":         {underMaster: false, raw: "   ", want: true},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if c.underMaster {
				t.Setenv("CONDOR_INHERIT", "1234 <10.0.0.1:9618>")
			} else {
				t.Setenv("CONDOR_INHERIT", "")
			}
			cfg := config.NewEmpty()
			cfg.Set("HTTP_API_CCB_STREAMING", c.raw)
			if got := loadCCBStreaming(cfg, logger); got != c.want {
				t.Errorf("loadCCBStreaming = %v, want %v", got, c.want)
			}
		})
	}
}

func ccbTestLogger(t *testing.T) *logging.Logger {
	t.Helper()
	l, err := logging.New(&logging.Config{OutputPath: "stderr"})
	if err != nil {
		t.Fatalf("logger: %v", err)
	}
	return l
}
