package main

import (
	"testing"
	"time"

	"github.com/bbockelm/golang-htcondor/config"
	"github.com/bbockelm/golang-htcondor/logging"
)

func pingIntervalLogger(t *testing.T) *logging.Logger {
	t.Helper()
	l, err := logging.New(&logging.Config{OutputPath: "stderr"})
	if err != nil {
		t.Fatalf("logger: %v", err)
	}
	return l
}

// TestLoadPingIntervalDisableAndDefault covers the two values that
// matter: unset must keep the daemon pinging as it always has, and an
// explicit 0 must turn it off. Before this knob existed there was no way
// to express the second — the library coerced its own documented "off"
// value back to the default, and nothing read a setting for it.
func TestLoadPingIntervalDisableAndDefault(t *testing.T) {
	logger := pingIntervalLogger(t)

	cases := map[string]struct {
		set  bool
		raw  string
		want time.Duration
	}{
		"unset keeps the daemon's default": {set: false, want: defaultPingInterval},
		"empty is treated as unset":        {set: true, raw: "   ", want: defaultPingInterval},
		"zero disables":                    {set: true, raw: "0", want: 0},
		"explicit cadence is honored":      {set: true, raw: "30s", want: 30 * time.Second},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := config.NewEmpty()
			if c.set {
				cfg.Set("HTTP_API_PING_INTERVAL", c.raw)
			}
			if got := loadPingInterval(cfg, logger); got != c.want {
				t.Errorf("loadPingInterval = %v, want %v", got, c.want)
			}
		})
	}
}
