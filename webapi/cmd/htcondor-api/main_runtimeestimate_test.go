package main

import (
	"testing"
	"time"

	"github.com/bbockelm/golang-htcondor/config"
)

func TestLoadRuntimeEstimateConfig(t *testing.T) {
	logger := pingIntervalLogger(t)
	cases := map[string]struct {
		interval, backfill string
		wantI, wantB       time.Duration
	}{
		"unset uses the defaults":   {"", "", defaultRuntimeEstimateInterval, defaultRuntimeEstimateBackfill},
		"zero disables":             {"0", "", 0, defaultRuntimeEstimateBackfill},
		"explicit values are taken": {"90s", "48h", 90 * time.Second, 48 * time.Hour},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := config.NewEmpty()
			if c.interval != "" {
				cfg.Set("HTTP_API_RUNTIME_ESTIMATE_INTERVAL", c.interval)
			}
			if c.backfill != "" {
				cfg.Set("HTTP_API_RUNTIME_ESTIMATE_BACKFILL", c.backfill)
			}
			i, b := loadRuntimeEstimateConfig(cfg, logger)
			if i != c.wantI || b != c.wantB {
				t.Errorf("got %v, %v; want %v, %v", i, b, c.wantI, c.wantB)
			}
		})
	}
}
