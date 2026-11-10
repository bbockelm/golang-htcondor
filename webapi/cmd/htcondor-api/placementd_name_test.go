package main

import (
	"testing"

	"github.com/bbockelm/golang-htcondor/config"
)

// HTTP_API_PLACEMENTD_NAME is this server's own choice and wins; without
// it, PLACEMENTD_HOST is honored as HTCondor's tools on this host honor it.
// Neither set leaves discovery to find this access point's own.
func TestLoadPlacementdName(t *testing.T) {
	for name, c := range map[string]struct {
		vars map[string]string
		want string
	}{
		"neither":         {vars: nil, want: ""},
		"PLACEMENTD_HOST": {vars: map[string]string{"PLACEMENTD_HOST": "pd.example.org"}, want: "pd.example.org"},
		"both": {vars: map[string]string{
			"PLACEMENTD_HOST":          "pd.example.org",
			"HTTP_API_PLACEMENTD_NAME": " placement@central.example.org ",
		}, want: "placement@central.example.org"},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := config.NewEmpty()
			for k, v := range c.vars {
				cfg.Set(k, v)
			}
			if got := loadPlacementdName(cfg, pingIntervalLogger(t)); got != c.want {
				t.Errorf("loadPlacementdName = %q, want %q", got, c.want)
			}
		})
	}
}
