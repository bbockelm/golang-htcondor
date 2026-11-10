package main

import (
	"testing"

	"github.com/bbockelm/golang-htcondor/config"
)

// A grace period cannot be turned off or made unbounded: zero, negative and
// unreadable fall back to the default, and anything past the ceiling is
// clamped to it.
func TestLoadJupyterGraceSecIsAlwaysBounded(t *testing.T) {
	params := []struct {
		name          string
		def, ceiling  int
		explicitValue string
		explicit      int
	}{
		{"HTTP_API_JUPYTER_RECONNECT_GRACE_SEC", 300, 3600, "120", 120},
		{"HTTP_API_JUPYTER_START_GRACE_SEC", 14400, 604800, "3600", 3600},
	}
	for _, p := range params {
		cases := map[string]struct {
			value string
			set   bool
			want  int
		}{
			"unset":      {want: p.def},
			"explicit":   {value: p.explicitValue, set: true, want: p.explicit},
			"zero":       {value: "0", set: true, want: p.def},
			"negative":   {value: "-5", set: true, want: p.def},
			"unreadable": {value: "4h", set: true, want: p.def},
			"too long":   {value: "999999999", set: true, want: p.ceiling},
		}
		for label, c := range cases {
			t.Run(p.name+"/"+label, func(t *testing.T) {
				cfg := config.NewEmpty()
				if c.set {
					cfg.Set(p.name, c.value)
				}
				if got := loadJupyterGraceSec(cfg, ccbTestLogger(t), p.name, p.def, p.ceiling); got != c.want {
					t.Errorf("loadJupyterGraceSec(%q) = %d, want %d", c.value, got, c.want)
				}
			})
		}
	}
}
