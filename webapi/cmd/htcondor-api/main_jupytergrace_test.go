package main

import (
	"testing"

	"github.com/bbockelm/golang-htcondor/config"
)

// A grace period cannot be turned off or made unbounded: zero, negative and
// unreadable fall back to the default, and anything past the ceiling is
// clamped to it.
func TestLoadJupyterGraceSecIsAlwaysBounded(t *testing.T) {
	const name, def, ceiling = "HTTP_API_JUPYTER_RECONNECT_GRACE_SEC", 300, 3600
	cases := map[string]struct {
		value string
		set   bool
		want  int
	}{
		"unset":      {want: def},
		"explicit":   {value: "120", set: true, want: 120},
		"zero":       {value: "0", set: true, want: def},
		"negative":   {value: "-5", set: true, want: def},
		"unreadable": {value: "4h", set: true, want: def},
		"too long":   {value: "999999999", set: true, want: ceiling},
	}
	for label, c := range cases {
		t.Run(label, func(t *testing.T) {
			cfg := config.NewEmpty()
			if c.set {
				cfg.Set(name, c.value)
			}
			if got := loadJupyterGraceSec(cfg, ccbTestLogger(t), name, def, ceiling); got != c.want {
				t.Errorf("loadJupyterGraceSec(%q) = %d, want %d", c.value, got, c.want)
			}
		})
	}
}
