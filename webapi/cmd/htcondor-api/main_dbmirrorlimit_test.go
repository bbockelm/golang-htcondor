package main

import (
	"testing"

	"github.com/bbockelm/golang-htcondor/config"
	"github.com/bbockelm/golang-htcondor/webapi/dbmirror"
)

// TestDBMirrorCeiling: an operator can raise how many records one
// mirror-served response carries, and a value that cannot mean a number
// of records leaves the default in place rather than capping reads at
// zero.
func TestDBMirrorCeiling(t *testing.T) {
	logger := pingIntervalLogger(t)
	const def = 2000

	for name, c := range map[string]struct {
		set  bool
		raw  string
		want int
	}{
		"unset keeps the default":    {set: false, want: def},
		"empty is treated as unset":  {set: true, raw: "  ", want: def},
		"a count is honored":         {set: true, raw: "50000", want: 50000},
		"zero keeps the default":     {set: true, raw: "0", want: def},
		"negative keeps the default": {set: true, raw: "-1", want: def},
		"garbage keeps the default":  {set: true, raw: "lots", want: def},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := config.NewEmpty()
			if c.set {
				cfg.Set("HTTP_API_DBMIRROR_MAX_LIMIT", c.raw)
			}
			if got := dbMirrorCeiling(cfg, logger, "HTTP_API_DBMIRROR_MAX_LIMIT", def); got != c.want {
				t.Errorf("dbMirrorCeiling(%q) = %d, want %d", c.raw, got, c.want)
			}
		})
	}
}

// TestLoadDBMirrorConfigAppliesCeilings: the knobs reach the package the
// read path clamps with, and ClampLimit hands out the raised ceiling.
// Without this the config is read and discarded, which looks identical
// from the configuration file.
func TestLoadDBMirrorConfigAppliesCeilings(t *testing.T) {
	maxLimit, maxProjected := dbmirror.MaxLimit, dbmirror.MaxProjectedLimit
	t.Cleanup(func() { dbmirror.MaxLimit, dbmirror.MaxProjectedLimit = maxLimit, maxProjected })

	cfg := config.NewEmpty()
	cfg.Set("HTTP_API_DBMIRROR_MAX_LIMIT", "25000")
	cfg.Set("HTTP_API_DBMIRROR_MAX_PROJECTED_LIMIT", "250000")
	loadDBMirrorConfig(cfg, pingIntervalLogger(t))

	if dbmirror.MaxLimit != 25000 || dbmirror.MaxProjectedLimit != 250000 {
		t.Fatalf("ceilings = %d / %d, want 25000 / 250000", dbmirror.MaxLimit, dbmirror.MaxProjectedLimit)
	}
	// -1 is what the REST layer passes for limit=*, so it is the request
	// that the ceiling alone answers.
	if got := dbmirror.ClampLimit(-1, false); got != 25000 {
		t.Errorf("whole-record read of everything = %d, want 25000", got)
	}
	if got := dbmirror.ClampLimit(-1, true); got != 250000 {
		t.Errorf("projected read of everything = %d, want 250000", got)
	}
}
