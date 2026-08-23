package mcpserver

import (
	"strings"
	"testing"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/config"
	"github.com/bbockelm/golang-htcondor/webapi/dbmirror"
)

func TestParseAsOf(t *testing.T) {
	rfc, err := parseAsOf("2026-07-24T00:00:00Z")
	if err != nil || rfc.UTC().Format(time.RFC3339) != "2026-07-24T00:00:00Z" {
		t.Errorf("RFC3339 parse: got %v err=%v", rfc, err)
	}
	// Relative durations mean "ago" whether or not the sign is given.
	for _, s := range []string{"-1h", "1h"} {
		ago, err := parseAsOf(s)
		if err != nil {
			t.Fatalf("relative %q: %v", s, err)
		}
		if d := time.Since(ago); d < 59*time.Minute || d > 61*time.Minute {
			t.Errorf("relative %q resolved to %v ago, want ~1h", s, d)
		}
	}
	if _, err := parseAsOf(""); err == nil {
		t.Error("empty as_of should error")
	}
	if _, err := parseAsOf("not-a-time"); err == nil {
		t.Error("garbage as_of should error")
	}
}

func TestDBIntArg(t *testing.T) {
	if got := dbLimitArg(map[string]interface{}{}); got != 200 {
		t.Errorf("default: got %d, want 200", got)
	}
	if got := dbLimitArg(map[string]interface{}{"limit": float64(50)}); got != 50 {
		t.Errorf("explicit: got %d, want 50", got)
	}
	if got := dbLimitArg(map[string]interface{}{"limit": float64(99999)}); got != 2000 {
		t.Errorf("clamp: got %d, want 2000", got)
	}
	if got := dbLimitArg(map[string]interface{}{"limit": float64(-5)}); got != 200 {
		t.Errorf("negative -> default: got %d, want 200", got)
	}
}

func TestFreshnessNote(t *testing.T) {
	note := freshnessNote(&dbmirror.Info{Name: "db", SecondsSinceSync: 5, HistoryGap: true})
	if !strings.Contains(note, "last synced 5s ago") {
		t.Errorf("missing sync age: %q", note)
	}
	if !strings.Contains(note, "durability gap") {
		t.Errorf("missing gap warning: %q", note)
	}
	if freshnessNote(nil) != "" {
		t.Error("nil info should yield empty note")
	}
}

func TestHTCondorDBToolsReadOnly(t *testing.T) {
	for _, name := range []string{"query_history_db", "query_jobs_as_of", "aggregate_jobs"} {
		if !IsReadOnlyTool(name) {
			t.Errorf("%s should be classified read-only", name)
		}
	}
}

func TestHTCondorDBEnabled(t *testing.T) {
	coll := htcondor.NewCollector("collector.example") // no connection made here
	cfg := config.NewEmpty()
	cases := []struct {
		name string
		s    *Server
		want bool
	}{
		{"both set", &Server{dbMirror: dbmirror.NewLocator(coll, cfg)}, true},
		{"no collector", &Server{dbMirror: dbmirror.NewLocator(nil, cfg)}, false},
		{"no config", &Server{dbMirror: dbmirror.NewLocator(coll, nil)}, false},
		{"neither", &Server{dbMirror: dbmirror.NewLocator(nil, nil)}, false},
		{"no locator at all", &Server{}, false},
	}
	for _, c := range cases {
		if got := c.s.htcondordbEnabled(); got != c.want {
			t.Errorf("%s: enabled = %v, want %v", c.name, got, c.want)
		}
	}
}
