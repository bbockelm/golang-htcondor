package httpserver

import (
	"context"
	"strings"
	"testing"

	"github.com/PelicanPlatform/classad/classad"

	"time"

	"github.com/bbockelm/golang-htcondor/webapi/jobwatch"
)

// TestWatchSourceHistoryNeedsAnOutcomeSource: the evaluator treats a
// tracked job's absence from a COMPLETE queue as evidence it finished,
// so the read has to know when it was cut short -- a silently truncated
// page would report a running cluster as done. Queue detects that by
// fetching one row past the limit and never yielding the probe.

// TestWatchSourceHistoryNeedsTheMirror: condor_history scans the
// schedd's on-disk history file, and running that from a loop every
// thirty seconds would spend more of the access point than the polling
// this feature replaces. Better to lose the terminal outcomes for a pass
// than to fall back to it.
func TestWatchSourceHistoryNeedsTheMirror(t *testing.T) {
	h := &Handler{dbMirror: nil}
	err := watchSource{h: h}.History(context.Background(), "alice", jobwatch.BaseAttrs, time.Time{}, 100,
		func(*classad.ClassAd) {})
	if err == nil {
		t.Fatal("history without a mirror must error rather than fall back to the schedd")
	}
	if !strings.Contains(err.Error(), "mirror") {
		t.Errorf("the error should say what is missing: %v", err)
	}
}

// TestWatchSourceScopesByOwner: the evaluator runs in the background
// with no caller credential, so the daemon reads as itself. The owner
// term in the constraint is the only thing confining a watch's snapshot
// to the person who registered it.
func TestWatchSourceScopesByOwner(t *testing.T) {
	// classadStringLit is what keeps a hostile owner string from
	// escaping the comparison; the owner comes from an authenticated
	// identity, but quoting it is free and the alternative is a bypass.
	got := classadStringLit(`alice" || true || "`)
	if strings.Count(got, `"`)-strings.Count(got, `\"`) != 2 {
		t.Errorf("owner literal is not safely quoted: %s", got)
	}
}

// TestWatchSourceSatisfiesTheInterface keeps the adapter honest if the
// evaluator's needs change.
func TestWatchSourceSatisfiesTheInterface(_ *testing.T) {
	var _ jobwatch.Source = watchSource{}
}
