package httpserver

import (
	"context"
	"strings"
	"testing"

	"github.com/PelicanPlatform/classad/classad"

	"time"

	"github.com/bbockelm/golang-htcondor/webapi/jobwatch"
)

// TestWatchSourceMarksATruncatedQueue. The evaluator treats a tracked
// job's absence from a COMPLETE queue as evidence that it finished, so a
// read that silently dropped the tail would report a running cluster as
// done. Truncation has to be detected, not assumed away.
func TestWatchSourceMarksATruncatedQueue(t *testing.T) {
	ads := make([]*classad.ClassAd, 0, 5)
	for i := 0; i < 5; i++ {
		ads = append(ads, classad.New())
	}

	full := truncate(ads, 5)
	if full.Truncated || len(full.Ads) != 5 {
		t.Errorf("an exactly-full page is not truncated: %+v", full)
	}
	// One past the limit is how "there were more" is detected.
	over := truncate(ads, 4)
	if !over.Truncated {
		t.Error("a read that returned more than the limit must be marked truncated")
	}
	if len(over.Ads) != 4 {
		t.Errorf("the extra probe row must not be handed to the evaluator: %d ads", len(over.Ads))
	}
	if short := truncate(ads[:2], 4); short.Truncated {
		t.Errorf("a short read is complete: %+v", short)
	}
}

// TestWatchSourceHistoryNeedsTheMirror: condor_history scans the
// schedd's on-disk history file, and running that from a loop every
// thirty seconds would spend more of the access point than the polling
// this feature replaces. Better to lose the terminal outcomes for a pass
// than to fall back to it.
func TestWatchSourceHistoryNeedsTheMirror(t *testing.T) {
	h := &Handler{dbMirror: nil}
	_, err := watchSource{h: h}.History(context.Background(), "alice", time.Time{}, 100)
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
