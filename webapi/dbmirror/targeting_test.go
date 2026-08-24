package dbmirror

import (
	"strings"
	"testing"

	"github.com/PelicanPlatform/classad/classad"
)

func mirrorAd(name, addr string, caughtUp bool, lastSync int64) *classad.ClassAd {
	ad := classad.New()
	ad.InsertAttrString("Name", name)
	ad.InsertAttrString("MyAddress", addr)
	ad.InsertAttrBool("JobQueueCaughtUp", caughtUp)
	ad.InsertAttr("JobQueueLastSyncTime", lastSync)
	return ad
}

// TestPickMirrorPrefersTheFreshest covers the multi-mirror pool. Nothing
// in the ad says which schedd each htcondordb mirrors, so picking the
// first one back from the collector is arbitrary — and being arbitrary
// here means serving one access point's jobs from another's database.
func TestPickMirrorPrefersTheFreshest(t *testing.T) {
	behind := mirrorAd("db-behind", "<10.0.0.1:9619>", false, 500)
	current := mirrorAd("db-current", "<10.0.0.2:9619>", true, 100)
	newer := mirrorAd("db-newer", "<10.0.0.3:9619>", true, 400)

	// Caught-up beats not-caught-up regardless of the clock reading.
	if got := pickMirror([]*classad.ClassAd{behind, current}); got.Name != "db-current" {
		t.Errorf("picked %q, want the caught-up mirror", got.Name)
	}
	// Among caught-up mirrors, the more recent sync wins, in either
	// input order (the collector does not promise one).
	if got := pickMirror([]*classad.ClassAd{current, newer}); got.Name != "db-newer" {
		t.Errorf("picked %q, want the most recently synced", got.Name)
	}
	if got := pickMirror([]*classad.ClassAd{newer, current}); got.Name != "db-newer" {
		t.Errorf("order changed the winner: picked %q", got.Name)
	}
}

// TestPickMirrorSkipsAddresslessAds: an ad with no MyAddress cannot be
// dialed, so choosing it would turn a working mirror into no mirror.
func TestPickMirrorSkipsAddresslessAds(t *testing.T) {
	noAddr := mirrorAd("db-broken", "", true, 900)
	usable := mirrorAd("db-ok", "<10.0.0.9:9619>", true, 100)

	got := pickMirror([]*classad.ClassAd{noAddr, usable})
	if got == nil || got.Name != "db-ok" {
		t.Fatalf("picked %+v, want the ad with an address even though it is less fresh", got)
	}
	if pickMirror([]*classad.ClassAd{noAddr}) != nil {
		t.Error("an ad with no address must not be chosen")
	}
}

// TestClassadStringLitEscapes: the pinned name goes into a collector
// constraint. A quote in it must not end the literal early — that would
// silently change which ads match rather than fail.
func TestClassadStringLitEscapes(t *testing.T) {
	got := classadStringLit(`db" || true || "x`)
	if strings.Count(got, `"`)-strings.Count(got, `\"`) != 2 {
		t.Errorf("unbalanced quoting: %s", got)
	}
	if !strings.Contains(got, `\"`) {
		t.Errorf("embedded quote was not escaped: %s", got)
	}
	if got := classadStringLit("a\nb\tc\\d"); got != `"a\nb\tc\\d"` {
		t.Errorf("escaping = %s", got)
	}
}

// TestRequiredNeedsRoutingEnabled: "required" describes routing that is
// on. A daemon with no collector cannot route at all, and treating it as
// required would fail every read rather than use the schedd.
func TestRequiredNeedsRoutingEnabled(t *testing.T) {
	l := NewLocatorWithOptions(nil, nil, Options{Required: true})
	if l.Enabled() {
		t.Fatal("a locator with no collector should not report enabled")
	}
	if l.Required() {
		t.Error("required must be false when routing cannot run at all")
	}
	if h := l.Health(); h.Required || h.Enabled {
		t.Errorf("health should report neither enabled nor required: %+v", h)
	}
}

// TestHealthOfUndiscoveredMirror: before discovery succeeds there is no
// Info, and Health must say so rather than invent a fresh-looking zero.
func TestHealthOfUndiscoveredMirror(t *testing.T) {
	l := NewLocator(nil, nil)
	h := l.Health()
	if h.Info != nil {
		t.Errorf("Info should be nil before discovery, got %+v", h.Info)
	}
	if !h.LastSuccess.IsZero() {
		t.Error("LastSuccess should be zero before discovery ever succeeded")
	}
	// Nil receiver must not panic: /readyz and the metrics collector
	// both call this on whatever the Handler holds.
	var nilLoc *Locator
	if hh := nilLoc.Health(); hh.Enabled {
		t.Error("a nil locator should report disabled")
	}
}

// TestDecisionStatus pins the status codes required mode returns. A
// caller has to be able to tell "retry later, the mirror is behind"
// from "this query will never work here".
func TestDecisionStatus(t *testing.T) {
	cases := map[Reason]int{
		ReasonServed:           200,
		ReasonStale:            503,
		ReasonNotCaughtUp:      503,
		ReasonNoMirror:         503,
		ReasonDialFailed:       503,
		ReasonHistoryGap:       503,
		ReasonUnsupportedQuery: 400,
		ReasonPageToken:        400,
		ReasonNoOwnerScope:     400,
	}
	for reason, want := range cases {
		d := Decision{Reason: reason, Use: reason == ReasonServed}
		if got := d.Status(); got != want {
			t.Errorf("%s: status = %d, want %d", reason, got, want)
		}
	}
}
