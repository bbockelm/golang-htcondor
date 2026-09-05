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

// TestPickMirrorIdentifiesTheScheddByHost covers the multi-mirror pool.
// Picking the wrong htcondordb does not serve stale data, it serves
// another access point's jobs — so the choice turns on the one thing in
// the ad that actually identifies a mirror's schedd: the host, since
// syncing a schedd means tailing its job_queue.log off local disk.
func TestPickMirrorIdentifiesTheScheddByHost(t *testing.T) {
	ours := mirrorAd("db-ours", "<10.0.0.2:9619?sock=x>", true, 100)
	theirs := mirrorAd("db-theirs", "<10.0.0.3:9619>", true, 400)

	// The freshest ad is the stranger's; the host is what decides.
	got, err := pickMirror([]*classad.ClassAd{theirs, ours}, "10.0.0.2")
	if err != nil {
		t.Fatalf("expected the host to settle it: %v", err)
	}
	if got.Name != "db-ours" {
		t.Errorf("picked %q, want the mirror on this schedd's host", got.Name)
	}

	// A single advertiser is unambiguous and is taken whatever its host —
	// a pool with one htcondordb needs no configuration.
	if got, err = pickMirror([]*classad.ClassAd{theirs}, "10.0.0.2"); err != nil || got.Name != "db-theirs" {
		t.Errorf("a lone advertiser must be used: %+v %v", got, err)
	}
}

// TestPickMirrorRefusesToGuess is the safety property. The old rule took
// the freshest job queue, which is a guess, and it went wrong in a
// specific direction: ranking "caught up" above "recently synced" meant a
// mirror whose syncer had stopped while caught up outranked a live one
// that was momentarily behind — so a busy queue on THIS access point
// handed the read to a stranger's database.
func TestPickMirrorRefusesToGuess(t *testing.T) {
	a := mirrorAd("db-a", "<10.0.0.3:9619>", true, 400)
	b := mirrorAd("db-b", "<10.0.0.4:9619>", false, 900)

	got, err := pickMirror([]*classad.ClassAd{a, b}, "10.0.0.2")
	if err == nil {
		t.Fatalf("picked %q when nothing identified it; a wrong pick serves another AP's jobs", got.Name)
	}
	if !strings.Contains(err.Error(), "HTTP_API_DBMIRROR_NAME") {
		t.Errorf("the error must say how to resolve it: %v", err)
	}

	// Two on our own host is equally ambiguous.
	c := mirrorAd("db-c", "<10.0.0.2:9619>", true, 400)
	d := mirrorAd("db-d", "<10.0.0.2:9620>", true, 500)
	if got, err = pickMirror([]*classad.ClassAd{c, d}, "10.0.0.2"); err == nil {
		t.Errorf("two mirrors on one host is still a guess, picked %q", got.Name)
	}

	// With no schedd address configured there is nothing to match on.
	if _, err = pickMirror([]*classad.ClassAd{a, b}, ""); err == nil {
		t.Error("an unknown schedd host cannot identify a mirror")
	}
}

// TestPickMirrorSkipsAddresslessAds: an ad with no MyAddress cannot be
// dialed, so choosing it would turn a working mirror into no mirror.
func TestPickMirrorSkipsAddresslessAds(t *testing.T) {
	noAddr := mirrorAd("db-broken", "", true, 900)
	usable := mirrorAd("db-ok", "<10.0.0.9:9619>", true, 100)

	got, err := pickMirror([]*classad.ClassAd{noAddr, usable}, "10.0.0.2")
	if err != nil || got.Name != "db-ok" {
		t.Fatalf("picked %+v (%v), want the only dialable ad", got, err)
	}
	if _, err = pickMirror([]*classad.ClassAd{noAddr}, "10.0.0.2"); err == nil {
		t.Error("an ad with no address must not be chosen")
	}
}

// TestHostOfSinful: the host has to survive the decorations HTCondor
// hangs off an address, or every comparison fails and routing silently
// stops.
func TestHostOfSinful(t *testing.T) {
	cases := map[string]string{
		"<10.0.0.1:9619?addrs=10.0.0.1-9619&alias=ap40&noUDP&sock=db>": "10.0.0.1",
		"<ap40.example.org:9619>":                                      "ap40.example.org",
		"10.0.0.1:9619":                                                "10.0.0.1",
		"":                                                             "",
	}
	for addr, want := range cases {
		if got := hostOfSinful(addr); got != want {
			t.Errorf("hostOfSinful(%q) = %q, want %q", addr, got, want)
		}
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
