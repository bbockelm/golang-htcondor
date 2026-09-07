package httpserver

import (
	"reflect"
	"testing"

	"github.com/PelicanPlatform/classad/classad"
)

func mustAd(t *testing.T, text string) *classad.ClassAd {
	t.Helper()
	ad, err := classad.Parse(text)
	if err != nil {
		t.Fatalf("parsing %q: %v", text, err)
	}
	return ad
}

// The projection has to speak the same JSON the job GET does. Emitting
// ClassAd expression text instead gives a client "2" where it had 2 and
// a quoted string where it had a bare one, so merging an update into the
// job already in hand corrupts it.
func TestProjectAttrsEmitsJSONValues(t *testing.T) {
	ad := mustAd(t, `[ClusterId = 7; JobStatus = 2; RemoteHost = "slot1_1@localhost"; ExitBySignal = false]`)
	got := projectAttrs(ad, []string{"JobStatus", "RemoteHost", "ExitBySignal", "Absent"})

	want := map[string]any{
		"JobStatus":    float64(2),
		"RemoteHost":   "slot1_1@localhost",
		"ExitBySignal": false,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("projectAttrs = %#v, want %#v", got, want)
	}
	if _, present := got["Absent"]; present {
		t.Error("an attribute the ad does not carry should be omitted, not recorded empty")
	}
}

func TestProjectAttrsIsCaseInsensitive(t *testing.T) {
	// ClassAd attribute names are case-insensitive, and the ad carries
	// whatever case it was written with.
	ad := mustAd(t, `[jobstatus = 5]`)
	got := projectAttrs(ad, []string{"JobStatus"})
	if got["JobStatus"] != float64(5) {
		t.Errorf("case-insensitive lookup failed: %#v", got)
	}
}

func TestDiffAttrsReportsOnlyChanges(t *testing.T) {
	prev := map[string]any{"JobStatus": float64(1), "HoldReason": "spooling"}
	cur := map[string]any{"JobStatus": float64(2), "RemoteHost": "slot1@h"}

	got := diffAttrs(prev, cur)
	want := map[string]any{
		"JobStatus":  float64(2), // changed
		"RemoteHost": "slot1@h",  // appeared
		"HoldReason": nil,        // went away
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("diffAttrs = %#v, want %#v", got, want)
	}
}

func TestDiffAttrsIsQuietWhenNothingChanged(t *testing.T) {
	// Most writes to a job ad touch nothing a page asked about. Emitting
	// on those would put the endpoint back to the traffic of a poll.
	same := map[string]any{"JobStatus": float64(2), "RemoteHost": "slot1@h"}
	other := map[string]any{"JobStatus": float64(2), "RemoteHost": "slot1@h"}
	if got := diffAttrs(same, other); len(got) != 0 {
		t.Errorf("expected no changes, got %#v", got)
	}
}
