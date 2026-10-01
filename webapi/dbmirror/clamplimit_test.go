package dbmirror

import "testing"

func TestAskingForEverythingGetsTheBiggestPage(t *testing.T) {
	// The REST layer turns `limit=*` into -1, and gives a request that
	// named no limit the ordinary default long before this -- so a
	// non-positive limit here means "everything".
	//
	// It used to map to a floor of 200, which inverted the request: the
	// page that asked for a whole 60,000-job queue got the smallest page
	// this server serves, and walked it three hundred times.
	if got := ClampLimit(-1, true); got != MaxProjectedLimit {
		t.Errorf("unlimited projected read = %d, want the ceiling %d", got, MaxProjectedLimit)
	}
	if got := ClampLimit(0, false); got != MaxLimit {
		t.Errorf("unlimited whole-ad read = %d, want the ceiling %d", got, MaxLimit)
	}
}

func TestTheCeilingFollowsHowWideARowIs(t *testing.T) {
	// The budget is bytes, not rows. A whole ad is seventy-odd
	// attributes; a projected row is a few hundred bytes, so the same
	// response buys far more of them.
	if MaxProjectedLimit <= MaxLimit {
		t.Fatalf("projected ceiling %d is not above the whole-ad ceiling %d", MaxProjectedLimit, MaxLimit)
	}
	if got := ClampLimit(MaxProjectedLimit, false); got != MaxLimit {
		t.Errorf("whole-ad read clamped to %d, want %d", got, MaxLimit)
	}
	if got := ClampLimit(MaxProjectedLimit, true); got != MaxProjectedLimit {
		t.Errorf("projected read clamped to %d, want it honoured", got)
	}
}

func TestASmallerRequestIsHonoured(t *testing.T) {
	// The clamp is a ceiling, not a target: a caller that wants a page
	// of fifty gets fifty.
	if got := ClampLimit(50, true); got != 50 {
		t.Errorf("= %d, want the caller's own limit", got)
	}
}

func TestProjectedMeansTheCallerNamedAttributes(t *testing.T) {
	cases := []struct {
		name       string
		projection []string
		want       bool
	}{
		{"named attributes", []string{"ClusterId", "ProcId", "JobStatus"}, true},
		// "*" is how the REST layer spells "the whole ad", so it is the
		// expensive case wearing a projection's shape -- counting it as
		// projected would hand out the wide ceiling for the widest rows.
		{"star", []string{"*"}, false},
		{"star among others", []string{"ClusterId", "*"}, false},
		{"none at all", nil, false},
		{"empty", []string{}, false},
	}
	for _, c := range cases {
		if got := Projected(c.projection); got != c.want {
			t.Errorf("%s: Projected(%v) = %v, want %v", c.name, c.projection, got, c.want)
		}
	}
}
