package httpserver

import "testing"

// Ranking failures by wasted time rather than by count is the whole
// point of the panel, so it is the thing to pin.
func TestTopExitCodesRanksByWastedTime(t *testing.T) {
	got := topExitCodes([]ExitCodeCount{
		{Code: 1, Count: 5000, Seconds: 5000},   // a broken submission: fails instantly
		{Code: 127, Count: 10, Seconds: 400000}, // ten jobs that each ran half a day
	}, 5)

	if len(got) != 2 {
		t.Fatalf("got %d rows, want 2: %+v", len(got), got)
	}
	// Ranking by count would put the broken submission first, which is
	// both obvious and cheap. The expensive failure is the rare one.
	if got[0].Code != 127 {
		t.Errorf("ranked exit %d first; the costly failure is exit 127 (%+v)", got[0].Code, got)
	}
}

func TestTopExitCodesMergesAndTrims(t *testing.T) {
	got := topExitCodes([]ExitCodeCount{
		{Signal: true, Code: 0, Count: 3, Seconds: 30},
		{Signal: true, Code: 9, Count: 2, Seconds: 20},
		{Code: 1, Count: 1, Seconds: 10},
		{Code: 2, Count: 1, Seconds: 9},
		{Code: 3, Count: 1, Seconds: 8},
		{Code: 4, Count: 1, Seconds: 7},
		{Code: 5, Count: 1, Seconds: 6},
	}, 3)

	if len(got) != 3 {
		t.Fatalf("got %d rows, want the limit of 3: %+v", len(got), got)
	}
	// Killed is killed: the exit code recorded alongside a signal is
	// meaningless, so those rows are one row.
	if !got[0].Signal || got[0].Count != 5 || got[0].Seconds != 50 {
		t.Errorf("signalled jobs did not merge into one row: %+v", got[0])
	}
}

func TestTopExitCodesOfNothing(t *testing.T) {
	if got := topExitCodes(nil, 5); got != nil {
		t.Errorf("no failures should produce no rows, got %+v", got)
	}
}

// Exit 0 and no exit code at all are different answers, and telling them
// apart is what separates "it worked" from "it never finished".
func TestParseAggIntDistinguishesZeroFromAbsent(t *testing.T) {
	if v, ok := parseAggInt("0"); !ok || v != 0 {
		t.Errorf(`parseAggInt("0") = %d, %v; want 0, true`, v, ok)
	}
	for _, absent := range []string{"", "undefined", "error"} {
		if _, ok := parseAggInt(absent); ok {
			t.Errorf("parseAggInt(%q) claimed a value; a missing exit code is not exit 0", absent)
		}
	}
}

// SUM comes back as a ClassAd number, which is a float as soon as any
// input was one. Parsing it as an integer would silently zero the whole
// column.
func TestParseAggFloatAcceptsBothNumberShapes(t *testing.T) {
	for in, want := range map[string]float64{
		"120":     120,
		"120.0":   120,
		"120.75":  120.75,
		"":        0,
		"garbage": 0,
	} {
		if got := parseAggFloat(in); got != want {
			t.Errorf("parseAggFloat(%q) = %v, want %v", in, got, want)
		}
	}
}
