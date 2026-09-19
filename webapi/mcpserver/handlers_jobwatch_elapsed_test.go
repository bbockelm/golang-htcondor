package mcpserver

import (
	"strings"
	"testing"

	"github.com/PelicanPlatform/classad/classad"
)

// structuredOf pulls the machine-readable half of a tool result.
func structuredOf(t *testing.T, res interface{}) map[string]interface{} {
	t.Helper()
	m, ok := res.(map[string]interface{})
	if !ok {
		t.Fatalf("result is not a map: %T", res)
	}
	sc, ok := m["structuredContent"].(map[string]interface{})
	if !ok {
		t.Fatalf("no structuredContent: %+v", m)
	}
	return sc
}

// An agent has no clock across a tool call. Without the elapsed time it
// cannot tell a watch that came back instantly from one that blocked for
// ten minutes, and those say very different things about the pool.
func TestWatchReportsHowLongItWaited(t *testing.T) {
	s := watchServer(t, &stubSource{history: []*classad.ClassAd{histAd(42, 0, 4, 0)}})

	res := mustWatch(t, s, map[string]interface{}{"constraint": "ClusterId == 42"})
	if got := text(t, res); !strings.Contains(got, "FIRED after") {
		t.Errorf("the text does not say how long the call waited:\n%s", got)
	}
	sc := structuredOf(t, res)
	if _, ok := sc["waited_seconds"]; !ok {
		t.Errorf("waited_seconds missing from the structured result: %+v", sc)
	}
	if _, ok := sc["watch_age_seconds"]; !ok {
		t.Errorf("watch_age_seconds missing from the structured result: %+v", sc)
	}

	// And on the reporting side, for a watch answered in an earlier call.
	report := text(t, mustCheck(t, s, map[string]interface{}{"include_delivered": true}))
	if !strings.Contains(report, "after waiting") {
		t.Errorf("check_watches does not say how long the question took:\n%s", report)
	}
}

// A watch still waiting reports its age too -- that is the number that
// says whether to keep waiting or go and look at the pool.
func TestWaitingWatchReportsItsAge(t *testing.T) {
	s := watchServer(t, &stubSource{queue: []*classad.ClassAd{histAd(42, 0, 1, 0)}})
	mustWatch(t, s, map[string]interface{}{"constraint": "ClusterId == 42", "event": "held"})

	sc := structuredOf(t, mustCheck(t, s, map[string]interface{}{}))
	watches, ok := sc["watches"].([]map[string]interface{})
	if !ok || len(watches) != 1 {
		t.Fatalf("expected one watch in the structured result: %+v", sc)
	}
	if _, ok := watches[0]["waited_seconds"]; !ok {
		t.Errorf("a waiting watch does not report its age: %+v", watches[0])
	}
}

// The reported bug, end to end at the tool boundary: a job that ran and
// finished between two sweeps must answer a "running" watch, not leave the
// caller blocked on a question that already has its answer.
func TestRunningWatchAnsweredByAJobThatAlreadyFinished(t *testing.T) {
	done := histAd(42, 0, 4, 0)
	done.InsertAttr("JobStartDate", int64(1750000000))
	s := watchServer(t, &stubSource{history: []*classad.ClassAd{done}})

	got := text(t, mustWatch(t, s, map[string]interface{}{"constraint": "ClusterId == 42", "event": "running"}))
	if !strings.Contains(got, "FIRED") {
		t.Errorf("a running watch over a job that already ran must fire:\n%s", got)
	}
	if !strings.Contains(got, "started running") {
		t.Errorf("the answer should say the job ran:\n%s", got)
	}
}

// And its opposite: a job removed before it ever started must not be
// reported as having run. The caller is still released -- silence is what
// it cannot act on -- but with the answer that the state never happened.
func TestRunningWatchSaysSoWhenTheJobNeverRan(t *testing.T) {
	gone := histAd(42, 0, 3, 0)
	gone.InsertAttr("NumJobStarts", int64(0))
	s := watchServer(t, &stubSource{history: []*classad.ClassAd{gone}})

	res := mustWatch(t, s, map[string]interface{}{"constraint": "ClusterId == 42", "event": "running"})
	got := text(t, res)
	if strings.Contains(got, "started running") {
		t.Errorf("a job that never ran was reported as having run:\n%s", got)
	}
	if !strings.Contains(got, "never happened") {
		t.Errorf("the caller was not told the state can no longer occur:\n%s", got)
	}
	if u, _ := structuredOf(t, res)["unsatisfiable"].(bool); !u {
		t.Error("unsatisfiable not set in the structured result")
	}
}
