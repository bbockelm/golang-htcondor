package multiap

import (
	"context"
	"sort"
	"strings"
	"testing"
)

// FindOwn finds the caller's matching jobs on every AP, including a
// degraded one even when unscoped reads exclude degraded APs, and never
// another user's or a non-member's.
func TestFindOwnScopesToTheCallerAndKeepsDegradedAPs(t *testing.T) {
	hub := hubDB(t)
	hub.PutSource("ap1", StateFresh, 1)
	hub.PutSource("ap2", StateStale, 600)
	session := `JobBatchName = "htcondor-api-session-work"`
	hub.PutJob("ap1", "alice@d", 7, 0, session)
	hub.PutJob("ap2", "alice@d", 7, 0, session)
	hub.PutJob("ap2", "alice@d", 8, 0, `JobBatchName = "other"`)
	hub.PutJob("ap1", "bob@d", 9, 0, session)
	hub.PutJob("ap3", "alice@d", 10, 0, session) // not a member

	s := newService(t, hub, newFakeRegistry("ap1", "ap2"))
	s.Stale = StaleExclude
	rows, src, err := s.FindOwn(context.Background(), "alice@d", `JobBatchName == "htcondor-api-session-work"`, []string{"JobBatchName"}, 0)
	if err != nil {
		t.Fatalf("FindOwn: %v", err)
	}
	var got []string
	for _, r := range rows {
		got = append(got, s.Codec.Format(r.ID))
		if name, _ := r.Ad.EvaluateAttrString("JobBatchName"); name != "htcondor-api-session-work" {
			t.Errorf("row %v lacks the projected attribute", r.ID)
		}
	}
	sort.Strings(got)
	if strings.Join(got, " ") != "7.0@ap1 7.0@ap2" {
		t.Errorf("FindOwn = %v, want 7.0@ap1 and 7.0@ap2 only", got)
	}
	if src.APs != 2 || len(src.Degraded) != 1 {
		t.Errorf("sources = %+v, want 2 APs with ap2 degraded", src)
	}
	if _, _, err := s.FindOwn(context.Background(), "", "true", nil, 0); err == nil {
		t.Error("FindOwn with no user answered")
	}
}
