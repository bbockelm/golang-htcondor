package httpserver

import (
	"testing"
	"time"

	"github.com/bbockelm/golang-htcondor/webapi/issues"
)

func recs(kind string, n int, owner, message string) []issues.Record {
	out := make([]issues.Record, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, issues.Record{
			Kind: kind, Owner: owner, Message: message,
			Cluster: int64(i), At: int64(1000 + i),
		})
	}
	return out
}

func TestBuildIssuesResponseSeparatesTheSections(t *testing.T) {
	set := &issues.Set{ComputedAt: time.Unix(1700000000, 0), Source: "test"}
	set.Records = append(set.Records, recs(issues.KindHold, 5, "alice",
		"Error from slot1_1@a.b.example.edu: memory usage exceeded request_memory")...)
	set.Records = append(set.Records, recs(issues.KindHold, 3, "bob",
		"Error from slot1_2@c.d.example.edu: memory usage exceeded request_memory")...)
	set.Records = append(set.Records, recs(issues.KindRunFailure, 4, "carol",
		"Error from slot1_3@e.f.example.edu: Failed to receive GoAhead message from 10.0.0.1.")...)

	resp := buildIssuesResponse(set, 24*time.Hour, 0.5, true)
	if len(resp.Sections) != 2 {
		t.Fatalf("sections = %d, want 2", len(resp.Sections))
	}
	holds := resp.Sections[0]
	if holds.Kind != issues.KindHold {
		t.Fatalf("first section is %q, want holds first", holds.Kind)
	}
	// The section's own totals, not the sum of its rows: those two must
	// agree here, and the header must not change when the slider does.
	if holds.Total != 8 || holds.Users != 2 {
		t.Errorf("holds section: total=%d users=%d, want 8 and 2", holds.Total, holds.Users)
	}
	if runs := resp.Sections[1]; runs.Total != 4 || runs.Kind != issues.KindRunFailure {
		t.Errorf("run-failure section = %+v", runs)
	}
	if resp.WindowSeconds != 86400 {
		t.Errorf("window_seconds = %d", resp.WindowSeconds)
	}
}

func TestBuildIssuesResponseTotalsDoNotMoveWithGranularity(t *testing.T) {
	// The slider changes how the rows are drawn, not what happened. A
	// header whose numbers moved with it would make the page look like
	// it was measuring something different at each setting.
	set := &issues.Set{ComputedAt: time.Unix(1700000000, 0)}
	set.Records = append(set.Records, recs(issues.KindHold, 6, "alice",
		"Transfer output files failure at execution point slot1_1@a.b.example.edu using protocol osdf")...)
	set.Records = append(set.Records, recs(issues.KindHold, 6, "bob",
		"Transfer input files failure at execution point slot1_2@c.d.example.edu using protocol osdf")...)

	coarse := buildIssuesResponse(set, time.Hour, 0, true)
	fine := buildIssuesResponse(set, time.Hour, 1, true)
	if coarse.Sections[0].Total != fine.Sections[0].Total {
		t.Errorf("totals moved with granularity: %d vs %d",
			coarse.Sections[0].Total, fine.Sections[0].Total)
	}
	if len(coarse.Sections[0].Clusters) >= len(fine.Sections[0].Clusters) {
		t.Errorf("coarse produced %d rows and fine %d; coarse should produce fewer",
			len(coarse.Sections[0].Clusters), len(fine.Sections[0].Clusters))
	}
}

func TestBuildIssuesResponseOmitsEmptySections(t *testing.T) {
	// An access point with nothing failing to start should not render a
	// section headed "Jobs that could not keep running" above nothing:
	// an empty section reads as a failure to load.
	set := &issues.Set{ComputedAt: time.Unix(1700000000, 0)}
	set.Records = recs(issues.KindHold, 2, "alice", "some hold")
	resp := buildIssuesResponse(set, time.Hour, 0.5, false)
	if len(resp.Sections) != 1 || resp.Sections[0].Kind != issues.KindHold {
		t.Fatalf("sections = %+v, want only holds", resp.Sections)
	}
	// And never nil, so a client can iterate the field unconditionally.
	empty := buildIssuesResponse(&issues.Set{ComputedAt: time.Now()}, time.Hour, 0.5, false)
	if empty.Sections == nil {
		t.Error("sections is nil; JSON should carry an empty array")
	}
}
