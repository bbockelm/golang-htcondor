package jobwatch

import (
	"context"
	"strings"
	"testing"
)

// TestTrackedSetIsRangeEncoded. Stored one entry per job, a 100,000-job
// cluster's tracked set is about 3.3 MB of JSON rewritten every pass for
// as long as the work runs. HTCondor numbers procs consecutively, so the
// set is nearly always a few contiguous runs.
func TestTrackedSetIsRangeEncoded(t *testing.T) {
	ids := make([]JobID, 0, 100000)
	for i := int64(0); i < 100000; i++ {
		ids = append(ids, JobID{Cluster: 417, Proc: i})
	}
	blob, err := encodeTracked(ids)
	if err != nil {
		t.Fatal(err)
	}
	if len(blob) > 100 {
		t.Errorf("100k contiguous jobs encoded to %d bytes; a run should collapse to one range", len(blob))
	}

	back, err := decodeTracked(blob)
	if err != nil {
		t.Fatal(err)
	}
	if len(back) != len(ids) {
		t.Fatalf("round trip lost jobs: %d -> %d", len(ids), len(back))
	}
	for i := range back {
		if back[i] != ids[i] {
			t.Fatalf("round trip changed job %d: %+v != %+v", i, back[i], ids[i])
		}
	}
}

// TestTrackedEncodingHandlesGapsAndClusters: procs are not always
// contiguous (a partial removal leaves holes) and a watch can span
// clusters. Coalescing must not invent jobs that were never tracked --
// a job wrongly in the set is one whose disappearance will be read as
// having finished.
func TestTrackedEncodingHandlesGapsAndClusters(t *testing.T) {
	ids := []JobID{{417, 0}, {417, 1}, {417, 5}, {418, 0}, {417, 2}}
	blob, err := encodeTracked(ids)
	if err != nil {
		t.Fatal(err)
	}
	back, err := decodeTracked(blob)
	if err != nil {
		t.Fatal(err)
	}
	want := map[JobID]bool{{417, 0}: true, {417, 1}: true, {417, 2}: true, {417, 5}: true, {418, 0}: true}
	if len(back) != len(want) {
		t.Fatalf("decoded %d jobs, want %d: %+v", len(back), len(want), back)
	}
	for _, id := range back {
		if !want[id] {
			t.Errorf("coalescing invented job %+v; its disappearance would read as a finish", id)
		}
	}
	if strings.Count(blob, "{") != 3 {
		t.Errorf("expected three ranges (417:0-2, 417:5, 418:0), got %s", blob)
	}
}

// TestTrackedDecodesTheOldEncoding: a watch registered before ranges
// existed must keep its memory across the upgrade. Losing it means
// forgetting the jobs whose disappearance is the evidence a terminal
// event depends on.
func TestTrackedDecodesTheOldEncoding(t *testing.T) {
	back, err := decodeTracked(`[{"cluster_id":417,"proc_id":0},{"cluster_id":417,"proc_id":1}]`)
	if err != nil {
		t.Fatalf("the previous encoding must still decode: %v", err)
	}
	if len(back) != 2 || back[0] != (JobID{417, 0}) || back[1] != (JobID{417, 1}) {
		t.Errorf("old encoding decoded wrong: %+v", back)
	}
	if empty, err := decodeTracked("[]"); err != nil || len(empty) != 0 {
		t.Errorf("empty set: %+v %v", empty, err)
	}
}

// TestUnchangedProgressIsNotWritten. In steady state the tracked set is
// identical pass after pass, and rewriting it every thirty seconds is a
// write for nothing. The passes worth recording are the ones where a job
// appeared or finished.
func TestUnchangedProgressIsNotWritten(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	w := register(t, s, "alice", EventDone, ModeAll)

	tracked := []JobID{{42, 0}, {42, 1}}
	if err := s.SaveProgress(ctx, w, Outcome{Tracked: tracked}); err != nil {
		t.Fatal(err)
	}
	first := w.trackedBlob
	if first == "" {
		t.Fatal("the first save should have recorded the set")
	}

	// Same set again: nothing to say.
	before := writeCount(t, s)
	if err := s.SaveProgress(ctx, w, Outcome{Tracked: tracked}); err != nil {
		t.Fatal(err)
	}
	if after := writeCount(t, s); after != before {
		t.Errorf("an unchanged tracked set was rewritten (%d -> %d changes)", before, after)
	}

	// A job appears: that is worth recording.
	if err := s.SaveProgress(ctx, w, Outcome{Tracked: append(tracked, JobID{42, 2})}); err != nil {
		t.Fatal(err)
	}
	if w.trackedBlob == first {
		t.Error("a changed tracked set was not written")
	}
}

// writeCount reads SQLite's total change counter, which only advances on
// a statement that actually modified a row.
func writeCount(t *testing.T, s *Store) int {
	t.Helper()
	var n int
	if err := s.db.QueryRowContext(context.Background(), `SELECT total_changes()`).Scan(&n); err != nil {
		t.Fatalf("total_changes: %v", err)
	}
	return n
}
