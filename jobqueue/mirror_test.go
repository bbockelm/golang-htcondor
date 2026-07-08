package jobqueue

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/PelicanPlatform/classad/collections"
)

func appendLog(t *testing.T, path, text string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatalf("open log: %v", err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.WriteString(text); err != nil {
		t.Fatalf("write log: %v", err)
	}
}

func nextEvent(t *testing.T, ch <-chan collections.WatchEvent) collections.WatchEvent {
	t.Helper()
	select {
	case ev, ok := <-ch:
		if !ok {
			t.Fatal("watch channel closed")
		}
		return ev
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for a watch event")
		return collections.WatchEvent{}
	}
}

func expectKind(t *testing.T, ch <-chan collections.WatchEvent, kind collections.WatchKind) collections.WatchEvent {
	t.Helper()
	ev := nextEvent(t, ch)
	if ev.Kind != kind {
		t.Fatalf("event kind = %d, want %d (key %s)", ev.Kind, kind, ev.Key)
	}
	return ev
}

// TestMirror verifies that job_queue.log entries are reflected into the watch
// collection, that only committed transactions are applied, and that a filtered
// watch (a single DAG) delivers only its jobs.
func TestMirror(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "job_queue.log")
	// A fresh log begins with a historical-sequence record.
	if err := os.WriteFile(logPath, []byte("107 1 CreationTimestamp 1700000000\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	m, err := New(logPath, Options{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := m.Poll(ctx); err != nil {
		t.Fatalf("initial poll: %v", err)
	}

	// Watch all jobs.
	seq, err := m.Collection().Watch(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	all := make(chan collections.WatchEvent, 64)
	go func() {
		for ev := range seq {
			all <- ev
		}
	}()
	expectKind(t, all, collections.WatchReset)
	expectKind(t, all, collections.WatchSynced)

	// Submit job 1.0 in DAG 42, as one committed transaction.
	appendLog(t, logPath, "105\n101 1.0 Job\n103 1.0 ClusterId 1\n103 1.0 ProcId 0\n103 1.0 DAGManJobId 42\n103 1.0 JobStatus 1\n106\n")
	if err := m.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	ev := expectKind(t, all, collections.WatchUpsert)
	if string(ev.Key) != "1.0" {
		t.Errorf("upsert key = %q, want 1.0", ev.Key)
	}
	if d, _ := ev.Ad.EvaluateAttrInt("DAGManJobId"); d != 42 {
		t.Errorf("DAGManJobId = %d, want 42", d)
	}

	// An open transaction must not be applied until it commits.
	appendLog(t, logPath, "105\n101 2.0 Job\n103 2.0 ClusterId 2\n103 2.0 DAGManJobId 99\n")
	if err := m.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case ev := <-all:
		t.Fatalf("got an event mid-transaction: kind=%d key=%s", ev.Kind, ev.Key)
	case <-time.After(200 * time.Millisecond):
	}
	// Commit it.
	appendLog(t, logPath, "106\n")
	if err := m.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	ev2 := expectKind(t, all, collections.WatchUpsert)
	if string(ev2.Key) != "2.0" {
		t.Errorf("committed upsert key = %q, want 2.0", ev2.Key)
	}
}

// TestMirrorFilteredWatch watches a single DAG through WatchFilter and confirms
// only that DAG's jobs are delivered.
func TestMirrorFilteredWatch(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "job_queue.log")
	if err := os.WriteFile(logPath, []byte("107 1 CreationTimestamp 1700000000\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Two jobs: one in DAG 42, one in DAG 7.
	appendLog(t, logPath, "105\n101 1.0 Job\n103 1.0 DAGManJobId 42\n106\n")
	appendLog(t, logPath, "105\n101 2.0 Job\n103 2.0 DAGManJobId 7\n106\n")

	m, err := New(logPath, Options{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := m.Poll(ctx); err != nil {
		t.Fatal(err)
	}

	match := func(ad *classad.ClassAd) bool {
		d, ok := ad.EvaluateAttrInt("DAGManJobId")
		return ok && d == 42
	}
	seq, err := m.Collection().Watch(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	ch := make(chan collections.WatchEvent, 64)
	go func() {
		for ev := range collections.WatchFilter(seq, match) {
			ch <- ev
		}
	}()

	// Catch-up: Reset, then the single matching job (1.0), then Synced.
	expectKind(t, ch, collections.WatchReset)
	up := expectKind(t, ch, collections.WatchUpsert)
	if string(up.Key) != "1.0" {
		t.Errorf("filtered upsert key = %q, want 1.0 (DAG 42)", up.Key)
	}
	expectKind(t, ch, collections.WatchSynced)
}

// TestMirrorChainedDAG verifies that a proc ad chains to its cluster ad: a
// DAGManJobId stored only on the cluster ad selects that cluster's procs through
// a filtered watch, and the delivered events carry the inherited attribute.
func TestMirrorChainedDAG(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "job_queue.log")
	log := "107 1 CreationTimestamp 1700000000\n" +
		"105\n101 1.-1 Job\n103 1.-1 DAGManJobId 42\n106\n" +
		"105\n101 1.0 Job\n103 1.0 ProcId 0\n106\n" +
		"105\n101 1.1 Job\n103 1.1 ProcId 1\n106\n" +
		"105\n101 2.-1 Job\n103 2.-1 DAGManJobId 7\n106\n" +
		"105\n101 2.0 Job\n103 2.0 ProcId 0\n106\n"
	if err := os.WriteFile(logPath, []byte(log), 0o644); err != nil {
		t.Fatal(err)
	}
	m, err := New(logPath, Options{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := m.Poll(ctx); err != nil {
		t.Fatal(err)
	}

	match := func(ad *classad.ClassAd) bool {
		d, ok := ad.EvaluateAttrInt("DAGManJobId")
		return ok && d == 42
	}
	seq, err := m.Collection().Watch(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	ch := make(chan collections.WatchEvent, 64)
	go func() {
		for ev := range collections.WatchFilter(seq, match) {
			ch <- ev
		}
	}()

	expectKind(t, ch, collections.WatchReset)
	got := map[string]int64{}
	for {
		ev := nextEvent(t, ch)
		if ev.Kind == collections.WatchSynced {
			break
		}
		if ev.Kind == collections.WatchUpsert {
			d, _ := ev.Ad.EvaluateAttrInt("DAGManJobId")
			got[string(ev.Key)] = d
		}
	}
	if len(got) != 2 || got["1.0"] != 42 || got["1.1"] != 42 {
		t.Errorf("chained filtered watch = %v, want procs 1.0 and 1.1 with DAGManJobId 42 (via cluster chain)", got)
	}
}
