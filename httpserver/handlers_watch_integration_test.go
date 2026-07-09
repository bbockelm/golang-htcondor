package httpserver

import (
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/collections"
	"github.com/PelicanPlatform/classad/collections/vm"

	"github.com/bbockelm/golang-htcondor/jobqueue"
)

// TestStreamCollectionEventsSSE drives the jobs watch SSE streaming end to end
// (minus auth): a job_queue.log job flows through the mirror and out as SSE
// frames, and a constraint filters to a single DAG. It exercises the same helper
// handleJobsWatch calls after authenticating.
func TestStreamCollectionEventsSSE(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "job_queue.log")
	log := "107 1 CreationTimestamp 1700000000\n" +
		"105\n101 1.0 Job\n103 1.0 DAGManJobId 42\n103 1.0 JobStatus 2\n106\n" +
		"105\n101 2.0 Job\n103 2.0 DAGManJobId 7\n106\n"
	if err := os.WriteFile(logPath, []byte(log), 0o600); err != nil {
		t.Fatal(err)
	}

	m, err := jobqueue.New(logPath, jobqueue.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}

	// stream runs the SSE helper with an optional constraint and a short deadline
	// so the streaming loop returns once catch-up has drained.
	stream := func(t *testing.T, constraint string) string {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 700*time.Millisecond)
		defer cancel()
		seq, err := m.Collection().Watch(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		if constraint != "" {
			q, err := vm.Parse(constraint)
			if err != nil {
				t.Fatal(err)
			}
			seq = collections.WatchFilter(seq, q.Matches)
		}
		req := httptest.NewRequestWithContext(ctx, "GET", "/api/v1/jobs/watch", nil)
		rec := httptest.NewRecorder()
		flusher, ok := sseSetup(rec)
		if !ok {
			t.Fatal("recorder is not a flusher")
		}
		streamCollectionEvents(ctx, rec, req, flusher, seq)
		return rec.Body.String()
	}

	body := stream(t, "")
	for _, want := range []string{"event: reset", "event: synced", "event: upsert", `"1.0"`, `"2.0"`, "DAGManJobId"} {
		if !strings.Contains(body, want) {
			t.Errorf("unfiltered stream missing %q:\n%s", want, body)
		}
	}

	fbody := stream(t, "DAGManJobId == 42")
	if !strings.Contains(fbody, `"1.0"`) {
		t.Errorf("filtered stream missing job 1.0 (DAG 42):\n%s", fbody)
	}
	if strings.Contains(fbody, `"2.0"`) {
		t.Errorf("filtered stream leaked job 2.0 (DAG 7):\n%s", fbody)
	}
}
