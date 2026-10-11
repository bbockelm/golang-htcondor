package htcondor

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
)

// countingListener accepts and drops connections, counting them, so a test
// can tell whether a call got as far as the schedd.
func countingListener(t *testing.T) (string, *atomic.Int64) {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	var accepted atomic.Int64
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			_ = conn.Close()
		}
	}()
	return ln.Addr().String(), &accepted
}

// A constraint that does not parse is refused by every job-query path --
// before any connection -- rather than sent as `true`. Through EditJobs a
// `true` would edit every job the schedd lets the caller edit.
func TestUnparseableQueryConstraintIsRefused(t *testing.T) {
	addr, accepted := countingListener(t)
	s := NewSchedd("test", addr)
	ctx := context.Background()
	const bad = "JobStatus = 1"

	n, err := s.EditJobs(ctx, bad, map[string]string{"Requirements": "false"}, nil)
	if err == nil || n != 0 {
		t.Errorf("EditJobs(%q) = (%d, %v), want an error and nothing edited", bad, n, err)
	}
	if _, _, err := s.QueryWithOptions(ctx, bad, nil); err == nil {
		t.Errorf("QueryWithOptions(%q) succeeded", bad)
	}
	if _, err := s.Query(ctx, bad, nil); err == nil {
		t.Errorf("Query(%q) succeeded", bad)
	}
	if _, err := s.QueryStreamWithOptions(ctx, bad, nil, nil); err == nil {
		t.Errorf("QueryStreamWithOptions(%q) succeeded", bad)
	}
	if got := accepted.Load(); got != 0 {
		t.Errorf("an unparseable constraint reached the schedd (%d connection(s))", got)
	}

	// A constraint that parses does go out, so the count above means
	// something.
	_, _, _ = s.QueryWithOptions(ctx, "JobStatus == 1", nil)
	if accepted.Load() == 0 {
		t.Error("a valid constraint never reached the schedd; the zero above proves nothing")
	}
}
