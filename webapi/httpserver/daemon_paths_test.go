package httpserver

import (
	"context"
	"sync"
	"testing"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
)

// reportUnmarked switches the process to UnmarkedWarn for one test and
// collects every context that reaches the daemon fallback without saying
// whose work it is. TestMain's policy is restored afterwards. The
// policy is process-wide, so tests using this must not call t.Parallel.
func reportUnmarked(t *testing.T) func() []string {
	t.Helper()
	var mu sync.Mutex
	var peers []string
	htcondor.SetUnmarkedOriginReporter(func(_ int, _ string, peer string) {
		mu.Lock()
		peers = append(peers, peer)
		mu.Unlock()
	})
	htcondor.SetUnmarkedOriginPolicy(htcondor.UnmarkedWarn)
	t.Cleanup(func() {
		htcondor.SetUnmarkedOriginPolicy(testOriginPolicy)
		htcondor.SetUnmarkedOriginReporter(nil)
	})
	return func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), peers...)
	}
}

// This daemon's own background work authenticates as the daemon by
// declaration, not by falling through: each path below reaches CEDAR on a
// context marked as daemon work, so none is reported as unclassified. The
// peers are closed ports; what matters is the credential decision, which is
// made before the dial.
func TestDaemonPathsAreMarked(t *testing.T) {
	const closed = "<127.0.0.1:1>"
	logger := newTestLogger(t)
	collector := htcondor.NewCollector(closed)

	for _, tc := range []struct {
		name string
		run  func()
	}{
		{"periodic ping", func() {
			h := &Handler{logger: logger, schedd: htcondor.NewSchedd("closed", closed)}
			h.performPeriodicPing()
		}},
		{"schedd discovery", func() {
			_, _ = discoverSchedd(collector, "some-schedd", "", 100*time.Millisecond, logger)
		}},
		{"credd discovery", func() {
			_, _ = discoverCredd(context.Background(), creddLookup{scheddName: "some-schedd", scheddAddr: closed, collector: collector}, logger)
		}},
		{"placementd discovery", func() {
			_, _ = discoverPlacementd(context.Background(), nil, collector, logger)
		}},
		{"queue superuser refresh", func() {
			p := newSuperuserPolicy(scheddSuperUserSource{get: func() *htcondor.Schedd { return htcondor.NewSchedd("closed", closed) }},
				"example.org", "", time.Hour, logger)
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan struct{})
			go func() { p.Run(ctx); close(done) }()
			// Run refreshes once before it waits.
			for {
				if _, _, err := p.Status(); err != nil {
					break
				}
				time.Sleep(5 * time.Millisecond)
			}
			cancel()
			<-done
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			unmarked := reportUnmarked(t)
			tc.run()
			if got := unmarked(); len(got) != 0 {
				t.Errorf("reached CEDAR on an unclassified context, for %v", got)
			}
		})
	}
}
