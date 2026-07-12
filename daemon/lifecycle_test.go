package daemon

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bbockelm/golang-htcondor/config"
)

// newTestDaemon builds a Daemon with an empty config and a logger, suitable for
// exercising the lifecycle methods without touching condor_master.
func newTestDaemon(t *testing.T) *Daemon {
	t.Helper()
	// A temp CONDOR_CONFIG so Reconfigure()'s config.New() reload succeeds.
	t.Setenv("CONDOR_CONFIG", "/dev/null")
	d, err := New(Options{Subsys: "TESTDAEMON", Config: config.NewEmpty()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return d
}

func TestDaemonShutdownStopsServe(t *testing.T) {
	d := newTestDaemon(t)
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	served := make(chan error, 1)
	go func() {
		served <- d.Serve(context.Background(), ln, func(ctx context.Context, _ net.Listener) error {
			<-ctx.Done() // serve until shutdown cancels us
			return nil
		})
	}()

	// Shutdown should make Serve return nil (graceful), like SIGTERM.
	d.Shutdown()
	select {
	case err := <-served:
		if err != nil {
			t.Errorf("Serve returned %v after Shutdown, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after Shutdown")
	}

	// Shutdown is idempotent.
	d.Shutdown()
}

func TestMasterGoneDecision(t *testing.T) {
	const master = 4242
	alive := func() bool { return true }
	dead := func() bool { return false }

	cases := []struct {
		name         string
		originalPPID int
		currentPPID  int
		aliveFn      func() bool
		want         bool
	}{
		{"same ppid, master alive: keep running", master, master, alive, false},
		{"ppid changed (reparented): shut down", master, 1, alive, true},
		{"ppid changed to non-1 subreaper: shut down", master, 9999, alive, true},
		{"same ppid but master pid ESRCH: shut down", master, master, dead, true},
		{"same ppid, nil probe: keep running", master, master, nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := masterGone(tc.originalPPID, tc.currentPPID, tc.aliveFn); got != tc.want {
				t.Errorf("masterGone(%d,%d,...) = %v, want %v",
					tc.originalPPID, tc.currentPPID, got, tc.want)
			}
		})
	}
}

// TestMasterMonitorDisabledStandalone verifies the monitor never fires for a
// standalone daemon (UnderMaster false): Serve stays up until Shutdown, even
// though a standalone daemon's parent (the test process) is not the master.
func TestMasterMonitorDisabledStandalone(t *testing.T) {
	d := newTestDaemon(t)
	if d.UnderMaster() {
		t.Skip("test daemon unexpectedly under master")
	}
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	served := make(chan error, 1)
	go func() {
		served <- d.Serve(context.Background(), ln, func(ctx context.Context, _ net.Listener) error {
			<-ctx.Done()
			return nil
		})
	}()

	// Give any (erroneously enabled) monitor more than a poll interval to fire.
	select {
	case err := <-served:
		t.Fatalf("Serve returned early (%v); monitor fired while standalone", err)
	case <-time.After(masterPollInterval + 500*time.Millisecond):
	}

	d.Shutdown()
	select {
	case err := <-served:
		if err != nil {
			t.Errorf("Serve returned %v after Shutdown, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after Shutdown")
	}
}

func TestDaemonReconfigureRunsCallbacks(t *testing.T) {
	d := newTestDaemon(t)
	var calls int32
	d.OnReconfig(func(*config.Config) { atomic.AddInt32(&calls, 1) })

	d.Reconfigure()

	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Errorf("OnReconfig called %d times after Reconfigure, want 1", got)
	}
}
