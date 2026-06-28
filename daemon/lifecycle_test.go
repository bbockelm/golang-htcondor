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

func TestDaemonReconfigureRunsCallbacks(t *testing.T) {
	d := newTestDaemon(t)
	var calls int32
	d.OnReconfig(func(*config.Config) { atomic.AddInt32(&calls, 1) })

	d.Reconfigure()

	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Errorf("OnReconfig called %d times after Reconfigure, want 1", got)
	}
}
