package daemon

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
)

// A daemon that also wants its own directly-dialable port asks
// BoundFallbackListener whether that address is already bound. Only the
// fallback binds it: a self-registered shared-port endpoint is a CEDAR
// socket like an inherited one, and leaves the address free.
//
// AdoptedInheritedListener used to be asked instead, which answered false
// for a self-registered endpoint -- so the htcondor-api server skipped its
// own HTTP port whenever USE_SHARED_PORT was on and no socket came down
// from condor_master, and came up reachable by nobody.
func TestBoundFallbackListener(t *testing.T) {
	t.Run("self-registered shared port leaves the address unbound", func(t *testing.T) {
		lock := shortTempDir(t)
		adFile := filepath.Join(lock, "shared_port_ad")
		if err := os.WriteFile(adFile, []byte("MyAddress = \"<127.0.0.1:9618?addrs=127.0.0.1-9618&noUDP>\"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		d := testDaemonWithConfig(t, "LOCK = "+lock+"\nUSE_SHARED_PORT = true\n")

		called := false
		ln, err := d.Listener(func() (net.Listener, error) {
			called = true
			return (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
		})
		if err != nil {
			t.Fatalf("Listener: %v", err)
		}
		defer func() { _ = ln.Close() }()

		if called {
			t.Error("fallback was called although shared port self-registration succeeded")
		}
		if d.SharedPortName() == "" {
			t.Error("expected a self-registered shared-port endpoint name")
		}
		if d.BoundFallbackListener() {
			t.Error("BoundFallbackListener = true; the fallback address was never bound")
		}
		if d.AdoptedInheritedListener() {
			t.Error("AdoptedInheritedListener = true; nothing was inherited")
		}
	})

	t.Run("standalone bind owns the address", func(t *testing.T) {
		d := testDaemonWithConfig(t, "USE_SHARED_PORT = false\n")

		ln, err := d.Listener(func() (net.Listener, error) {
			return (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
		})
		if err != nil {
			t.Fatalf("Listener: %v", err)
		}
		defer func() { _ = ln.Close() }()

		if !d.BoundFallbackListener() {
			t.Error("BoundFallbackListener = false after a standalone bind")
		}
		if d.SharedPortName() != "" {
			t.Errorf("SharedPortName = %q, want empty", d.SharedPortName())
		}
	})
}

func testDaemonWithConfig(t *testing.T, text string) *Daemon {
	t.Helper()
	t.Setenv("CONDOR_CONFIG", "/dev/null")
	d, err := New(Options{Subsys: "TESTDAEMON", Config: spConfig(t, text)})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return d
}
