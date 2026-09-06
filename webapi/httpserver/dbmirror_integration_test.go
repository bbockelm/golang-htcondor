//go:build integration

package httpserver

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/config"
	"github.com/bbockelm/golang-htcondor/webapi/dbmirror"
)

// Everything else about mirror routing is tested against a collector
// that does not exist, which exercises the decline paths and nothing
// else. No test has ever completed discover -> dial -> query against a
// real htcondordb, and the seam nothing crossed is where the bugs were:
// a "served" tally counted before anything was dialed, a dial failure
// with no error recorded anywhere, discovery guessing between mirrors,
// and a freshness gate reading an attribute that meant something else.
// Each was invisible to unit tests because each lives in the round trip.
//
// This runs the real thing. It needs an htcondordb binary, which CI
// builds from the version pinned in .github/tools (so Dependabot bumps
// it and the test starts exercising each new release); without one it
// skips, because a developer without htcondordb checked out should not
// be blocked by it.

// htcondordbBinary locates the daemon, or skips.
func htcondordbBinary(t *testing.T) string {
	t.Helper()
	if bin := os.Getenv("HTCONDORDB_BINARY"); bin != "" {
		if _, err := os.Stat(bin); err != nil {
			// Set but wrong is a mistake worth failing on: a CI job that
			// meant to run this must not silently skip it.
			t.Fatalf("HTCONDORDB_BINARY=%s is not usable: %v", bin, err)
		}
		return bin
	}
	bin, err := exec.LookPath("htcondordb")
	if err != nil {
		t.Skip("htcondordb not found (set HTCONDORDB_BINARY or put it on PATH); skipping the mirror integration test")
	}
	return bin
}

// startMirror runs an htcondordb advertising to the harness collector,
// and returns once it has published an address.
func startMirror(t *testing.T, h *htcondor.CondorTestHarness, bin, dir string) {
	t.Helper()

	addrFile := filepath.Join(dir, "addr")
	logDir := filepath.Join(dir, "log")
	for _, d := range []string{logDir, filepath.Join(dir, "db")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	// FS authentication throughout: both processes are this test user, so
	// there is no token to mint and nothing to distribute. What is being
	// tested is the mirror round trip, not the security handshake.
	cfg := fmt.Sprintf(`
CONDOR_HOST = 127.0.0.1
COLLECTOR_HOST = %s
UID_DOMAIN = %s
TRUST_DOMAIN = %s
SEC_DEFAULT_AUTHENTICATION = REQUIRED
SEC_DEFAULT_AUTHENTICATION_METHODS = FS
SEC_DEFAULT_INTEGRITY = REQUIRED
SEC_DEFAULT_ENCRYPTION = OPTIONAL
ALLOW_DAEMON = *
ALLOW_WRITE = *
ALLOW_READ = *
ALLOW_ADMINISTRATOR = *
LOG = %s
HTCONDORDB_DIR = %s
HTCONDORDB_ADDRESS_FILE = %s
HTCONDORDB_ADVERTISE = true
UPDATE_INTERVAL = 5
`, h.GetCollectorAddr(), h.GetTrustDomain(), h.GetTrustDomain(),
		logDir, filepath.Join(dir, "db"), addrFile)

	cfgPath := filepath.Join(dir, "condor_config")
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	stderr, err := os.Create(filepath.Join(dir, "stderr.log"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, bin)
	cmd.Env = append(os.Environ(), "CONDOR_CONFIG="+cfgPath)
	cmd.Stderr, cmd.Stdout = stderr, stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting htcondordb: %v", err)
	}
	t.Cleanup(func() {
		cancel()
		_ = cmd.Wait()
		_ = stderr.Close()
		// The daemon's own log is the only account of why a failure
		// happened on the far side of the connection.
		if t.Failed() {
			if b, rerr := os.ReadFile(filepath.Join(dir, "stderr.log")); rerr == nil && len(b) > 0 {
				t.Logf("=== htcondordb stderr ===\n%s", b)
			}
		}
	})

	waitFor(t, "htcondordb to publish its address", 30*time.Second, func() bool {
		b, rerr := os.ReadFile(addrFile)
		return rerr == nil && len(strings.TrimSpace(string(b))) > 0
	})
}

func waitFor(t *testing.T, what string, limit time.Duration, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		if ok() {
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("timed out after %s waiting for %s", limit, what)
}

// TestMirrorRoundTrip is the test the unit suite structurally cannot be:
// a real collector, a real database, and a real authenticated read.
func TestMirrorRoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test (forks a real htcondordb)")
	}
	// Look for the daemon before paying for a pool: a developer without
	// htcondordb should skip in milliseconds, not after a harness boot.
	bin := htcondordbBinary(t)
	// A collector is all the pool this needs: discovery is what the
	// mirror path turns on, and a schedd would only slow the test down.
	harness := htcondor.SetupCondorHarnessWithConfig(t, "DAEMON_LIST = MASTER, COLLECTOR\n")
	startMirror(t, harness, bin, t.TempDir())

	cfg := config.NewEmpty()
	cfg.Set("SEC_DEFAULT_AUTHENTICATION_METHODS", "FS")
	cfg.Set("SEC_CLIENT_AUTHENTICATION_METHODS", "FS")
	cfg.Set("UID_DOMAIN", harness.GetTrustDomain())
	cfg.Set("TRUST_DOMAIN", harness.GetTrustDomain())

	locator := dbmirror.NewLocator(htcondor.NewCollector(harness.GetCollectorAddr()), cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Discovery. The ad reaches the collector on the update interval, so
	// this is the slow step, not the connection.
	var info *dbmirror.Info
	waitFor(t, "the collector to carry the htcondordb ad", 45*time.Second, func() bool {
		var err error
		info, err = locator.Discover(ctx)
		return err == nil && info != nil
	})
	if info.Address == "" {
		t.Fatalf("discovered a mirror with no address: %+v", info)
	}
	t.Logf("discovered %q at %s", info.Name, info.Address)

	// Connect. This is the step that was failing in production with
	// nothing recorded anywhere but a metric label.
	dbc, closer, _, err := locator.Client(ctx)
	if err != nil {
		t.Fatalf("connecting to the discovered mirror: %v", err)
	}
	defer closer()

	// A fresh database has no jobs table -- schedd-sync creates it on its
	// first pass -- and this test deliberately runs no schedd, because
	// what is under test is the round trip rather than the sync. Create
	// it, which also exercises a mutating call over the same session.
	if err := dbc.CreateTable(ctx, "jobs"); err != nil && !strings.Contains(err.Error(), "exists") {
		t.Fatalf("creating the jobs table on the mirror: %v", err)
	}

	// And a real query, over the authenticated session.
	rows, err := dbc.QueryRawProject(ctx, "jobs", "false", []string{"ClusterId"}, 1)
	if err != nil {
		t.Fatalf("querying the mirror's jobs table: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("a constraint matching nothing returned %d rows", len(rows))
	}

	// The health view must agree with what just happened. It reported a
	// mirror as healthy off the ad alone before dial failures were
	// recorded, which is how one that never answered looked fine.
	health := mirrorHealth(locator, time.Now())
	if health == nil {
		t.Fatal("no health reported for a locator that just answered a query")
	}
	if health.DialError != "" {
		t.Errorf("a successful connection left a dial error behind: %q", health.DialError)
	}
	if !health.Discovered {
		t.Error("health says nothing was discovered, immediately after a successful read")
	}
	if health.Status == "down" {
		t.Errorf("status is %q after a successful round trip", health.Status)
	}
}

// TestMirrorProbeReportsEachStage drives the admin page's test button
// against a real database, so the stages it reports are the stages that
// actually happen rather than the ones I assumed.
func TestMirrorProbeReportsEachStage(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test (forks a real htcondordb)")
	}
	bin := htcondordbBinary(t)
	harness := htcondor.SetupCondorHarnessWithConfig(t, "DAEMON_LIST = MASTER, COLLECTOR\n")
	startMirror(t, harness, bin, t.TempDir())

	cfg := config.NewEmpty()
	cfg.Set("SEC_DEFAULT_AUTHENTICATION_METHODS", "FS")
	cfg.Set("SEC_CLIENT_AUTHENTICATION_METHODS", "FS")
	cfg.Set("UID_DOMAIN", harness.GetTrustDomain())
	cfg.Set("TRUST_DOMAIN", harness.GetTrustDomain())

	h := &Handler{
		dbMirror: dbmirror.NewLocator(htcondor.NewCollector(harness.GetCollectorAddr()), cfg),
		logger:   testLogger(t),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// The probe queries the jobs table, so it has to exist -- see
	// TestMirrorRoundTrip.
	waitFor(t, "the mirror to accept a connection", 45*time.Second, func() bool {
		dbc, closer, _, err := h.dbMirror.Client(ctx)
		if err != nil {
			return false
		}
		defer closer()
		cerr := dbc.CreateTable(ctx, "jobs")
		return cerr == nil || strings.Contains(cerr.Error(), "exists")
	})

	got := h.probeDBMirror(ctx)

	want := []string{"discover", "connect", "query"}
	if len(got.Stages) != len(want) {
		t.Fatalf("probe reported %d stages, want %v: %+v", len(got.Stages), want, got.Stages)
	}
	for i, name := range want {
		if got.Stages[i].Name != name {
			t.Errorf("stage %d is %q, want %q", i, got.Stages[i].Name, name)
		}
		if !got.Stages[i].OK {
			t.Errorf("stage %q failed against a working mirror: %s", name, got.Stages[i].Error)
		}
	}
}
