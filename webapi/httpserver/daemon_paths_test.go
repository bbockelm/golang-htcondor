package httpserver

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/webapi/httpserver/appdb"
	"github.com/bbockelm/golang-htcondor/webapi/reservation"
	"github.com/bbockelm/golang-htcondor/webapi/runtimeest"
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
			l := &placementdLocator{scheddName: "some-schedd", query: collectorAdQuery(collector), logger: logger}
			_, _ = l.discover(context.Background())
		}},
		{"reservations: controller tick", func() {
			// A tick against a live collector makes three reads back
			// to back -- the census, what is already held, and
			// running-by-project -- which is the burst that showed up
			// unclassified. Here the first read fails and the tick
			// stops, which is enough: the classification is decided
			// before the dial. No application database, so the spec
			// list comes back empty and the tick goes straight to the
			// pool rather than stopping short of it.
			h, wait := reservationHandler(t, closed)
			h.collector = collector
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			h.startReservations(ctx)
			wait("reservation tick failed")
		}},
		{"reservations: stamping pass", func() {
			h, wait := reservationHandler(t, closed)
			h.runtimeEst = runtimeest.New(runtimeest.Config{})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			h.startReservationStamping(ctx)
			wait("reservation stamping failed")
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

// reservationHandler builds a Handler with the reservation subsystem on
// and returns a wait function that blocks until the given line reaches
// the log.
//
// The wait is what makes the assertion mean anything. Both Run loops act
// once before they wait on their ticker, and both report the failure the
// closed peer produces -- so the line proves the pass ran and reached the
// dial. Without it an absence of unclassified contexts would also be what
// a subsystem that never started looks like.
func reservationHandler(t *testing.T, addr string) (*Handler, func(string)) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "daemon-paths.log")
	// DefaultLevel has to be said out loud: logging.New leaves an unset
	// one at VerbosityError, which would drop the warning this waits for.
	logger, err := logging.New(&logging.Config{
		OutputPath: path, DefaultLevel: logging.VerbosityDebug, SkipGlobalInstall: true})
	if err != nil {
		t.Fatalf("building the capture logger: %v", err)
	}
	// A real store holding one standing reservation, because both loops
	// are gated on something being reserved and would otherwise go quiet
	// without reaching CEDAR at all -- passing the test by doing nothing.
	db, err := appdb.Open(filepath.Join(t.TempDir(), "app.db"))
	if err != nil {
		t.Fatalf("appdb.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := appdb.Migrate(context.Background(), db); err != nil {
		t.Fatalf("appdb.Migrate: %v", err)
	}
	spec, err := goodReservation().toSpec()
	if err != nil {
		t.Fatalf("building the reservation: %v", err)
	}
	if err := reservation.NewStore(db).Put(context.Background(), spec); err != nil {
		t.Fatalf("storing the reservation: %v", err)
	}
	h := &Handler{
		logger:              logger,
		db:                  db,
		schedd:              htcondor.NewSchedd("closed", addr),
		reservationsEnabled: true,
		// Only their emptiness is checked before the stamper starts;
		// the pass fails on the closed schedd long before it mints
		// anything with them.
		signingKeyPath: filepath.Join(t.TempDir(), "signing"),
		trustDomain:    "example.org",
	}
	wait := func(want string) {
		t.Helper()
		deadline := time.Now().Add(30 * time.Second)
		for {
			//nolint:gosec // G304: path is this test's own TempDir file
			if b, rerr := os.ReadFile(path); rerr == nil && strings.Contains(string(b), want) {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("%q never reached the log; the pass under test did not run", want)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	return h, wait
}
