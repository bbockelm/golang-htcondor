package interactive

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"

	htcondor "github.com/bbockelm/golang-htcondor"
)

// Sessions in front of several access points: the access point is
// chosen once, at Create, and every later call goes to the one the
// session's record names -- never to the caller's current assignment.

const (
	testAP1 = "ap1.example.org"
	testAP2 = "ap2.example.org"
)

type apKey struct{}

// fakeAPs is two (or more) fake schedds behind an assignment the test
// can change, and a catalog standing in for the federation hub.
type fakeAPs struct {
	mu       sync.Mutex
	schedds  map[string]*fakeSchedd
	assigned string
	assigns  int
	routes   []string
	writes   []string
	// unreachable makes Route fail for an AP, as for one that left the
	// collector.
	unreachable map[string]bool
	// catalog, when set, replaces the catalog's answer (a lagging hub).
	catalog func() []LocatedAd
	// locateErr fails Locate, as for a hub that does not answer.
	locateErr error
}

func newFakeAPs(names ...string) *fakeAPs {
	f := &fakeAPs{schedds: map[string]*fakeSchedd{}, unreachable: map[string]bool{}}
	for i, n := range names {
		s := newFakeSchedd()
		s.stampOwner = alice.Owner
		// Distinct cluster ranges, so a job id names one AP's job in
		// the assertions -- except where a test wants the same number
		// on both.
		s.nextCluster = 100 * (i + 1)
		f.schedds[n] = s
	}
	f.assigned = names[0]
	return f
}

func (f *fakeAPs) assign(ap string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.assigned = ap
}

func (f *fakeAPs) Assign(ctx context.Context, _ Caller, explicit string) (string, context.Context, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.assigns++
	ap := f.assigned
	if explicit != "" {
		ap = explicit
	}
	return ap, context.WithValue(ctx, apKey{}, ap), nil
}

func (f *fakeAPs) Route(ctx context.Context, _ Caller, ap string) (context.Context, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.routes = append(f.routes, ap)
	if f.unreachable[ap] {
		return nil, fmt.Errorf("access point %s is not advertised in the collector right now", ap)
	}
	if _, ok := f.schedds[ap]; !ok {
		return nil, fmt.Errorf("%q is not an access point this server serves", ap)
	}
	return context.WithValue(ctx, apKey{}, ap), nil
}

func (f *fakeAPs) Locate(_ context.Context, caller Caller, _ string, _ []string) ([]LocatedAd, error) {
	f.mu.Lock()
	catalog, err := f.catalog, f.locateErr
	f.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if catalog != nil {
		return catalog(), nil
	}
	var out []LocatedAd
	for ap, s := range f.schedds {
		ads, _, _ := s.QueryWithOptions(context.Background(), "", &htcondor.QueryOptions{Owner: caller.Owner})
		for _, ad := range ads {
			out = append(out, LocatedAd{AP: ap, Ad: ad})
		}
	}
	return out, nil
}

func (f *fakeAPs) JobID(ap string, cluster, proc int) string {
	return fmt.Sprintf("%d.%d@%s", cluster, proc, ap)
}

func (f *fakeAPs) Wrote(ap string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.writes = append(f.writes, ap)
}

// scheddFor is Options.ScheddFor: the AP the context was routed to, and
// nothing without a route.
func (f *fakeAPs) scheddFor(ctx context.Context) ScheddClient {
	ap, _ := ctx.Value(apKey{}).(string)
	f.mu.Lock()
	defer f.mu.Unlock()
	if s, ok := f.schedds[ap]; ok {
		return s
	}
	return nil
}

func (f *fakeAPs) assignCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.assigns
}

// multiManager builds a Manager in multi-AP mode over aps. The
// single-schedd accessor counts its calls, which must stay zero.
func multiManager(t *testing.T, aps *fakeAPs, opts Options) (*Manager, *[]string, *int) {
	t.Helper()
	var mu sync.Mutex
	dialed := &[]string{}
	singleCalls := new(int)
	opts.APs = aps
	opts.ScheddFor = aps.scheddFor
	opts.Schedd = func() ScheddClient {
		mu.Lock()
		defer mu.Unlock()
		*singleCalls++
		return nil
	}
	shell := &fakeShell{}
	opts.Dial = func(ctx context.Context, cluster, proc int) (Shell, error) {
		ap, _ := ctx.Value(apKey{}).(string)
		mu.Lock()
		*dialed = append(*dialed, fmt.Sprintf("%d.%d@%s", cluster, proc, ap))
		mu.Unlock()
		return shell, nil
	}
	mgr, _ := testManager(t, nil, opts)
	t.Cleanup(func() {
		mu.Lock()
		defer mu.Unlock()
		if *singleCalls != 0 {
			t.Errorf("the single-schedd accessor was called %d times in multi-AP mode", *singleCalls)
		}
	})
	return mgr, dialed, singleCalls
}

func (f *fakeAPs) running(ap string) {
	s := f.schedds[ap]
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, j := range s.jobs {
		j.status = jobStatusRunning
	}
}

func TestMultiAPCreateLandsOnTheAssignedAPOnly(t *testing.T) {
	aps := newFakeAPs(testAP1, testAP2)
	aps.assign(testAP2)
	mgr, _, _ := multiManager(t, aps, Options{})

	info, err := mgr.Create(context.Background(), alice, CreateSpec{Name: "work"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if got := len(aps.schedds[testAP2].submittedFiles()); got != 1 {
		t.Errorf("%s got %d submissions, want 1", testAP2, got)
	}
	if got := len(aps.schedds[testAP1].submittedFiles()); got != 0 {
		t.Errorf("%s got %d submissions, want none", testAP1, got)
	}
	if info.Schedd != testAP2 || info.JobID != "200.0@"+testAP2 {
		t.Errorf("Create answered schedd %q job %q, want %s and 200.0@%s", info.Schedd, info.JobID, testAP2, testAP2)
	}
	if aps.assignCount() != 1 {
		t.Errorf("assignment asked %d times for one Create, want 1", aps.assignCount())
	}
	if len(aps.writes) == 0 || aps.writes[0] != testAP2 {
		t.Errorf("writes noted = %v, want %s", aps.writes, testAP2)
	}
}

// An existing session keeps its AP when the caller's assignment
// changes: exec dials it there, stop removes it there, and neither asks
// the assignment again -- in the process that created it and in a fresh
// one that finds it through the catalog.
func TestMultiAPSessionKeepsItsAPAfterReassignment(t *testing.T) {
	for _, restart := range []bool{false, true} {
		t.Run(fmt.Sprintf("restart=%v", restart), func(t *testing.T) {
			aps := newFakeAPs(testAP1, testAP2)
			aps.assign(testAP2)
			mgr, dialed, _ := multiManager(t, aps, Options{})
			if _, err := mgr.Create(context.Background(), alice, CreateSpec{Name: "work"}); err != nil {
				t.Fatalf("Create: %v", err)
			}
			aps.running(testAP2)
			aps.assign(testAP1)
			if restart {
				mgr.Close()
				mgr, dialed, _ = multiManager(t, aps, Options{})
			}
			assignsBefore := aps.assignCount()

			res, err := mgr.Exec(context.Background(), alice, "work", ExecRequest{Command: "hostname"})
			if err != nil {
				t.Fatalf("Exec: %v", err)
			}
			if want := []string{"200.0@" + testAP2}; strings.Join(*dialed, ",") != strings.Join(want, ",") {
				t.Errorf("Exec dialed %v, want %v", *dialed, want)
			}
			if res.JobID != "200.0@"+testAP2 {
				t.Errorf("Exec answered job %q, want 200.0@%s", res.JobID, testAP2)
			}
			if _, err := mgr.Stop(context.Background(), alice, "work"); err != nil {
				t.Fatalf("Stop: %v", err)
			}
			if got := aps.schedds[testAP2].removedJobs(); len(got) != 1 || !strings.Contains(got[0], "ClusterId == 200") {
				t.Errorf("removals on %s = %v, want the session's job", testAP2, got)
			}
			if got := aps.schedds[testAP1].removedJobs(); len(got) != 0 {
				t.Errorf("removals on %s = %v, want none", testAP1, got)
			}
			if got := len(aps.schedds[testAP1].submittedFiles()); got != 0 {
				t.Errorf("%s got %d submissions, want none", testAP1, got)
			}
			if n := aps.assignCount() - assignsBefore; n != 0 {
				t.Errorf("exec and stop asked the assignment %d times, want 0", n)
			}
		})
	}
}

// Lease expiry runs in the background with no request, and still goes
// to the session's own AP.
func TestMultiAPLeaseExpiryRemovesOnTheSessionsAP(t *testing.T) {
	aps := newFakeAPs(testAP1, testAP2)
	aps.assign(testAP2)
	mgr, _, _ := multiManager(t, aps, Options{
		HeartbeatInterval: 10 * time.Millisecond,
		DefaultLease:      60 * time.Millisecond,
	})
	if _, err := mgr.Create(context.Background(), alice, CreateSpec{Name: "work"}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	aps.running(testAP2)
	if _, err := mgr.Exec(context.Background(), alice, "work", ExecRequest{Command: "true"}); err != nil {
		t.Fatalf("Exec: %v", err)
	}
	aps.assign(testAP1)
	waitFor(t, "the expired session to be removed", 3*time.Second, func() bool {
		return len(aps.schedds[testAP2].removedJobs()) > 0
	})
	if got := aps.schedds[testAP1].removedJobs(); len(got) != 0 {
		t.Errorf("lease expiry removed on %s: %v", testAP1, got)
	}
}

// A name is unique per owner across every AP: with the assignment moved
// to ap1, creating a name the caller already has on ap2 is refused and
// nothing reaches ap1 -- whether the session is in this process's record
// or only in the catalog.
func TestMultiAPSessionNameIsUniqueAcrossAPs(t *testing.T) {
	for _, restart := range []bool{false, true} {
		t.Run(fmt.Sprintf("restart=%v", restart), func(t *testing.T) {
			aps := newFakeAPs(testAP1, testAP2)
			aps.assign(testAP2)
			mgr, _, _ := multiManager(t, aps, Options{})
			if _, err := mgr.Create(context.Background(), alice, CreateSpec{Name: "work"}); err != nil {
				t.Fatalf("Create: %v", err)
			}
			aps.assign(testAP1)
			if restart {
				mgr.Close()
				mgr, _, _ = multiManager(t, aps, Options{})
			}
			_, err := mgr.Create(context.Background(), alice, CreateSpec{Name: "work"})
			var exists *SessionExistsError
			if !errors.As(err, &exists) {
				t.Fatalf("second Create = %v, want SessionExistsError", err)
			}
			if exists.Info.Schedd != testAP2 || exists.Info.JobID != "200.0@"+testAP2 {
				t.Errorf("the existing session is reported on %q as %q, want %s", exists.Info.Schedd, exists.Info.JobID, testAP2)
			}
			if got := len(aps.schedds[testAP1].submittedFiles()); got != 0 {
				t.Errorf("%s got %d submissions, want none", testAP1, got)
			}
			// A different name goes to the new assignment.
			info, err := mgr.Create(context.Background(), alice, CreateSpec{Name: "other"})
			if err != nil {
				t.Fatalf("Create other: %v", err)
			}
			if info.Schedd != testAP1 {
				t.Errorf("a new session went to %q, want the new assignment %s", info.Schedd, testAP1)
			}
		})
	}
}

// The per-owner limit counts sessions on every AP.
func TestMultiAPPerOwnerLimitCountsEveryAP(t *testing.T) {
	aps := newFakeAPs(testAP1, testAP2)
	mgr, _, _ := multiManager(t, aps, Options{MaxPerOwner: 2})
	aps.assign(testAP1)
	if _, err := mgr.Create(context.Background(), alice, CreateSpec{Name: "a"}); err != nil {
		t.Fatalf("Create a: %v", err)
	}
	aps.assign(testAP2)
	if _, err := mgr.Create(context.Background(), alice, CreateSpec{Name: "b"}); err != nil {
		t.Fatalf("Create b: %v", err)
	}
	_, err := mgr.Create(context.Background(), alice, CreateSpec{Name: "c"})
	if err == nil || !strings.Contains(err.Error(), "per-user limit") {
		t.Fatalf("third Create = %v, want the per-user limit", err)
	}
	if got := len(aps.schedds[testAP2].submittedFiles()); got != 1 {
		t.Errorf("%s got %d submissions, want 1", testAP2, got)
	}
	infos, err := mgr.List(context.Background(), alice)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	got := map[string]string{}
	for _, i := range infos {
		got[i.Name] = i.Schedd
	}
	if len(infos) != 2 || got["a"] != testAP1 || got["b"] != testAP2 {
		t.Errorf("List = %v, want a on %s and b on %s, once each", got, testAP1, testAP2)
	}
}

// injectSession puts a session job on an AP's queue directly, as one
// created by another server (or before a restart) would be.
func (f *fakeAPs) injectSession(ap string, cluster int, name string) {
	s := f.schedds[ap]
	s.mu.Lock()
	defer s.mu.Unlock()
	s.jobs = append(s.jobs, &fakeJob{cluster: cluster, owner: alice.Owner, session: name,
		batchName: BatchNameForSession(name), status: jobStatusRunning})
}

// A name on two APs is refused, not resolved to one of them: neither is
// dialed or removed, and the error names both jobs.
func TestMultiAPAmbiguousSessionNameIsRefused(t *testing.T) {
	aps := newFakeAPs(testAP1, testAP2)
	// The same number on both, as two fresh schedds would assign.
	aps.injectSession(testAP1, 7, "work")
	aps.injectSession(testAP2, 7, "work")
	mgr, dialed, _ := multiManager(t, aps, Options{})

	_, err := mgr.Exec(context.Background(), alice, "work", ExecRequest{Command: "rm -rf data"})
	var amb *AmbiguousSessionError
	if !errors.As(err, &amb) {
		t.Fatalf("Exec = %v, want AmbiguousSessionError", err)
	}
	want := "7.0@" + testAP1 + ", 7.0@" + testAP2
	if strings.Join(amb.Jobs, ", ") != want {
		t.Errorf("ambiguity names %v, want %s", amb.Jobs, want)
	}
	if len(*dialed) != 0 {
		t.Errorf("an ambiguous name was dialed: %v", *dialed)
	}
	if _, err := mgr.Stop(context.Background(), alice, "work"); !errors.As(err, &amb) {
		t.Errorf("Stop = %v, want AmbiguousSessionError", err)
	}
	for _, ap := range []string{testAP1, testAP2} {
		if got := aps.schedds[ap].removedJobs(); len(got) != 0 {
			t.Errorf("an ambiguous Stop removed on %s: %v", ap, got)
		}
	}
	// The catalog lagging behind a removal is not ambiguity: the AP's
	// own answer decides.
	stale, err := aps.Locate(context.Background(), alice, "", nil)
	if err != nil || len(stale) != 2 {
		t.Fatalf("catalog snapshot = %v, %v", stale, err)
	}
	aps.catalog = func() []LocatedAd { return stale }
	aps.schedds[testAP1].setStatus(aps.schedds[testAP1].jobs[0], jobStatusRemoved)
	if _, err := mgr.Exec(context.Background(), alice, "work", ExecRequest{Command: "true"}); err != nil {
		t.Fatalf("Exec once ap1's copy is gone: %v", err)
	}
	if got := strings.Join(*dialed, ","); got != "7.0@"+testAP2 {
		t.Errorf("dialed %s, want 7.0@%s", got, testAP2)
	}
}

// A session whose AP cannot be reached is reported from the catalog,
// and an exec on it fails naming that AP -- it is not sent anywhere
// else, and no new session is created in its place.
func TestMultiAPUnreachableSessionAPIsNotSubstituted(t *testing.T) {
	aps := newFakeAPs(testAP1, testAP2)
	aps.assign(testAP2)
	mgr, dialed, _ := multiManager(t, aps, Options{})
	if _, err := mgr.Create(context.Background(), alice, CreateSpec{Name: "work"}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	aps.running(testAP2)
	aps.assign(testAP1)
	aps.mu.Lock()
	aps.unreachable[testAP2] = true
	aps.mu.Unlock()

	_, err := mgr.Exec(context.Background(), alice, "work", ExecRequest{Command: "true"})
	if err == nil || !strings.Contains(err.Error(), testAP2) {
		t.Fatalf("Exec = %v, want a failure naming %s", err, testAP2)
	}
	if len(*dialed) != 0 {
		t.Errorf("dialed %v with the session's AP unreachable", *dialed)
	}

	// A fresh process finds it through the catalog and says the same.
	mgr.Close()
	mgr, dialed, _ = multiManager(t, aps, Options{})
	infos, err := mgr.List(context.Background(), alice)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(infos) != 1 || infos[0].Schedd != testAP2 || infos[0].APError == "" {
		t.Errorf("List = %+v, want the session on %s marked unreachable", infos, testAP2)
	}
	if _, err := mgr.Exec(context.Background(), alice, "work", ExecRequest{Command: "true"}); err == nil ||
		!strings.Contains(err.Error(), testAP2) {
		t.Errorf("Exec in a fresh process = %v, want a failure naming %s", err, testAP2)
	}
	// And the name still counts: creating it again is refused.
	var exists *SessionExistsError
	if _, err := mgr.Create(context.Background(), alice, CreateSpec{Name: "work"}); !errors.As(err, &exists) {
		t.Errorf("Create of the unreachable session's name = %v, want SessionExistsError", err)
	}
	if len(*dialed) != 0 || len(aps.schedds[testAP1].submittedFiles()) != 0 {
		t.Errorf("something reached %s: dialed %v", testAP1, *dialed)
	}
}

// With no way to find where the caller's sessions are, Create refuses
// rather than risk a second session of the same name.
func TestMultiAPCreateRefusesWithoutTheCatalog(t *testing.T) {
	aps := newFakeAPs(testAP1, testAP2)
	aps.locateErr = errors.New("the federation hub is unavailable")
	mgr, _, _ := multiManager(t, aps, Options{})
	if _, err := mgr.Create(context.Background(), alice, CreateSpec{Name: "work"}); err == nil ||
		!strings.Contains(err.Error(), "federation hub") {
		t.Fatalf("Create = %v, want the catalog's failure", err)
	}
	for ap, s := range aps.schedds {
		if n := len(s.submittedFiles()); n != 0 {
			t.Errorf("%s got %d submissions", ap, n)
		}
	}
}

// A catalog row for another owner, or one that is not a session, is
// not taken for the caller's.
func TestMultiAPCatalogRowsAreFilteredAgain(t *testing.T) {
	aps := newFakeAPs(testAP1, testAP2)
	ad := classad.New()
	ad.InsertAttr("ClusterId", int64(5))
	ad.InsertAttr("ProcId", int64(0))
	ad.InsertAttr("JobStatus", int64(jobStatusRunning))
	ad.InsertAttrString("Owner", "mallory")
	ad.InsertAttrString("JobBatchName", BatchNameForSession("work"))
	aps.catalog = func() []LocatedAd { return []LocatedAd{{AP: testAP1, Ad: ad}} }
	mgr, dialed, _ := multiManager(t, aps, Options{})
	if _, err := mgr.Exec(context.Background(), alice, "work", ExecRequest{Command: "true"}); err == nil {
		t.Fatal("Exec found another owner's session through the catalog")
	}
	if len(*dialed) != 0 {
		t.Errorf("dialed %v", *dialed)
	}
}
