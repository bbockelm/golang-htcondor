package httpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/logging"
)

// fakeCredd records what the bootstrap asked of the credd.
//
// It answers the way CedarCredd does, including the part that hid the bug
// this file once had: a credential that is not there is reported as
// ErrCredentialNotFound, not as Exists=false. An earlier fake answered
// Exists=false with no error, so the tests passed while the real bootstrap
// skipped every missing credential as "could not check".
type fakeCredd struct {
	htcondor.CreddClient

	mu       sync.Mutex
	exists   map[string]bool
	pending  map[string]bool
	statuses int
	puts     []string
	putBody  []byte
	statErr  error
	putErr   error

	// What CheckCreds does: the services a local credmon would create
	// (they come back pending, as a fresh request does), and what it answers.
	localProviders []string
	oldCredd       bool
	checks         int
	named          []string
	checkURL       string
	checkErr       error
}

func newFakeCredd() *fakeCredd {
	return &fakeCredd{exists: map[string]bool{}, pending: map[string]bool{}}
}

func (f *fakeCredd) GetServiceCredStatus(_ context.Context, _ htcondor.CredType, service, _, _ string) (htcondor.CredentialStatus, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.statuses++
	if f.statErr != nil {
		return htcondor.CredentialStatus{}, f.statErr
	}
	switch {
	case f.exists[service]:
		return htcondor.CredentialStatus{Exists: true}, nil
	case f.pending[service]:
		return htcondor.CredentialStatus{Pending: true}, nil
	}
	return htcondor.CredentialStatus{}, htcondor.ErrCredentialNotFound
}

func (f *fakeCredd) CheckCreds(_ context.Context, requests []htcondor.CredRequest) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.checks++
	if f.checkErr != nil {
		return "", f.checkErr
	}
	if len(requests) == 0 {
		// A credd from HTCondor 25.13.2 on adds its local credmons' services
		// to a request that names none; an older one adds nothing.
		if !f.oldCredd {
			for _, p := range f.localProviders {
				if !f.exists[p] {
					f.pending[p] = true
				}
			}
		}
		return f.checkURL, nil
	}
	f.named = append(f.named, requests[0].Service)
	for _, req := range requests {
		if f.exists[req.Service] || f.pending[req.Service] {
			continue
		}
		if !slices.Contains(f.localProviders, req.Service) {
			return "", &htcondor.CheckCredsRefusal{Reason: fmt.Sprintf("ERROR: Credential '%s' of unknown type is missing.", req.Service)}
		}
		f.pending[req.Service] = true
	}
	return f.checkURL, nil
}

func (f *fakeCredd) checkCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.checks
}

func (f *fakeCredd) PutServiceCred(_ context.Context, _ htcondor.CredType, cred []byte, service, _, _ string, _ *bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.putErr != nil {
		return f.putErr
	}
	f.puts = append(f.puts, service)
	f.putBody = cred
	f.exists[service] = true
	return nil
}

func (f *fakeCredd) counts() (statuses, puts int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.statuses, len(f.puts)
}

func credTestHandler(t *testing.T, credd htcondor.CreddClient, services ...string) *Handler {
	t.Helper()
	lg, err := logging.New(&logging.Config{OutputPath: "stderr"})
	if err != nil {
		t.Fatalf("logger: %v", err)
	}
	h := &Handler{
		logger:              lg,
		credd:               credd,
		requiredCredentials: services,
		requiredCredCache:   newRequiredCredCache(requiredCredentialTTL),
	}
	h.creddAvailable.Store(credd != nil)
	return h
}

func ctxAs(user string) context.Context {
	return htcondor.WithAuthenticatedUser(context.Background(), user)
}

// TestBootstrapsAMissingCredential is the point of the feature: a submit by
// someone with no credential on file leaves one behind, so the access point
// does not hold the job.
func TestBootstrapsAMissingCredential(t *testing.T) {
	credd := newFakeCredd()
	h := credTestHandler(t, credd, "scitokens")

	h.ensureRequiredCredentials(ctxAs("alice@ap.example.org"))

	_, puts := credd.counts()
	if puts != 1 {
		t.Fatalf("stored %d credentials, want 1", puts)
	}
	if credd.puts[0] != "scitokens" {
		t.Errorf("stored %q, want scitokens", credd.puts[0])
	}
	// The credd stores whatever it is given and then fails every later read
	// of a credential that is not JSON, so a placeholder that is not valid
	// JSON would replace a missing credential with a broken one.
	if !json.Valid(credd.putBody) {
		t.Errorf("placeholder is not valid JSON: %q", credd.putBody)
	}
	if err := htcondor.ValidateOAuthCredential("scitokens", credd.putBody); err != nil {
		t.Errorf("placeholder rejected by the validator: %v", err)
	}
}

// TestLeavesAnExistingCredentialAlone: a real credential must never be
// overwritten by a placeholder.
func TestLeavesAnExistingCredentialAlone(t *testing.T) {
	credd := newFakeCredd()
	credd.exists["scitokens"] = true
	h := credTestHandler(t, credd, "scitokens")

	h.ensureRequiredCredentials(ctxAs("alice@ap.example.org"))

	if _, puts := credd.counts(); puts != 0 {
		t.Errorf("overwrote an existing credential (%d puts)", puts)
	}
}

// TestCachesPresenceAcrossSubmits: a burst of submissions must not become a
// burst of credd round trips.
func TestCachesPresenceAcrossSubmits(t *testing.T) {
	credd := newFakeCredd()
	h := credTestHandler(t, credd, "scitokens")
	ctx := ctxAs("alice@ap.example.org")

	for i := 0; i < 5; i++ {
		h.ensureRequiredCredentials(ctx)
	}

	statuses, puts := credd.counts()
	if statuses != 1 {
		t.Errorf("asked the credd %d times, want 1", statuses)
	}
	if puts != 1 {
		t.Errorf("stored %d times, want 1", puts)
	}
}

// TestCacheExpires: a credential deleted out from under us is noticed again
// once the entry ages out.
func TestCacheExpires(t *testing.T) {
	credd := newFakeCredd()
	h := credTestHandler(t, credd, "scitokens")
	ctx := ctxAs("alice@ap.example.org")

	now := time.Now()
	h.requiredCredCache.now = func() time.Time { return now }

	h.ensureRequiredCredentials(ctx)
	now = now.Add(requiredCredentialTTL + time.Second)
	h.ensureRequiredCredentials(ctx)

	if statuses, _ := credd.counts(); statuses != 2 {
		t.Errorf("asked the credd %d times, want 2 once the entry expired", statuses)
	}
}

// TestCacheIsPerUser: one caller's credential must never answer for another's.
func TestCacheIsPerUser(t *testing.T) {
	credd := newFakeCredd()
	h := credTestHandler(t, credd, "scitokens")

	h.ensureRequiredCredentials(ctxAs("alice@ap.example.org"))
	h.ensureRequiredCredentials(ctxAs("bob@ap.example.org"))

	if statuses, _ := credd.counts(); statuses != 2 {
		t.Errorf("asked the credd %d times for two users, want 2", statuses)
	}
}

// TestUnidentifiedCallerIsNotCached: with no identity there is no safe key, so
// nothing is remembered rather than remembered under a key that could collide.
func TestUnidentifiedCallerIsNotCached(t *testing.T) {
	credd := newFakeCredd()
	h := credTestHandler(t, credd, "scitokens")

	h.ensureRequiredCredentials(context.Background())
	h.ensureRequiredCredentials(context.Background())

	if statuses, _ := credd.counts(); statuses != 2 {
		t.Errorf("asked the credd %d times, want 2 (no caching without an identity)", statuses)
	}
}

// TestFailureIsNotCached: a store that failed must be retried, not remembered
// as done.
func TestFailureIsNotCached(t *testing.T) {
	credd := newFakeCredd()
	credd.putErr = errors.New("credd refused")
	h := credTestHandler(t, credd, "scitokens")
	ctx := ctxAs("alice@ap.example.org")

	h.ensureRequiredCredentials(ctx)
	h.ensureRequiredCredentials(ctx)

	if statuses, _ := credd.counts(); statuses != 2 {
		t.Errorf("asked the credd %d times, want 2 after a failed store", statuses)
	}
}

// TestNeverBlocksSubmit: every credd failure mode has to return, not panic or
// hang. Refusing to submit would turn a convenience into a new way for
// submission to break.
func TestNeverBlocksSubmit(t *testing.T) {
	cases := []struct {
		name  string
		credd *fakeCredd
		nilIt bool
	}{
		{name: "status fails", credd: func() *fakeCredd { c := newFakeCredd(); c.statErr = errors.New("down"); return c }()},
		{name: "store fails", credd: func() *fakeCredd { c := newFakeCredd(); c.putErr = errors.New("denied"); return c }()},
		{name: "no credd at all", nilIt: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var h *Handler
			if tc.nilIt {
				h = credTestHandler(t, nil, "scitokens")
			} else {
				h = credTestHandler(t, tc.credd, "scitokens")
			}
			h.ensureRequiredCredentials(ctxAs("alice@ap.example.org"))
		})
	}
}

// TestNoServicesConfiguredOnlyChecks: with nothing configured the server
// still makes condor_submit's request -- that is the part needing no
// configuration -- but stores nothing.
func TestNoServicesConfiguredOnlyChecks(t *testing.T) {
	credd := newFakeCredd()
	h := credTestHandler(t, credd)

	h.ensureRequiredCredentials(ctxAs("alice@ap.example.org"))

	if statuses, puts := credd.counts(); statuses != 0 || puts != 0 {
		t.Errorf("touched stored credentials with nothing configured: %d statuses, %d puts", statuses, puts)
	}
	if n := credd.checkCount(); n != 1 {
		t.Errorf("made the check-creds request %d times, want 1", n)
	}
}

// TestChecksCredsBeforeSubmit is issue #576: an access point whose schedd
// requires local-credmon credentials on every job held each one submitted
// here once the credd had swept the user's credentials, because nothing in
// this server asked the credd for them the way condor_submit does.
func TestChecksCredsBeforeSubmit(t *testing.T) {
	credd := newFakeCredd()
	credd.localProviders = []string{"rdrive", "scitokens"}
	h := credTestHandler(t, credd)

	h.ensureRequiredCredentials(ctxAs("elinck@ap.example.org"))

	for _, p := range credd.localProviders {
		if !credd.pending[p] && !credd.exists[p] {
			t.Errorf("%s was not requested from the credd", p)
		}
	}
}

// TestCheckCredsIsCachedPerUser: one request per user per TTL, not one per
// submit.
func TestCheckCredsIsCachedPerUser(t *testing.T) {
	credd := newFakeCredd()
	h := credTestHandler(t, credd)

	for i := 0; i < 3; i++ {
		h.ensureRequiredCredentials(ctxAs("alice@ap.example.org"))
	}
	h.ensureRequiredCredentials(ctxAs("bob@ap.example.org"))

	if n := credd.checkCount(); n != 2 {
		t.Errorf("made the check-creds request %d times for two users, want 2", n)
	}
}

// TestCheckCredsUnreachableIsRetried and refused-is-remembered: a credd that
// could not be reached is asked again on the next submit; one that answered
// "no" is not asked again until the entry expires.
func TestCheckCredsFailureCaching(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want int
	}{
		{name: "unreachable", err: errors.New("connection refused"), want: 2},
		{name: "refused", err: &htcondor.CheckCredsRefusal{Reason: "ERROR - SEC_CREDENTIAL_DIRECTORY_OAUTH not configured"}, want: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			credd := newFakeCredd()
			credd.checkErr = tc.err
			h := credTestHandler(t, credd)
			ctx := ctxAs("alice@ap.example.org")

			h.ensureRequiredCredentials(ctx)
			h.ensureRequiredCredentials(ctx)

			if n := credd.checkCount(); n != tc.want {
				t.Errorf("made the check-creds request %d times, want %d", n, tc.want)
			}
		})
	}
}

// TestLocalCredmonServiceGetsNoPlaceholder: a required service that a local
// credmon provides is requested by the check and comes back pending. Storing
// a placeholder over it would replace the credd's request with ours.
func TestLocalCredmonServiceGetsNoPlaceholder(t *testing.T) {
	credd := newFakeCredd()
	credd.localProviders = []string{"scitokens"}
	h := credTestHandler(t, credd, "scitokens")

	h.ensureRequiredCredentials(ctxAs("alice@ap.example.org"))

	if _, puts := credd.counts(); puts != 0 {
		t.Errorf("stored a placeholder over a credential the credd had just requested (%d puts)", puts)
	}
}

// TestOlderCreddIsAskedByName: a credd before HTCondor 25.13.2 adds nothing to
// a request that names no services, so a required service it provides is
// missing after the first check. Named, the credd creates it -- and it must
// not get a placeholder instead.
func TestOlderCreddIsAskedByName(t *testing.T) {
	credd := newFakeCredd()
	credd.localProviders = []string{"scitokens"}
	credd.oldCredd = true
	h := credTestHandler(t, credd, "scitokens")

	h.ensureRequiredCredentials(ctxAs("alice@ap.example.org"))

	if !credd.pending["scitokens"] {
		t.Error("scitokens was not requested from the credd by name")
	}
	if _, puts := credd.counts(); puts != 0 {
		t.Errorf("stored a placeholder for a service the credd provides (%d puts)", puts)
	}
}

// TestNoCreddDoesNothing: without a credd there is nobody to ask.
func TestNoCreddDoesNothing(t *testing.T) {
	credd := newFakeCredd()
	h := credTestHandler(t, credd)
	h.creddAvailable.Store(false)

	h.ensureRequiredCredentials(ctxAs("alice@ap.example.org"))

	if n := credd.checkCount(); n != 0 {
		t.Errorf("made the check-creds request %d times with no credd available", n)
	}
}

// Every submit this daemon makes goes through submitJob, and that is
// where the bootstrap lives now. It used to be a line each surface
// copied, and the surfaces added later -- interactive sessions, reached
// from the SSH gateway and from the MCP tools -- did not copy it, so
// somebody who typed `ssh` got a job held with "Job credentials are not
// available".
func TestSubmitJobBootstrapsTheRequiredCredentials(t *testing.T) {
	credd := newFakeCredd()
	h := credTestHandler(t, credd, "scitokens")
	// Nothing listens on port 1, so the submit fails. That is fine and
	// deliberate: what is being pinned is that the preparation happens
	// on this path at all.
	h.schedd = htcondor.NewSchedd("test", "127.0.0.1:1")

	ctx, cancel := context.WithTimeout(ctxAs("alice@ap.example.org"), 20*time.Second)
	defer cancel()
	if _, _, err := h.submitJob(ctx, "executable = /bin/true\nqueue\n"); err == nil {
		t.Fatal("a submit to an address nothing listens on succeeded")
	}

	if _, puts := credd.counts(); puts != 1 {
		t.Errorf("the submit path stored %d credentials, want 1", puts)
	}
}
