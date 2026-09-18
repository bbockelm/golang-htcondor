package httpserver

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/logging"
)

// fakeCredd records what the bootstrap asked of the credd.
type fakeCredd struct {
	htcondor.CreddClient

	mu       sync.Mutex
	exists   map[string]bool
	statuses int
	puts     []string
	putBody  []byte
	statErr  error
	putErr   error
}

func newFakeCredd() *fakeCredd { return &fakeCredd{exists: map[string]bool{}} }

func (f *fakeCredd) GetServiceCredStatus(_ context.Context, _ htcondor.CredType, service, _, _ string) (htcondor.CredentialStatus, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.statuses++
	if f.statErr != nil {
		return htcondor.CredentialStatus{}, f.statErr
	}
	return htcondor.CredentialStatus{Exists: f.exists[service]}, nil
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

// TestNoServicesConfiguredDoesNothing: the default must not talk to the credd.
func TestNoServicesConfiguredDoesNothing(t *testing.T) {
	credd := newFakeCredd()
	h := credTestHandler(t, credd)

	h.ensureRequiredCredentials(ctxAs("alice@ap.example.org"))

	if statuses, puts := credd.counts(); statuses != 0 || puts != 0 {
		t.Errorf("touched the credd with nothing configured: %d statuses, %d puts", statuses, puts)
	}
}
