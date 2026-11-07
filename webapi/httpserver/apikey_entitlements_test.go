package httpserver

import (
	"context"
	"path/filepath"
	"slices"
	"testing"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/droppriv"
	"github.com/bbockelm/golang-htcondor/webapi/httpserver/apikey"
)

// Entitlement scopes are claims about a person, so they are re-checked
// on use for an ordinary key and granted once for a service key. These
// tests drive resolveAPIKeyEntitlements through every way that can go,
// because the difference between them is the difference between an
// automation that keeps working and one that silently narrows to one
// user's records.

// fakeGroups is a group source that answers from a map, so a test can
// be a deployment with an account database without having one.
type fakeGroups struct {
	groups map[string][]string
	err    error
	calls  int
}

func (f *fakeGroups) LookupGroups(_ context.Context, user string) ([]string, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return f.groups[user], nil
}

func (f *fakeGroups) Name() string { return "fake" }

var _ droppriv.GroupLookup = (*fakeGroups)(nil)

// entitlementHandler builds a Handler whose group source is whatever
// the test wants: nil for a deployment that reads groups from the token
// and so can never re-check them, non-nil for one with an account
// database.
func entitlementHandler(t *testing.T, groups droppriv.GroupLookup) *Handler {
	t.Helper()
	db := newTestDB(t, filepath.Join(t.TempDir(), "ent-ak.db"))
	h := &Handler{
		apiKeyStore:      &apiKeyStore{db: db},
		webuiAdminGroups: newGroupSet("condor-admins"),
		uidDomain:        "example.org",
	}
	if groups != nil {
		h.localIdentity = &localIdentity{groups: groups}
	}
	return h
}

// insertKey persists a key and returns its row as the auth path would
// read it.
func insertKey(t *testing.T, h *Handler, creator string, scopes []string, service bool, checked time.Time) *apiKeyRow {
	t.Helper()
	minted, err := apikey.Mint()
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	exp := time.Now().Add(24 * time.Hour)
	if _, err := h.apiKeyStore.Insert(context.Background(),
		minted.KeyID, minted.SecretHash, "k", creator, scopes, &exp, service); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	if !checked.IsZero() {
		if _, err := h.apiKeyStore.db.ExecContext(context.Background(),
			`UPDATE api_keys SET entitlements_checked_at = ? WHERE key_id = ?`,
			checked.UTC(), minted.KeyID); err != nil {
			t.Fatalf("backdate: %v", err)
		}
	}
	row, err := h.apiKeyStore.LookupActive(context.Background(), minted.KeyID)
	if err != nil {
		t.Fatalf("LookupActive: %v", err)
	}
	return row
}

func resolve(t *testing.T, h *Handler, row *apiKeyRow) []string {
	t.Helper()
	_, scopes := h.resolveAPIKeyEntitlements(context.Background(), row)
	return scopes
}

// A key carrying no entitlement is returned untouched and costs no
// lookup. This is every key minted before entitlements existed, so the
// cheap path has to stay cheap and has to stay a no-op.
func TestEntitlementsUntouchedWithoutEntitlementScope(t *testing.T) {
	groups := &fakeGroups{groups: map[string][]string{"alice": {"condor-admins"}}}
	h := entitlementHandler(t, groups)
	row := insertKey(t, h, "alice", []string{"metrics", "condor:/READ"}, false, time.Time{})

	got := resolve(t, h, row)
	if !slices.Equal(got, []string{"metrics", "condor:/READ"}) {
		t.Errorf("scopes = %v, want them unchanged", got)
	}
	if groups.calls != 0 {
		t.Errorf("looked up groups %d times for a key with no entitlement; want 0", groups.calls)
	}
}

// A service key holds its entitlement where nothing can confirm it.
// This is the case the whole feature exists for: an automation in a
// deployment whose groups come from the token, where there is no live
// source and never will be.
func TestServiceKeyHoldsEntitlementWithNoLiveSource(t *testing.T) {
	h := entitlementHandler(t, nil) // no account database
	row := insertKey(t, h, "alice", []string{scopePoolRead, "condor:/READ"}, true,
		time.Now().Add(-30*24*time.Hour)) // and last confirmed a month ago

	got := resolve(t, h, row)
	if !slices.Contains(got, scopePoolRead) {
		t.Errorf("service key lost %s (got %v); it is granted at mint and held for the key's life",
			scopePoolRead, got)
	}
}

// The same key, not marked as a service key, loses the entitlement once
// the staleness window has passed. Silence is not consent forever.
func TestOrdinaryKeyLosesStaleEntitlementWithNoLiveSource(t *testing.T) {
	h := entitlementHandler(t, nil)
	row := insertKey(t, h, "alice", []string{scopePoolRead, "condor:/READ"}, false,
		time.Now().Add(-2*time.Hour)) // older than the default one-hour window

	got := resolve(t, h, row)
	if slices.Contains(got, scopePoolRead) {
		t.Errorf("stale entitlement survived with nothing able to confirm it: %v", got)
	}
	if !slices.Contains(got, "condor:/READ") {
		t.Errorf("withholding the entitlement also dropped an endpoint scope: %v", got)
	}
}

// Inside the window the same key keeps working, so an unreachable or
// absent source is a grace period rather than an outage.
func TestOrdinaryKeyKeepsFreshEntitlementWithNoLiveSource(t *testing.T) {
	h := entitlementHandler(t, nil)
	row := insertKey(t, h, "alice", []string{scopePoolRead}, false, time.Now().Add(-time.Minute))

	if got := resolve(t, h, row); !slices.Contains(got, scopePoolRead) {
		t.Errorf("entitlement confirmed a minute ago was withheld: %v", got)
	}
}

// With an account database the answer is live, and a creator still in
// the group keeps the entitlement however old the stored timestamp is.
func TestOrdinaryKeyConfirmedByLiveGroups(t *testing.T) {
	groups := &fakeGroups{groups: map[string][]string{"alice": {"condor-admins"}}}
	h := entitlementHandler(t, groups)
	row := insertKey(t, h, "alice", []string{scopePoolRead}, false,
		time.Now().Add(-30*24*time.Hour))

	got := resolve(t, h, row)
	if !slices.Contains(got, scopePoolRead) {
		t.Errorf("live group membership did not restore a stale entitlement: %v", got)
	}
	// A confirmation restarts the window, so the next request inside the
	// TTL costs no lookup even if the source goes away.
	after, err := h.apiKeyStore.LookupActive(context.Background(), row.KeyID)
	if err != nil {
		t.Fatalf("LookupActive: %v", err)
	}
	if after.EntitlementsCheckedAt == nil || time.Since(*after.EntitlementsCheckedAt) > time.Minute {
		t.Errorf("a successful verification did not record itself: %v", after.EntitlementsCheckedAt)
	}
}

// A creator who has left the group loses the entitlement at once,
// regardless of how recently it was confirmed. A denial is not subject
// to the grace period; only silence is.
func TestOrdinaryKeyDeniedByLiveGroups(t *testing.T) {
	groups := &fakeGroups{groups: map[string][]string{"alice": {"users"}}}
	h := entitlementHandler(t, groups)
	row := insertKey(t, h, "alice", []string{scopePoolRead, "metrics"}, false, time.Now())

	got := resolve(t, h, row)
	if slices.Contains(got, scopePoolRead) {
		t.Errorf("a creator out of the group kept the entitlement: %v", got)
	}
	if !slices.Contains(got, "metrics") {
		t.Errorf("the denial also dropped an endpoint scope: %v", got)
	}
}

// An unreadable account database is silence, not a denial: it must not
// revoke everybody the moment NSS hiccups.
func TestUnreadableGroupSourceIsSilenceNotDenial(t *testing.T) {
	groups := &fakeGroups{err: context.DeadlineExceeded}
	h := entitlementHandler(t, groups)
	row := insertKey(t, h, "alice", []string{scopePoolRead}, false, time.Now().Add(-time.Minute))

	if got := resolve(t, h, row); !slices.Contains(got, scopePoolRead) {
		t.Errorf("an unreadable group source revoked a fresh entitlement: %v", got)
	}
}

// A service key is bounded by its expiry and nothing else, so an
// expired one stops authenticating outright rather than merely losing
// its entitlement.
func TestExpiredServiceKeyDoesNotAuthenticate(t *testing.T) {
	h := entitlementHandler(t, nil)
	minted, err := apikey.Mint()
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	past := time.Now().Add(-time.Minute)
	if _, err := h.apiKeyStore.Insert(context.Background(),
		minted.KeyID, minted.SecretHash, "k", "alice",
		[]string{scopePoolRead}, &past, true); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	if _, err := h.apiKeyStore.LookupActive(context.Background(), minted.KeyID); err == nil {
		t.Fatal("an expired service key still authenticated; its expiry is the only bound on its entitlement")
	}
}

// The verification runs once per request even though authenticateAPIKey
// runs twice for a request that passes the condor-scope middleware.
func TestEntitlementVerifiedOncePerRequest(t *testing.T) {
	groups := &fakeGroups{groups: map[string][]string{"alice": {"condor-admins"}}}
	h := entitlementHandler(t, groups)
	row := insertKey(t, h, "alice", []string{scopePoolRead}, false, time.Time{})

	ctx, first := h.resolveAPIKeyEntitlements(context.Background(), row)
	ctx2, second := h.resolveAPIKeyEntitlements(ctx, row)
	_ = ctx2
	if !slices.Equal(first, second) {
		t.Errorf("two resolutions in one request disagreed: %v vs %v", first, second)
	}
	if groups.calls != 1 {
		t.Errorf("looked up groups %d times in one request; want 1", groups.calls)
	}
}

// A second key's verdict must not be served from the first key's cached
// answer, or one key would borrow another's entitlement.
func TestMemoIsPerKey(t *testing.T) {
	groups := &fakeGroups{groups: map[string][]string{
		"alice": {"condor-admins"},
		"bob":   {"users"},
	}}
	h := entitlementHandler(t, groups)
	aliceRow := insertKey(t, h, "alice", []string{scopePoolRead}, false, time.Time{})
	bobRow := insertKey(t, h, "bob", []string{scopePoolRead}, false, time.Time{})

	ctx, alice := h.resolveAPIKeyEntitlements(context.Background(), aliceRow)
	if !slices.Contains(alice, scopePoolRead) {
		t.Fatalf("alice lost her entitlement: %v", alice)
	}
	_, bob := h.resolveAPIKeyEntitlements(ctx, bobRow)
	if slices.Contains(bob, scopePoolRead) {
		t.Errorf("bob was served alice's cached verdict: %v", bob)
	}
}

// pool:read is what makes a key see past its creator's own jobs, so the
// owner-scoping gate has to honour it. Without this the whole feature
// records an entitlement nothing consults.
func TestPoolReadGrantsCrossUserReads(t *testing.T) {
	h := entitlementHandler(t, nil)
	h.logger = nil

	ctx := withAPIKeyScopes(context.Background(), []string{scopePoolRead})
	ctx = htcondor.WithAuthenticatedUser(ctx, "alice")
	if !h.seesAllJobsByPolicy(ctx, requestWithBearer(t, ""), jobScopeRead) {
		t.Error("a credential granted pool:read was still confined to its own jobs")
	}

	// And it is the read tier only: acting on other users' jobs is a
	// separate power this scope does not carry.
	if h.seesAllJobsByPolicy(ctx, requestWithBearer(t, ""), jobScopeMutate) {
		t.Error("pool:read granted the mutate tier")
	}
}

// A service key's entitlement is bounded only by its expiry, so minting
// one without an expiry has to be refused rather than quietly producing
// a standing grant.
func TestServiceKeyEntitlementRequiresExpiry(t *testing.T) {
	max := 365 * 24 * time.Hour
	if err := validateServiceKeyExpiry([]string{scopePoolRead}, true, nil, max); err == nil {
		t.Error("a service key carrying an entitlement was allowed to never expire")
	}

	// Beyond the cap is refused too, or the expiry is a formality.
	far := time.Now().Add(2 * max)
	if err := validateServiceKeyExpiry([]string{scopePoolRead}, true, &far, max); err == nil {
		t.Error("a service key was allowed an expiry past the server's cap")
	}

	ok := time.Now().Add(24 * time.Hour)
	if err := validateServiceKeyExpiry([]string{scopePoolRead}, true, &ok, max); err != nil {
		t.Errorf("a bounded service key was refused: %v", err)
	}
}

// The rule is about frozen entitlements, not about service keys as
// such: a service key that freezes nothing needs no expiry, and an
// ordinary key is re-verified on use so it needs none either.
func TestExpiryRuleOnlyBindsFrozenEntitlements(t *testing.T) {
	max := 365 * 24 * time.Hour
	if err := validateServiceKeyExpiry([]string{"metrics"}, true, nil, max); err != nil {
		t.Errorf("a service key with no entitlement was forced to expire: %v", err)
	}
	if err := validateServiceKeyExpiry([]string{scopePoolRead}, false, nil, max); err != nil {
		t.Errorf("an ordinary key was forced to expire: %v", err)
	}
}

// Minting an entitlement that cannot be re-verified is legal but
// short-lived, and the person minting it is told so while they are
// still looking. Silence here is how the original report happened.
func TestMintNoteWarnsWhenEntitlementCannotBeConfirmed(t *testing.T) {
	h := entitlementHandler(t, nil) // groups come from the token
	note := h.mintNote(context.Background(), "alice", []string{scopePoolRead}, false)
	if note == "" {
		t.Error("no note for an entitlement that will lapse unattended")
	}

	// A service key is the answer to that problem, so it gets no note.
	if n := h.mintNote(context.Background(), "alice", []string{scopePoolRead}, true); n != "" {
		t.Errorf("service key warned about lapsing: %q", n)
	}
	// Neither does a key with nothing to lapse.
	if n := h.mintNote(context.Background(), "alice", []string{"metrics"}, false); n != "" {
		t.Errorf("key with no entitlement warned about lapsing: %q", n)
	}

	// Where the entitlement CAN be re-verified there is nothing to warn
	// about: the key keeps working as long as its creator qualifies.
	live := entitlementHandler(t, &fakeGroups{groups: map[string][]string{"alice": {"condor-admins"}}})
	if n := live.mintNote(context.Background(), "alice", []string{scopePoolRead}, false); n != "" {
		t.Errorf("warned about lapsing in a deployment that can re-verify: %q", n)
	}
}

// countingOracle records how often it was asked and answers however the
// test says.
type countingOracle struct {
	calls  int
	status UserStatus
	reason string
}

func (o *countingOracle) Name() string { return "counting" }

func (o *countingOracle) Check(context.Context, string, []string) (ReauthDecision, error) {
	o.calls++
	return ReauthDecision{Status: o.status, Reason: o.reason}, nil
}

// Every revocation oracle is an RPC to the schedd, so they must not be
// consulted on each authenticated request. Within the staleness window
// the stored answer stands and nothing is asked.
func TestOraclesNotConsultedWhileEntitlementIsFresh(t *testing.T) {
	oracle := &countingOracle{status: UserStatusRevoked, reason: "disabled"}
	h := entitlementHandler(t, nil) // no group source, so oracles are the only live source
	h.revocationOracles = []RevocationOracle{oracle}
	row := insertKey(t, h, "alice", []string{scopePoolRead}, false, time.Now().Add(-time.Minute))

	if got := resolve(t, h, row); !slices.Contains(got, scopePoolRead) {
		t.Errorf("a fresh entitlement was withheld: %v", got)
	}
	if oracle.calls != 0 {
		t.Errorf("asked the schedd %d times for a fresh entitlement; want 0 -- this is the authentication path",
			oracle.calls)
	}
}

// Once it is stale they are asked, and a revoked user loses the
// entitlement rather than merely letting it lapse.
func TestOraclesConsultedOnceEntitlementIsStale(t *testing.T) {
	oracle := &countingOracle{status: UserStatusRevoked, reason: "disabled by an admin"}
	h := entitlementHandler(t, nil)
	h.revocationOracles = []RevocationOracle{oracle}
	row := insertKey(t, h, "alice", []string{scopePoolRead, "metrics"}, false,
		time.Now().Add(-2*time.Hour))

	got := resolve(t, h, row)
	if slices.Contains(got, scopePoolRead) {
		t.Errorf("a revoked user kept the entitlement: %v", got)
	}
	if !slices.Contains(got, "metrics") {
		t.Errorf("revocation also dropped an endpoint scope: %v", got)
	}
	if oracle.calls != 1 {
		t.Errorf("oracle consulted %d times; want exactly 1", oracle.calls)
	}
}

// A stale entitlement that an oracle vouches for is restored, and the
// window restarts so the next request costs nothing.
func TestActiveOracleRenewsStaleEntitlement(t *testing.T) {
	oracle := &countingOracle{status: UserStatusActive}
	h := entitlementHandler(t, nil)
	h.revocationOracles = []RevocationOracle{oracle}
	row := insertKey(t, h, "alice", []string{scopePoolRead}, false, time.Now().Add(-2*time.Hour))

	if got := resolve(t, h, row); !slices.Contains(got, scopePoolRead) {
		t.Errorf("an oracle vouched for the user but the entitlement was withheld: %v", got)
	}
	after, err := h.apiKeyStore.LookupActive(context.Background(), row.KeyID)
	if err != nil {
		t.Fatalf("LookupActive: %v", err)
	}
	if after.EntitlementsCheckedAt == nil || time.Since(*after.EntitlementsCheckedAt) > time.Minute {
		t.Errorf("an oracle confirmation did not restart the window: %v", after.EntitlementsCheckedAt)
	}
}

// A live group source answers for free, so the oracles stay unasked
// even when the stored answer is ancient.
func TestLiveGroupsAnswerWithoutAskingOracles(t *testing.T) {
	oracle := &countingOracle{status: UserStatusRevoked}
	h := entitlementHandler(t, &fakeGroups{groups: map[string][]string{"alice": {"condor-admins"}}})
	h.revocationOracles = []RevocationOracle{oracle}
	row := insertKey(t, h, "alice", []string{scopePoolRead}, false, time.Now().Add(-30*24*time.Hour))

	if got := resolve(t, h, row); !slices.Contains(got, scopePoolRead) {
		t.Errorf("live membership did not settle it: %v", got)
	}
	if oracle.calls != 0 {
		t.Errorf("asked the schedd %d times when groups had already answered; want 0", oracle.calls)
	}
}

// And a service key asks nothing of anybody: its entitlement was
// granted at mint and is bounded by its expiry alone.
func TestServiceKeyAsksNoOracles(t *testing.T) {
	oracle := &countingOracle{status: UserStatusRevoked}
	h := entitlementHandler(t, nil)
	h.revocationOracles = []RevocationOracle{oracle}
	row := insertKey(t, h, "alice", []string{scopePoolRead}, true, time.Now().Add(-30*24*time.Hour))

	if got := resolve(t, h, row); !slices.Contains(got, scopePoolRead) {
		t.Errorf("service key lost its entitlement: %v", got)
	}
	if oracle.calls != 0 {
		t.Errorf("service key triggered %d oracle calls; want 0", oracle.calls)
	}
}
