package httpserver

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"

	"github.com/bbockelm/golang-htcondor/logging"
)

func superuserTestHandler(t *testing.T, superUsers []string) *Handler {
	t.Helper()
	logger, err := logging.New(&logging.Config{OutputPath: "stderr"})
	if err != nil {
		t.Fatalf("logger: %v", err)
	}
	h := &Handler{
		logger:         logger,
		uidDomain:      "example.org",
		trustDomain:    "example.org",
		signingKeyPath: "/nonexistent/passwords.d/POOL",
		superuserGroup: "condor-webadmins",
	}
	h.superuserPolicy = newSuperuserPolicy(
		&fakeSuperUsers{users: superUsers}, "example.org", "", time.Hour, logger)
	if err := h.superuserPolicy.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	return h
}

// TestReasonNamesBothParties is the audit requirement expressed as a test.
//
// The schedd appends "(by user <authenticated identity>)" to whatever reason
// it receives. When the actor is not themselves a queue superuser that
// appended identity is a shared account, so the reason text this server sends
// is the only place in the job ad where the human appears -- and the job ad is
// the record that outlives our logs and reaches the job's owner.
func TestReasonNamesBothParties(t *testing.T) {
	imp := Impersonation{
		Actor:    "bob@example.org",
		Target:   "alice@example.org",
		Identity: "condor@example.org",
	}
	reason := imp.Reason("Removed")

	if !strings.Contains(reason, "bob@example.org") {
		t.Errorf("reason does not name the actor: %q", reason)
	}
	if !strings.Contains(reason, "alice@example.org") {
		t.Errorf("reason does not name the target: %q", reason)
	}
	if !strings.Contains(strings.ToLower(reason), "superuser") {
		t.Errorf("reason does not disclose that this was superuser mode: %q", reason)
	}
	if !strings.HasPrefix(reason, "Removed") {
		t.Errorf("reason should lead with the action: %q", reason)
	}
}

// TestSessionTagSeparatesImpersonations pins that cedar cannot cross sessions
// between identities. cedar caches per {SecurityTag, address, command}; an
// untagged or coarsely-tagged impersonation could reuse -- or be reused by --
// an ordinary user's session.
func TestSessionTagSeparatesImpersonations(t *testing.T) {
	base := Impersonation{Actor: "bob@example.org", Target: "alice@example.org", Identity: "condor@example.org"}
	otherTarget := base
	otherTarget.Target = "carol@example.org"
	otherIdentity := base
	otherIdentity.Identity = "bob@example.org"

	if base.sessionTag() == otherTarget.sessionTag() {
		t.Errorf("two targets share a session tag: %q", base.sessionTag())
	}
	if base.sessionTag() == otherIdentity.sessionTag() {
		t.Errorf("two identities share a session tag: %q", base.sessionTag())
	}
	if !strings.HasPrefix(base.sessionTag(), "superuser:") {
		t.Errorf("tag should be recognisably a superuser session: %q", base.sessionTag())
	}
	// And must not collide with the ordinary per-user tag, which is the
	// bare username (see requireAuthentication).
	if base.sessionTag() == "alice@example.org" || base.sessionTag() == "bob@example.org" {
		t.Errorf("superuser tag collides with an ordinary user tag: %q", base.sessionTag())
	}
}

func TestImpersonateRequiresActorAndTarget(t *testing.T) {
	h := superuserTestHandler(t, []string{"condor@example.org"})
	ctx := context.Background()

	if _, _, err := h.impersonate(ctx, armedSession{identity: "condor@example.org"}, "", "alice"); err == nil {
		t.Errorf("expected an error with no actor")
	}
	if _, _, err := h.impersonate(ctx, armedSession{identity: "condor@example.org"}, "bob", ""); err == nil {
		t.Errorf("expected an error with no target")
	}
}

func TestImpersonateRefusedWhenDisabled(t *testing.T) {
	logger, _ := logging.New(&logging.Config{OutputPath: "stderr"})
	h := &Handler{logger: logger, uidDomain: "example.org"} // no group, no policy
	if _, _, err := h.impersonate(context.Background(), armedSession{identity: "condor@example.org"}, "bob", "alice"); err == nil {
		t.Errorf("impersonation must be refused when superuser mode is off")
	}
}

// TestSuperuserAuthzExcludesAdministrator pins the token narrowing. Queue
// superuser status comes from QUEUE_SUPER_USERS, not from the ADMINISTRATOR
// authorization level, so granting it would add reconfigure-the-pool power to
// a credential that only needs to touch the queue.
func TestSuperuserAuthzExcludesAdministrator(t *testing.T) {
	for _, forbidden := range []string{"ADMINISTRATOR", "CONFIG", "DAEMON", "NEGOTIATOR"} {
		for _, got := range superuserAuthz {
			if strings.EqualFold(got, forbidden) {
				t.Errorf("impersonation token grants %s", forbidden)
			}
		}
	}
	if len(superuserAuthz) != 2 {
		t.Errorf("superuserAuthz = %v, want exactly READ and WRITE", superuserAuthz)
	}
}

func TestSuperuserSessionArmAndExpiry(t *testing.T) {
	s := newSuperuserSessions(50 * time.Millisecond)

	if _, ok := s.Armed("sess"); ok {
		t.Errorf("a fresh session must not be armed")
	}
	s.Arm("sess", armedSession{identity: "condor@example.org"})
	if a, ok := s.Armed("sess"); !ok {
		t.Errorf("session should be armed after Arm")
	} else if a.identity != "condor@example.org" {
		t.Errorf("armed identity = %q, want it preserved", a.identity)
	}
	if s.Count() != 1 {
		t.Errorf("Count = %d, want 1", s.Count())
	}

	// Auto-disarm: an admin who walks away must not leave the mode on.
	time.Sleep(80 * time.Millisecond)
	if _, ok := s.Armed("sess"); ok {
		t.Errorf("session should have disarmed itself")
	}
	if s.Count() != 0 {
		t.Errorf("expired session still counted")
	}

	s.Arm("sess", armedSession{identity: "condor@example.org"})
	s.Disarm("sess")
	if _, ok := s.Armed("sess"); ok {
		t.Errorf("Disarm did not take effect")
	}

	if _, ok := s.Armed(""); ok {
		t.Errorf("an empty session id must never be armed")
	}
}

// TestSuperuserReasonReplacesCallerText: the reason is the durable record of
// who acted on somebody else's job, so it must lead with that rather than
// with whatever the caller typed.
func TestSuperuserReasonReplacesCallerText(t *testing.T) {
	imp := &Impersonation{Actor: "bob@example.org", Target: "alice@example.org"}

	got := superuserReason(imp, "Held", "because I felt like it")
	if strings.Contains(got, "because I felt like it") {
		t.Errorf("caller text survived into a superuser reason: %q", got)
	}
	if !strings.Contains(got, "bob@example.org") || !strings.Contains(got, "alice@example.org") {
		t.Errorf("reason must name both parties: %q", got)
	}

	// Without an impersonation the caller's own reason is untouched.
	if got := superuserReason(nil, "Held", "because I felt like it"); got != "because I felt like it" {
		t.Errorf("non-superuser reason was modified: %q", got)
	}
}

// TestSuperuserActionContextInertWhenDisabled pins that none of this engages
// on a server where the feature is off: no job lookup, no identity swap.
func TestSuperuserActionContextInertWhenDisabled(t *testing.T) {
	logger, _ := logging.New(&logging.Config{OutputPath: "stderr"})
	h := &Handler{logger: logger, uidDomain: "example.org"} // feature off

	req := httptest.NewRequestWithContext(context.Background(), http.MethodDelete, "/api/v1/jobs/1.0", nil)
	ctx := context.Background()
	gotCtx, imp, err := h.superuserActionContext(ctx, req, 1, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if imp != nil {
		t.Errorf("impersonation created with the feature disabled")
	}
	if gotCtx != ctx {
		t.Errorf("context was replaced with the feature disabled")
	}
}

// TestSuperuserActionContextNeedsArming: being in the group is not enough.
// The mode has to have been turned on, which is what makes it a deliberate
// posture rather than an ambient capability of every admin request.
func TestSuperuserActionContextNeedsArming(t *testing.T) {
	h := superuserTestHandler(t, []string{"condor@example.org"})
	h.superuserArmed = newSuperuserSessions(time.Hour)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodDelete, "/api/v1/jobs/1.0", nil)
	// No session cookie at all: cannot be armed, so nothing happens and no
	// job lookup is attempted (which would fail without a live schedd).
	ctx := context.Background()
	gotCtx, imp, err := h.superuserActionContext(ctx, req, 1, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if imp != nil || gotCtx != ctx {
		t.Errorf("unarmed request produced an impersonation")
	}
}

// TestBulkPlanInertWhenDisabled: bulk actions must be untouched on a server
// where the feature is off -- no owner query, no plan.
func TestBulkPlanInertWhenDisabled(t *testing.T) {
	logger, _ := logging.New(&logging.Config{OutputPath: "stderr"})
	h := &Handler{logger: logger, uidDomain: "example.org"}

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/jobs/hold", nil)
	plans, err := h.planSuperuserBulkAction(context.Background(), req, "JobStatus == 5")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if plans != nil {
		t.Errorf("a plan was produced with the feature disabled: %v", plans)
	}
}

// TestBulkPlanNeedsArming: group membership alone must not engage bulk
// impersonation, for the same reason it does not for single jobs.
func TestBulkPlanNeedsArming(t *testing.T) {
	h := superuserTestHandler(t, []string{"condor@example.org"})
	h.superuserArmed = newSuperuserSessions(time.Hour)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/jobs/hold", nil)
	plans, err := h.planSuperuserBulkAction(context.Background(), req, "JobStatus == 5")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if plans != nil {
		t.Errorf("unarmed request produced a plan")
	}
}

// TestBulkOwnerCapIsMeaningful guards the fan-out limit. Each distinct owner
// costs an impersonation and a schedd round trip, so an unbounded constraint
// on a busy AP must refuse rather than quietly widen.
func TestBulkOwnerCapIsMeaningful(t *testing.T) {
	if maxSuperuserBulkOwners <= 0 {
		t.Fatalf("the owner cap must be positive, got %d", maxSuperuserBulkOwners)
	}
	if maxSuperuserBulkOwners > 100 {
		t.Errorf("owner cap of %d is high enough to be a fan-out hazard", maxSuperuserBulkOwners)
	}
}

// TestArmedStateIsPerSession is the property that matters most about arming:
// it is keyed to one browser session, never process-wide. One operator turning
// the mode on must not change what anybody else's requests do.
func TestArmedStateIsPerSession(t *testing.T) {
	s := newSuperuserSessions(time.Hour)

	s.Arm("alice-session", armedSession{identity: "alice@example.org"})

	if _, ok := s.Armed("alice-session"); !ok {
		t.Errorf("the arming session should be armed")
	}
	if _, ok := s.Armed("bob-session"); ok {
		t.Errorf("arming one session armed another")
	}
	// A second browser for the same human is a different session and is
	// independently unarmed.
	if _, ok := s.Armed("alice-other-browser"); ok {
		t.Errorf("arming leaked across sessions")
	}

	s.Arm("bob-session", armedSession{identity: "condor@example.org"})
	s.Disarm("alice-session")
	b, ok := s.Armed("bob-session")
	if !ok {
		t.Errorf("disarming one session disarmed another")
	}
	// Each session keeps its OWN resolved identity; one operator's
	// fallback must not become another's.
	if b.identity != "condor@example.org" {
		t.Errorf("bob's identity = %q, want its own", b.identity)
	}
	if _, ok := s.Armed("alice-session"); ok {
		t.Errorf("disarm did not take effect")
	}
}

// TestResolveImpersonationIdentityNeedsAUserRec covers the smoothing that the
// integration test forced: being in QUEUE_SUPER_USERS is necessary but not
// sufficient. The schedd's UserCheck2 maps the caller to a JobQueueUserRec
// FIRST and rejects a caller it cannot map, before superuser status is
// consulted at all -- so acting as an admin who has never submitted fails, and
// fails pointing nowhere near the cause. Falling back keeps it working.
func TestResolveImpersonationIdentityNeedsAUserRec(t *testing.T) {
	disabled := false
	enabled := true

	for _, tc := range []struct {
		name         string
		record       *htcondor.UserRecord
		lookupErr    error
		wantIdentity string
		wantAsActor  bool
		wantNote     string // substring
	}{
		{
			name:         "queue superuser with a record acts as themselves",
			record:       &htcondor.UserRecord{User: "bob@example.org", Enabled: &enabled},
			wantIdentity: "bob@example.org",
			wantAsActor:  true,
		},
		{
			name:         "queue superuser with no record falls back",
			record:       nil,
			wantIdentity: "condor@example.org",
			wantNote:     "condor_qusers -add",
		},
		{
			name:         "disabled record falls back and says so",
			record:       &htcondor.UserRecord{User: "bob@example.org", Enabled: &disabled, DisableReason: "on leave"},
			wantIdentity: "condor@example.org",
			wantNote:     "disabled",
		},
		{
			// A schedd blip must not silently downgrade the audit trail;
			// if the record really is missing the action fails loudly.
			name:         "lookup failure still prefers the actor",
			lookupErr:    errors.New("schedd unreachable"),
			wantIdentity: "bob@example.org",
			wantAsActor:  true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := superuserTestHandler(t, []string{"bob@example.org", "condor@example.org"})
			fake := &fakeUserRecords{record: tc.record, err: tc.lookupErr}
			got := h.resolveImpersonationIdentityWith(context.Background(), "bob", fake)

			if got.identity != tc.wantIdentity {
				t.Errorf("identity = %q, want %q", got.identity, tc.wantIdentity)
			}
			if got.actorIsSuperUser != tc.wantAsActor {
				t.Errorf("actorIsSuperUser = %v, want %v", got.actorIsSuperUser, tc.wantAsActor)
			}
			if tc.wantNote == "" && got.note != "" {
				t.Errorf("unexpected note: %s", got.note)
			}
			if tc.wantNote != "" && !strings.Contains(got.note, tc.wantNote) {
				t.Errorf("note %q does not mention %q", got.note, tc.wantNote)
			}
		})
	}
}

// TestResolveIdentityNoteForNonSuperuser: an operator who is simply not a
// queue superuser should be told, since the fix is one config change.
func TestResolveIdentityNoteForNonSuperuser(t *testing.T) {
	h := superuserTestHandler(t, []string{"condor@example.org"})
	got := h.resolveImpersonationIdentityWith(context.Background(), "carol", &fakeUserRecords{})
	if got.identity != "condor@example.org" || got.actorIsSuperUser {
		t.Fatalf("got (%q, %v), want the fallback", got.identity, got.actorIsSuperUser)
	}
	if !strings.Contains(got.note, "QUEUE_SUPER_USERS") {
		t.Errorf("note should explain why: %s", got.note)
	}
}
