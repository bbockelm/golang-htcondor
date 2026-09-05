package httpserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

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
		&fakeSuperUsers{users: superUsers}, "example.org", time.Hour, logger)
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

	if _, _, err := h.impersonate(ctx, "", "alice"); err == nil {
		t.Errorf("expected an error with no actor")
	}
	if _, _, err := h.impersonate(ctx, "bob", ""); err == nil {
		t.Errorf("expected an error with no target")
	}
}

func TestImpersonateRefusedWhenDisabled(t *testing.T) {
	logger, _ := logging.New(&logging.Config{OutputPath: "stderr"})
	h := &Handler{logger: logger, uidDomain: "example.org"} // no group, no policy
	if _, _, err := h.impersonate(context.Background(), "bob", "alice"); err == nil {
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

	if armed, _ := s.Armed("sess"); armed {
		t.Errorf("a fresh session must not be armed")
	}
	s.Arm("sess")
	if armed, _ := s.Armed("sess"); !armed {
		t.Errorf("session should be armed after Arm")
	}
	if s.Count() != 1 {
		t.Errorf("Count = %d, want 1", s.Count())
	}

	// Auto-disarm: an admin who walks away must not leave the mode on.
	time.Sleep(80 * time.Millisecond)
	if armed, _ := s.Armed("sess"); armed {
		t.Errorf("session should have disarmed itself")
	}
	if s.Count() != 0 {
		t.Errorf("expired session still counted")
	}

	s.Arm("sess")
	s.Disarm("sess")
	if armed, _ := s.Armed("sess"); armed {
		t.Errorf("Disarm did not take effect")
	}

	if armed, _ := s.Armed(""); armed {
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

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/jobs/1.0", nil)
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

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/jobs/1.0", nil)
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
