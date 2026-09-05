package httpserver

import (
	"context"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/logging"
)

// superuserAuthz is the authorization set on an impersonation token.
//
// READ and WRITE only, deliberately. Queue-superuser status comes from the
// authenticated identity appearing in QUEUE_SUPER_USERS, NOT from the
// ADMINISTRATOR authorization level, so the extra level would buy nothing and
// would turn a leaked impersonation token into one that can reconfigure the
// pool. Same reasoning as mapCondorScopesToAuthz, which drops ADMINISTRATOR,
// CONFIG, DAEMON and NEGOTIATOR from every token this server mints for a user.
var superuserAuthz = []string{"READ", "WRITE"}

// Impersonation describes one superuser action: who asked for it, whose job it
// is, and which identity the server will present to the schedd.
type Impersonation struct {
	// Actor is the authenticated human who armed superuser mode.
	Actor string
	// Target is the job owner being acted for, derived from the job rather
	// than supplied by the caller.
	Target string
	// Identity is what this server authenticates to the schedd as. Either
	// Actor (when they are themselves a queue superuser) or the shared
	// fallback.
	Identity string
	// ActorIsSuperUser records which of those it was. When true the schedd's
	// own log names the human; when false the schedd only ever sees the
	// shared identity and this server's audit record is the only place the
	// actor appears.
	ActorIsSuperUser bool
}

// Reason renders the actor and target into a string suitable for a
// HoldReason / RemoveReason / ReleaseReason.
//
// The schedd appends "(by user <authenticated identity>)" to whatever reason
// it is given -- see actOnJobs in schedd.cpp -- so when the actor is a queue
// superuser the job ad ends up naming them twice, from two independent
// sources. When they are not, the schedd can only append the shared identity,
// and this prefix is the ONLY record in the job ad of which human acted. That
// is why the actor goes in the text rather than being left to the schedd.
//
// The result lands in the job ad, so it outlives this server's logs, follows
// the job into history, and is visible to the job's owner -- who is entitled
// to know that somebody else touched their job, and which somebody.
func (i Impersonation) Reason(what string) string {
	return fmt.Sprintf("%s by %s via the web UI (superuser mode, acting for %s)",
		what, i.Actor, i.Target)
}

// sessionTag is the cedar session-cache key for this impersonation.
//
// Sessions must not be shared across identities. cedar caches an
// authenticated session per {SecurityTag, address, command}, so an untagged
// impersonation would be reachable by an ordinary request -- and worse, an
// ordinary user's cached session could be picked up for a superuser action or
// the reverse. Keying on both ends of the impersonation, and marking it
// distinctly, keeps these connections in their own space.
func (i Impersonation) sessionTag() string {
	return "superuser:" + i.Identity + "->" + i.Target
}

// impersonate prepares a context that will authenticate to the schedd as the
// identity resolved for this actor, for the purpose of acting on target's job.
//
// It returns an error rather than silently falling back to the caller's own
// identity: a superuser action that quietly degrades into "acted as myself"
// would either fail confusingly or, worse, succeed against the wrong job.
func (h *Handler) impersonate(ctx context.Context, actor, target string) (context.Context, *Impersonation, error) {
	if !h.superuserModeAvailable() {
		return nil, nil, fmt.Errorf("superuser mode is not enabled on this server")
	}
	actor = strings.TrimSpace(actor)
	target = strings.TrimSpace(target)
	if actor == "" {
		return nil, nil, fmt.Errorf("no authenticated actor")
	}
	if target == "" {
		return nil, nil, fmt.Errorf("could not determine the job's owner")
	}

	identity, actorIsSuper := h.superuserPolicy.ImpersonationIdentity(actor)
	imp := &Impersonation{
		Actor:            qualifyUser(actor, h.uidDomain),
		Target:           qualifyUser(target, h.uidDomain),
		Identity:         identity,
		ActorIsSuperUser: actorIsSuper,
	}
	if imp.Actor == "" {
		imp.Actor = actor
	}
	if imp.Target == "" {
		imp.Target = target
	}

	token, err := h.mintImpersonationToken(identity)
	if err != nil {
		return nil, nil, fmt.Errorf("minting the impersonation credential: %w", err)
	}

	secConfig, err := htcondor.NewClientSecurityConfig(ctx, token, "", 0, "CLIENT", nil)
	if err != nil {
		return nil, nil, fmt.Errorf("building the impersonation security config: %w", err)
	}
	secConfig.SecurityTag = imp.sessionTag()

	return htcondor.WithSecurityConfig(ctx, secConfig), imp, nil
}

// mintImpersonationToken issues a short-lived IDTOKEN asserting identity,
// narrowed to READ and WRITE.
func (h *Handler) mintImpersonationToken(identity string) (string, error) {
	if h.signingKeyPath == "" || h.trustDomain == "" {
		return "", fmt.Errorf("no pool signing key configured")
	}
	now := time.Now()
	return generateMCPAccessJWT(
		filepath.Dir(h.signingKeyPath),
		filepath.Base(h.signingKeyPath),
		identity,
		h.trustDomain,
		now.Unix(),
		now.Add(condorIDTokenLifetime).Unix(),
		superuserAuthz,
	)
}

// auditSuperuserAction records a superuser action.
//
// Logged at Info and unconditionally, including when the action fails: an
// attempt to act on someone else's job is worth recording whether or not it
// worked, and a failed attempt is often the more interesting one.
//
// This is the only place the actor is recorded when they are not themselves a
// queue superuser, so it is not optional and does not depend on log level.
func (h *Handler) auditSuperuserAction(r *http.Request, imp *Impersonation, action, subject string, err error) {
	fields := []any{
		"actor", imp.Actor,
		"target", imp.Target,
		"authenticated_as", imp.Identity,
		"actor_is_queue_superuser", imp.ActorIsSuperUser,
		"action", action,
		"subject", subject,
		"remote_addr", r.RemoteAddr,
	}
	if err != nil {
		fields = append(fields, "outcome", "failed", "error", err)
	} else {
		fields = append(fields, "outcome", "succeeded")
	}
	h.logger.Info(logging.DestinationSecurity, "Superuser action", fields...)
}
