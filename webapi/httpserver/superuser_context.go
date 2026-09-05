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
func (h *Handler) impersonate(ctx context.Context, armed armedSession, actor, target string) (context.Context, *Impersonation, error) {
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

	imp := &Impersonation{
		Actor:            qualifyUser(actor, h.uidDomain),
		Target:           qualifyUser(target, h.uidDomain),
		Identity:         armed.identity,
		ActorIsSuperUser: armed.actorIsSuperUser,
	}
	identity := armed.identity
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

// jobOwner looks up the Owner of a single job.
//
// The target of an impersonation is derived from the job, never from the
// request: a caller-supplied target would let an admin name any identity they
// liked and have the server authenticate as a superuser on its behalf, which
// is a different and much larger capability than "fix this job".
func (h *Handler) jobOwner(ctx context.Context, cluster, proc int) (string, error) {
	constraint := fmt.Sprintf("ClusterId == %d && ProcId == %d", cluster, proc)
	ads, _, err := h.getSchedd().QueryWithOptions(ctx, constraint, &htcondor.QueryOptions{
		Limit:      1,
		Projection: []string{"Owner", "User", "ClusterId", "ProcId"},
	})
	if err != nil {
		return "", fmt.Errorf("looking up job %d.%d: %w", cluster, proc, err)
	}
	if len(ads) == 0 {
		return "", fmt.Errorf("job %d.%d not found", cluster, proc)
	}
	if owner, ok := ads[0].EvaluateAttrString("Owner"); ok && owner != "" {
		return owner, nil
	}
	// Older ads may only carry User ("owner@domain").
	if user, ok := ads[0].EvaluateAttrString("User"); ok && user != "" {
		return ownerFromActor(user), nil
	}
	return "", fmt.Errorf("job %d.%d has no owner attribute", cluster, proc)
}

// superuserActionContext decides whether a single-job action should run as
// somebody else, and if so prepares the context for it.
//
// Returns the original context and a nil Impersonation when the action should
// proceed normally: superuser mode off, not armed, caller not permitted, or
// the job already belongs to the caller. Acting on your own job is never an
// impersonation even with the mode armed -- routing it through one would
// muddy the audit trail with entries that record no privilege being used.
//
// An error means the action must not proceed. In particular a failure to
// determine the owner is fatal rather than a fallback to acting as the
// caller, because "we could not tell whose job this is" is not a good reason
// to try it as somebody.
func (h *Handler) superuserActionContext(ctx context.Context, r *http.Request, cluster, proc int) (context.Context, *Impersonation, error) {
	if !h.superuserModeAvailable() || !h.mayUseSuperuserMode(r) {
		return ctx, nil, nil
	}
	sessionID, err := getSessionCookie(r)
	if err != nil {
		return ctx, nil, nil
	}
	armed, isArmed := h.superuserArmed.Armed(sessionID)
	if !isArmed {
		return ctx, nil, nil
	}
	session, ok := h.getSessionFromRequest(r)
	if !ok {
		return ctx, nil, nil
	}

	owner, err := h.jobOwner(ctx, cluster, proc)
	if err != nil {
		return nil, nil, err
	}
	if strings.EqualFold(ownerFromActor(owner), ownerFromActor(session.Username)) {
		// The caller's own job. No impersonation, no audit entry.
		return ctx, nil, nil
	}

	impCtx, imp, err := h.impersonate(ctx, armed, session.Username, owner)
	if err != nil {
		return nil, nil, err
	}
	return impCtx, imp, nil
}

// superuserReason returns the reason string to send with an action, and the
// impersonation it belongs to. When imp is nil the caller's own reason is
// used unchanged.
func superuserReason(imp *Impersonation, what, fallback string) string {
	if imp == nil {
		return fallback
	}
	return imp.Reason(what)
}

// maxSuperuserBulkOwners caps how many distinct job owners one bulk action may
// span.
//
// Each owner costs its own impersonation and its own schedd round trip, so an
// unbounded constraint ("JobStatus == 5") on a busy access point could fan out
// to hundreds. The cap turns that into a refusal the operator can see and
// narrow, rather than a request that appears to hang while quietly acting on
// an ever-widening set of other people's jobs.
const maxSuperuserBulkOwners = 25

// maxSuperuserBulkJobsScanned bounds the owner-resolution read that precedes a
// bulk action. Reaching it is treated as "too broad to plan", not as a page to
// continue from: acting on a truncated view would apply the action to some of
// the matching jobs and silently not to others.
const maxSuperuserBulkJobsScanned = 10000

// superuserBulkPlan is one owner's share of a bulk action.
type superuserBulkPlan struct {
	// Imp is nil for the actor's own jobs, which are acted on normally.
	Imp *Impersonation
	// Constraint is the caller's constraint narrowed to this owner, so each
	// batch acts only on the jobs the impersonation was granted for.
	Constraint string
	// Jobs is how many jobs matched for this owner, for the audit record.
	Jobs int
}

// planSuperuserBulkAction splits a bulk constraint into per-owner batches.
//
// Bulk is the one place where "derive the target from the job" needs work:
// there is no single job, and a constraint can span any number of owners.
// Resolving the owners first and then acting once per owner preserves the
// property that matters -- every impersonation is for a specific identity that
// was read off a real job, and every job acted on belongs to the identity the
// server authenticated as. The alternative, acting once as a superuser across
// everything, would be a single unbounded grant with one audit line.
//
// Returns a nil plan when superuser mode is not engaged, in which case the
// caller proceeds normally.
func (h *Handler) planSuperuserBulkAction(ctx context.Context, r *http.Request, constraint string) ([]superuserBulkPlan, error) {
	if !h.superuserModeAvailable() || !h.mayUseSuperuserMode(r) {
		return nil, nil
	}
	sessionID, err := getSessionCookie(r)
	if err != nil {
		return nil, nil
	}
	armed, isArmed := h.superuserArmed.Armed(sessionID)
	if !isArmed {
		return nil, nil
	}
	session, ok := h.getSessionFromRequest(r)
	if !ok {
		return nil, nil
	}

	// Bounded deliberately. Resolving owners means reading every matching
	// job, and a bulk constraint on a busy access point can match a great
	// many; an unlimited read here would be the most expensive thing in the
	// request. The limit is one job past what the owner cap could possibly
	// need, so hitting it always means the constraint is too broad to plan
	// safely rather than that the answer was silently truncated.
	ads, _, err := h.getSchedd().QueryWithOptions(ctx, constraint, &htcondor.QueryOptions{
		Limit:      maxSuperuserBulkJobsScanned,
		Projection: []string{"Owner", "User", "ClusterId", "ProcId"},
	})
	if err != nil {
		return nil, fmt.Errorf("resolving the owners of the matching jobs: %w", err)
	}
	if len(ads) >= maxSuperuserBulkJobsScanned {
		return nil, fmt.Errorf(
			"this constraint matches at least %d jobs, too many to plan a superuser bulk action over; narrow it",
			maxSuperuserBulkJobsScanned)
	}
	if len(ads) == 0 {
		// Nothing matches. Let the normal path run and report zero.
		return nil, nil
	}

	counts := make(map[string]int)
	var order []string
	for _, ad := range ads {
		owner, ok := ad.EvaluateAttrString("Owner")
		if !ok || owner == "" {
			if user, ok := ad.EvaluateAttrString("User"); ok && user != "" {
				owner = ownerFromActor(user)
			}
		}
		if owner == "" {
			return nil, fmt.Errorf("a matching job has no owner attribute; narrow the constraint")
		}
		if _, seen := counts[owner]; !seen {
			order = append(order, owner)
		}
		counts[owner]++
	}

	if len(order) > maxSuperuserBulkOwners {
		return nil, fmt.Errorf(
			"this constraint spans %d job owners, more than the limit of %d for a superuser bulk action; narrow it",
			len(order), maxSuperuserBulkOwners)
	}

	actorOwner := ownerFromActor(session.Username)
	plans := make([]superuserBulkPlan, 0, len(order))
	for _, owner := range order {
		scoped, err := scopeToOwner(owner, constraint)
		if err != nil {
			return nil, fmt.Errorf("scoping the constraint to %s: %w", owner, err)
		}
		if strings.EqualFold(owner, actorOwner) {
			// The operator's own jobs. No impersonation and no audit
			// entry -- acting on your own work is not a use of privilege.
			plans = append(plans, superuserBulkPlan{Constraint: scoped, Jobs: counts[owner]})
			continue
		}
		_, imp, err := h.impersonate(ctx, armed, session.Username, owner)
		if err != nil {
			return nil, err
		}
		plans = append(plans, superuserBulkPlan{Imp: imp, Constraint: scoped, Jobs: counts[owner]})
	}
	return plans, nil
}

// scopeForImpersonation rebuilds a single-job constraint for an impersonated
// action.
//
// The handlers owner-scope their constraint before they know whether this is a
// superuser action, and that scoping confines it to the CALLER's jobs -- which
// is exactly backwards once we are acting for somebody else. Left alone it
// produces a constraint that matches nothing, and the schedd dutifully reports
// that it acted on zero jobs: the action silently does nothing rather than
// failing in a way anyone would notice. The integration test caught this;
// none of the unit tests could, because they never reach a schedd.
//
// Re-scoping to the target rather than dropping the clause keeps the second
// layer: we act only on jobs belonging to the identity we resolved off the job
// and authenticated for.
func (h *Handler) scopeForImpersonation(imp *Impersonation, cluster, proc int) (string, error) {
	return scopeToOwner(ownerFromActor(imp.Target),
		fmt.Sprintf("ClusterId == %d && ProcId == %d", cluster, proc))
}

// resolveImpersonationIdentity works out which identity this operator's
// actions should carry, and whether it will actually work.
//
// Being in QUEUE_SUPER_USERS is necessary but NOT sufficient. The schedd's
// UserCheck2 first maps the caller to a JobQueueUserRec and rejects a caller
// it cannot map with "anonymous user not permitted" -- before it consults
// superuser status at all. An administrator who is a queue superuser but has
// never submitted a job has no such record, so acting as them fails, and fails
// with a message that points nowhere near the cause.
//
// Rather than let that surface as a mysterious "the action did nothing", check
// for the record here and fall back to the shared identity when it is missing.
// The cost is audit fidelity, not function: the schedd will name the shared
// account instead of the human, and the human's name survives only in this
// server's audit log and in the reason written into the job. The note explains
// that trade to the operator, along with how to fix it.
//
// Done at arm time because it needs a schedd round trip, and arming is rare
// while actions are not.
func (h *Handler) resolveImpersonationIdentity(ctx context.Context, actor string) armedSession {
	schedd := h.getSchedd()
	if schedd == nil {
		identity, isSuper := h.superuserPolicy.ImpersonationIdentity(actor)
		return armedSession{identity: identity, actorIsSuperUser: isSuper}
	}
	return h.resolveImpersonationIdentityWith(ctx, actor, schedd)
}

// resolveImpersonationIdentityWith is resolveImpersonationIdentity with the
// user-record lookup injected, so the fallback rules are testable without a
// live schedd. See UserRecordLookup.
func (h *Handler) resolveImpersonationIdentityWith(ctx context.Context, actor string, lookup UserRecordLookup) armedSession {
	identity, actorIsSuper := h.superuserPolicy.ImpersonationIdentity(actor)
	if !actorIsSuper {
		// Already the shared identity; nothing further to check. Whether
		// the operator would PREFER to act as themselves is worth saying,
		// since the fix is one command.
		return armedSession{
			identity: identity,
			note: fmt.Sprintf(
				"Acting as %s: %s is not in the schedd's QUEUE_SUPER_USERS. "+
					"Actions will be attributed to the shared account by the schedd; "+
					"your name is recorded in the audit log and in each job's reason.",
				identity, actor),
		}
	}

	qualified := qualifyUser(actor, h.uidDomain)
	if lookup == nil {
		return armedSession{identity: identity, actorIsSuperUser: true}
	}

	lookupCtx, cancel := context.WithTimeout(ctx, oracleTimeout)
	defer cancel()
	record, err := lookup.GetUserRecord(lookupCtx, qualified)
	switch {
	case err != nil:
		// Could not tell. Prefer the actor anyway: they are a queue
		// superuser, the record probably exists, and a schedd blip should
		// not silently downgrade the audit trail. If it turns out to be
		// missing the action fails loudly rather than doing the wrong
		// thing quietly.
		h.logger.Warn(logging.DestinationSecurity,
			"Could not confirm the operator's schedd user record; acting as them anyway",
			"actor", qualified, "error", err)
		return armedSession{identity: identity, actorIsSuperUser: true}
	case record == nil:
		return armedSession{
			identity: h.superuserPolicy.fallback,
			note: fmt.Sprintf(
				"Acting as %s rather than %s: the schedd has no user record for you, "+
					"so it would refuse the action outright. Run `condor_qusers -add %s` "+
					"on the access point to have your own name recorded by the schedd.",
				h.superuserPolicy.fallback, qualified, qualified),
		}
	case record.IsDisabled():
		// A disabled operator is a strange state to act from, and the
		// schedd may well refuse. Say so rather than proceed silently.
		return armedSession{
			identity: h.superuserPolicy.fallback,
			note: fmt.Sprintf(
				"Acting as %s rather than %s: your user record on the access point is "+
					"disabled (%s).", h.superuserPolicy.fallback, qualified, record.DisableReason),
		}
	default:
		return armedSession{identity: identity, actorIsSuperUser: true}
	}
}
