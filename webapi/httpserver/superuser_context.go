package httpserver

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/PelicanPlatform/classad/classad"

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
	// Project is set when the actor is acting as a project lead rather
	// than as a global superuser: the project, as configured, that grants
	// this impersonation. Empty for global scope.
	Project string
}

// projectScoped reports whether this impersonation rests on project
// leadership rather than global superuser membership.
func (i *Impersonation) projectScoped() bool { return i != nil && i.Project != "" }

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
//
// A project lead's reason names the project, so the owner can tell which
// grant was used and whom to ask about it.
func (i Impersonation) Reason(what string) string {
	if i.Project != "" {
		return fmt.Sprintf("%s by %s via the web UI (project lead for %s, acting for %s)",
			what, i.Actor, i.Project, i.Target)
	}
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

	secConfig, err := htcondor.NewClientSecurityConfigWithConfig(ctx, h.clientConfig, token, "", 0, "CLIENT", nil)
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
		"scope", imp.scopeName(),
		"project", imp.Project,
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

// scopeName is "project" or "global", for audit records.
func (i *Impersonation) scopeName() string {
	if i.projectScoped() {
		return "project"
	}
	return "global"
}

// superuserJobProjection is what superuser mode reads off a job to decide
// whose it is. Deliberately not ProjectName: project membership is decided
// by the schedd evaluating a constraint against the whole ad (see
// jobLedProject), never by this server reading a projected copy.
var superuserJobProjection = []string{"Owner", "User", "ClusterId", "ProcId"}

// queryJobs reads job ads from the schedd, or from jobQueryOverride in tests.
func (h *Handler) queryJobs(ctx context.Context, constraint string, opts *htcondor.QueryOptions) ([]*classad.ClassAd, error) {
	if h.jobQueryOverride != nil {
		return h.jobQueryOverride(ctx, constraint, opts)
	}
	schedd := h.getSchedd()
	if schedd == nil {
		return nil, fmt.Errorf("no schedd configured")
	}
	ads, _, err := schedd.QueryWithOptions(ctx, constraint, opts)
	return ads, err
}

// streamJobs is the job listing's schedd stream, or jobQueryOverride's
// answer delivered the same way in tests.
func (h *Handler) streamJobs(ctx context.Context, constraint string, opts *htcondor.QueryOptions, streamOpts *htcondor.StreamOptions) (<-chan htcondor.JobAdResult, error) {
	if h.jobQueryOverride == nil {
		return h.getSchedd().QueryStreamWithOptions(ctx, constraint, opts, streamOpts)
	}
	ads, err := h.jobQueryOverride(ctx, constraint, opts)
	if err != nil {
		return nil, err
	}
	ch := make(chan htcondor.JobAdResult, len(ads))
	for _, ad := range ads {
		ch <- htcondor.JobAdResult{Ad: ad}
	}
	close(ch)
	return ch, nil
}

// querySuperuserJobs reads jobs for superuser-mode decisions.
func (h *Handler) querySuperuserJobs(ctx context.Context, constraint string, limit int) ([]*classad.ClassAd, error) {
	return h.queryJobs(ctx, constraint, &htcondor.QueryOptions{
		Limit:      limit,
		Projection: superuserJobProjection,
	})
}

// adOwner reads a job's owner, falling back to the User attribute older ads
// may carry alone ("owner@domain").
func adOwner(ad *classad.ClassAd) string {
	if owner, ok := ad.EvaluateAttrString("Owner"); ok && owner != "" {
		return owner
	}
	if user, ok := ad.EvaluateAttrString("User"); ok && user != "" {
		return ownerFromActor(user)
	}
	return ""
}

// jobOwner looks up the Owner of a single job.
//
// The target of an impersonation is derived from the job, never from the
// request: a caller-supplied target would let an admin name any identity they
// liked and have the server authenticate as a superuser on its behalf, which
// is a different and much larger capability than "fix this job".
//
// It returns the Owner and, when the ad has one, the User ("owner@domain").
// errNoSuchOwnedJob marks the two answers that say something about the job
// itself -- there is no such job, or it has no owner -- as opposed to a
// failure to ask.
func (h *Handler) jobOwner(ctx context.Context, cluster, proc int) (owner, user string, err error) {
	ads, err := h.querySuperuserJobs(ctx, fmt.Sprintf("ClusterId == %d && ProcId == %d", cluster, proc), 1)
	if err != nil {
		return "", "", fmt.Errorf("looking up job %d.%d: %w", cluster, proc, err)
	}
	if len(ads) == 0 {
		return "", "", fmt.Errorf("job %d.%d not found: %w", cluster, proc, errNoSuchOwnedJob)
	}
	owner = adOwner(ads[0])
	if owner == "" {
		return "", "", fmt.Errorf("job %d.%d has no owner attribute: %w", cluster, proc, errNoSuchOwnedJob)
	}
	user, _ = ads[0].EvaluateAttrString("User")
	return owner, user, nil
}

// errNoSuchOwnedJob is wrapped by jobOwner when the job does not exist or has
// no owner.
var errNoSuchOwnedJob = errors.New("no such job with an owner")

// errNotInLedProject is the one refusal a project lead gets for a job they
// may not act on, whatever the reason: it does not exist, or it is someone
// else's job outside their projects. One message for both, so probing job
// ids cannot tell a lead which jobs exist or whose they are. The reason
// itself goes to the audit log.
func errNotInLedProject(cluster, proc int) error {
	return fmt.Errorf(
		"job %d.%d is not in a project you lead; as a project lead you may act only on other users' jobs in your projects",
		cluster, proc)
}

// jobLedProject returns which of projects the job is in, as the schedd
// evaluates it, or "" when it is in none of them.
//
// The schedd decides, not this server. ProjectName is an expression like any
// other attribute and may refer to others; evaluating it here would mean
// evaluating a projected copy, where those references are missing, and
// trusting a decision the schedd could make differently. Asking the schedd
// to match the clause is the same decision hold, release and remove then
// re-make atomically in their constraint, and it covers ssh and tail, which
// have no constraint of their own.
//
// One query decides membership; when several projects are led, one more per
// project finds which, for the reason text and the TOCTOU clause.
func (h *Handler) jobLedProject(ctx context.Context, cluster, proc int, projects []string) (string, error) {
	if len(projects) == 0 {
		return "", nil
	}
	job := fmt.Sprintf("ClusterId == %d && ProcId == %d", cluster, proc)
	match := func(candidates []string) (bool, error) {
		c, err := andScope(projectClause(candidates), job)
		if err != nil {
			return false, err
		}
		ads, err := h.queryJobs(ctx, c, &htcondor.QueryOptions{
			Limit:      1,
			Projection: []string{"ClusterId", "ProcId"},
		})
		if err != nil {
			return false, fmt.Errorf("checking the project of job %d.%d: %w", cluster, proc, err)
		}
		return len(ads) > 0, nil
	}
	in, err := match(projects)
	if err != nil || !in {
		return "", err
	}
	if len(projects) == 1 {
		return projects[0], nil
	}
	for _, p := range projects {
		in, err := match([]string{p})
		if err != nil {
			return "", err
		}
		if in {
			return p, nil
		}
	}
	// In the set but in none of its members: the job moved between the
	// queries. Treat it as outside.
	return "", nil
}

// auditProjectLeadRefusal records a project lead being refused, at Info and
// unconditionally, like a superuser action: an attempt on a job outside the
// lead's grant is the event an audit most needs to show.
func (h *Handler) auditProjectLeadRefusal(r *http.Request, actor, subject, reason string) {
	h.logger.Info(logging.DestinationSecurity, "Project lead refused",
		"actor", actor,
		"subject", subject,
		"reason", reason,
		"remote_addr", r.RemoteAddr)
}

// refuseProjectLeadTarget is the check a project lead's impersonation of
// owner must pass beyond project membership: owner must not be a queue
// superuser or the fallback identity. Returns the refusal, or nil.
func (h *Handler) refuseProjectLeadTarget(owner, user string) error {
	privileged, known := h.superuserPolicy.privilegedTarget(owner, user)
	switch {
	case !known:
		return fmt.Errorf("cannot act as a project lead yet: the schedd's queue superusers have not been read, so it is not known whether this job's owner is one")
	case privileged:
		return fmt.Errorf("project leads cannot act on jobs owned by a queue superuser or by this server's own identity")
	}
	return nil
}

// armedSuperuser is the shared prologue of every superuser-mode decision:
// is the feature on, is this a session, is it armed, and what may it do now.
//
// ok=false means superuser mode is not engaged and the request should
// proceed normally. A non-nil error means it WAS engaged and the session has
// since lost the right to use it -- removed from the leads file or the
// group after arming. That disarms the session and fails the request rather
// than quietly proceeding as the caller: the operator believes the mode is
// on, and an action that silently ran as themselves instead would be a
// surprise in one direction or the other.
func (h *Handler) armedSuperuser(r *http.Request) (armedSession, superuserScope, *SessionData, bool, error) {
	if !h.superuserModeAvailable() {
		return armedSession{}, superuserScope{}, nil, false, nil
	}
	sessionID, err := getSessionCookie(r)
	if err != nil {
		return armedSession{}, superuserScope{}, nil, false, nil
	}
	armed, isArmed := h.superuserArmed.Armed(sessionID)
	if !isArmed {
		return armedSession{}, superuserScope{}, nil, false, nil
	}
	session, ok := h.getSessionFromRequest(r)
	if !ok {
		return armedSession{}, superuserScope{}, nil, false, nil
	}
	scope := effectiveSuperuserScope(armed, h.superuserScopeFor(session))
	if !scope.allowed() {
		h.superuserArmed.Disarm(sessionID)
		h.logger.Info(logging.DestinationSecurity,
			"Superuser mode disarmed: the session is no longer permitted to use it",
			"actor", session.Username, "remote_addr", r.RemoteAddr)
		return armedSession{}, superuserScope{}, nil, false, fmt.Errorf(
			"superuser mode has been turned off: you are no longer permitted to use it")
	}
	return armed, scope, session, true, nil
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
//
// Project scope adds one rule: another user's job must carry a ProjectName
// the actor leads, re-checked against the configuration now rather than at
// arming. A job in some other project, or in none, is refused outright.
// Falling back to acting as the caller would be the wrong failure: the
// operator is in a mode where their clicks reach other people's jobs, and an
// action that quietly ran as themselves would look like it had worked.
func (h *Handler) superuserActionContext(ctx context.Context, r *http.Request, cluster, proc int) (context.Context, *Impersonation, error) {
	armed, scope, session, ok, err := h.armedSuperuser(r)
	if err != nil {
		return nil, nil, err
	}
	if !ok {
		return ctx, nil, nil
	}

	subject := fmt.Sprintf("%d.%d", cluster, proc)
	owner, user, err := h.jobOwner(ctx, cluster, proc)
	if err != nil {
		if !scope.Global && errors.Is(err, errNoSuchOwnedJob) {
			h.auditProjectLeadRefusal(r, session.Username, subject, err.Error())
			return nil, nil, errNotInLedProject(cluster, proc)
		}
		return nil, nil, err
	}
	if strings.EqualFold(ownerFromActor(owner), ownerFromActor(session.Username)) {
		// The caller's own job. No impersonation, no audit entry.
		return ctx, nil, nil
	}

	ledProject := ""
	if !scope.Global {
		ledProject, err = h.jobLedProject(ctx, cluster, proc, scope.Projects)
		if err != nil {
			return nil, nil, err
		}
		if ledProject == "" {
			// Neither the owner nor the project is named in the
			// refusal: a lead has no business learning either for a
			// job outside their projects, and probing job ids one by
			// one should not tell them.
			h.auditProjectLeadRefusal(r, session.Username, subject, "job is not in a project the actor leads")
			return nil, nil, errNotInLedProject(cluster, proc)
		}
		if refusal := h.refuseProjectLeadTarget(owner, user); refusal != nil {
			h.auditProjectLeadRefusal(r, session.Username, subject, refusal.Error())
			return nil, nil, refusal
		}
	}

	impCtx, imp, err := h.impersonate(ctx, armed, session.Username, owner)
	if err != nil {
		return nil, nil, err
	}
	imp.Project = ledProject
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
// Project scope never reads the caller's constraint unscoped. It plans from
// one query for the caller's own jobs and one per led project, each with the
// scoping clause ANDed in front, so the schedd decides which jobs are in
// which project and a job outside them is never read, planned or acted on.
// Other users' jobs are batched per (owner, project), and each batch's
// constraint carries its project clause: the schedd re-applies it when it
// acts, so a job moved out of the project after planning is not touched, and
// each batch's reason names the one project that granted it.
//
// Returns a nil plan when superuser mode is not engaged, in which case the
// caller proceeds normally.
func (h *Handler) planSuperuserBulkAction(ctx context.Context, r *http.Request, constraint string) ([]superuserBulkPlan, error) {
	armed, scope, session, ok, err := h.armedSuperuser(r)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil
	}
	actorOwner := ownerFromActor(session.Username)

	// One batch per owner, and for project scope per (owner, project).
	type batchKey struct{ owner, project string }
	counts := make(map[batchKey]int)
	var order []batchKey
	owners := make(map[string]bool)
	scanned := 0

	// collect reads one planning query into batches. project is "" for
	// the caller's own jobs and for global scope.
	collect := func(planConstraint, project string) error {
		// Bounded deliberately. Resolving owners means reading every
		// matching job, and a bulk constraint on a busy access point can
		// match a great many. Hitting the bound always means the
		// constraint is too broad to plan safely rather than that the
		// answer was silently truncated.
		ads, err := h.querySuperuserJobs(ctx, planConstraint, maxSuperuserBulkJobsScanned)
		if err != nil {
			return fmt.Errorf("resolving the owners of the matching jobs: %w", err)
		}
		scanned += len(ads)
		if len(ads) >= maxSuperuserBulkJobsScanned || scanned >= maxSuperuserBulkJobsScanned {
			return fmt.Errorf(
				"this constraint matches at least %d jobs, too many to plan a superuser bulk action over; narrow it",
				maxSuperuserBulkJobsScanned)
		}
		for _, ad := range ads {
			owner := adOwner(ad)
			if owner == "" {
				return fmt.Errorf("a matching job has no owner attribute; narrow the constraint")
			}
			key := batchKey{owner: owner}
			if project != "" {
				if strings.EqualFold(owner, actorOwner) {
					// Planned already, by the own-jobs query.
					continue
				}
				key.project = project
				// Checked per job rather than per batch: User is read
				// off each ad, and a privileged owner anywhere in scope
				// refuses the whole action rather than quietly
				// skipping their jobs.
				user, _ := ad.EvaluateAttrString("User")
				if refusal := h.refuseProjectLeadTarget(owner, user); refusal != nil {
					h.auditProjectLeadRefusal(r, session.Username, planConstraint, refusal.Error())
					return refusal
				}
			}
			if _, seen := counts[key]; !seen {
				order = append(order, key)
			}
			counts[key]++
			owners[strings.ToLower(owner)] = true
		}
		return nil
	}

	if scope.Global {
		if err := collect(constraint, ""); err != nil {
			return nil, err
		}
	} else {
		own, err := scopeToOwner(actorOwner, constraint)
		if err != nil {
			return nil, err
		}
		if err := collect(own, ""); err != nil {
			return nil, err
		}
		for _, project := range scope.Projects {
			inProject, err := scopeToProjects([]string{project}, constraint)
			if err != nil {
				return nil, err
			}
			if err := collect(inProject, project); err != nil {
				return nil, err
			}
		}
	}

	if len(order) == 0 {
		// Nothing this mode could act on matches. Let the normal path
		// run: it acts as the caller, so the schedd confines it to their
		// own jobs exactly as it would with the mode off.
		return nil, nil
	}
	if len(owners) > maxSuperuserBulkOwners {
		return nil, fmt.Errorf(
			"this constraint spans %d job owners, more than the limit of %d for a superuser bulk action; narrow it",
			len(owners), maxSuperuserBulkOwners)
	}

	plans := make([]superuserBulkPlan, 0, len(order))
	for _, key := range order {
		batch := constraint
		if key.project != "" {
			if batch, err = scopeToProjects([]string{key.project}, constraint); err != nil {
				return nil, err
			}
		}
		scoped, err := scopeToOwner(key.owner, batch)
		if err != nil {
			return nil, fmt.Errorf("scoping the constraint to %s: %w", key.owner, err)
		}
		if strings.EqualFold(key.owner, actorOwner) {
			// The operator's own jobs. No impersonation and no audit
			// entry -- acting on your own work is not a use of privilege.
			plans = append(plans, superuserBulkPlan{Constraint: scoped, Jobs: counts[key]})
			continue
		}
		_, imp, err := h.impersonate(ctx, armed, session.Username, key.owner)
		if err != nil {
			return nil, err
		}
		imp.Project = key.project
		plans = append(plans, superuserBulkPlan{Imp: imp, Constraint: scoped, Jobs: counts[key]})
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
//
// For a project lead the project clause goes in too. The lead's authority was
// checked against the job's ProjectName a moment ago, but the owner can change
// that attribute at any time; with the clause in the constraint the schedd
// re-checks it atomically as it acts, so a job moved out of the project in
// between matches nothing instead of being acted on.
func (h *Handler) scopeForImpersonation(imp *Impersonation, cluster, proc int) (string, error) {
	job := fmt.Sprintf("ClusterId == %d && ProcId == %d", cluster, proc)
	if imp.projectScoped() {
		var err error
		if job, err = scopeToProjects([]string{imp.Project}, job); err != nil {
			return "", err
		}
	}
	return scopeToOwner(ownerFromActor(imp.Target), job)
}

// refuseProjectLeadInteractiveApp is the policy that keeps project leads out
// of other users' browser-proxied apps (code-server and anything else served
// through the job proxy). Returns a non-nil error when imp must be refused.
//
// The proxied app is served on this server's own origin, so whatever the job
// sends back -- and the job owner controls all of it -- runs in the lead's
// browser with the lead's session cookie and can call this API as them. For
// a project lead that is an escalation path from project member to project
// lead. A global superuser is not given anything by the same trick that they
// did not already hold, so they keep access.
//
// One function on purpose: once apps are served from an isolated origin this
// is the single check to lift.
func refuseProjectLeadInteractiveApp(imp *Impersonation) error {
	if !imp.projectScoped() {
		return nil
	}
	return fmt.Errorf(
		"project leads cannot open another user's interactive app: it is served from this site's own origin, " +
			"so the job's owner would control code running in your browser session. Use the terminal or output tail instead")
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
