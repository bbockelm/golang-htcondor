package httpserver

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/logging"
)

// defaultSuperuserRefresh is how often the queue-superuser set is re-read.
// QUEUE_SUPER_USERS changes at the pace of an admin editing a config file and
// running condor_reconfig, so this only has to be faster than "an operator
// notices it didn't take effect".
const defaultSuperuserRefresh = 15 * time.Minute

// queueSuperUserSource is the slice of the schedd client the policy needs.
// Narrow so the identity logic can be tested without a live daemon.
type queueSuperUserSource interface {
	QueueSuperUsers(ctx context.Context) ([]string, error)
}

// superuserPolicy caches the schedd's QUEUE_SUPER_USERS set and answers the
// one question superuser mode asks of it: which identity should this server
// authenticate as when acting on another user's behalf?
//
// The set is polled — at startup and on an interval — and NEVER on the path of
// an action. Two reasons. It would put a schedd round trip inside every job
// operation, on a value that changes about as often as the config file does;
// and it would make an admin's ability to act depend on the schedd being
// reachable at that instant, turning a transient blip into an authorization
// failure that looks like a permissions bug.
//
// The cost of caching is bounded and in the safe direction: an admin newly
// added to QUEUE_SUPER_USERS keeps acting as the fallback identity until the
// next refresh, which loses audit fidelity, not safety. An admin REMOVED from
// QUEUE_SUPER_USERS also keeps acting until the next refresh — but the schedd
// re-checks superuser status itself on every connection, so a stale cache
// there produces a failed action, not an unauthorized one. The schedd remains
// the enforcement point; this cache only chooses which identity to present.
type superuserPolicy struct {
	source    queueSuperUserSource
	uidDomain string
	// fallback is the identity used when the actor is not a known queue
	// superuser, or when the set could not be read.
	//
	// "condor@<UID_DOMAIN>" is the right answer for a schedd running as the
	// condor user, because real_owner_is_condor recognises the daemon's own
	// OS user. It is only right for THAT arrangement: a personal condor
	// disables that branch entirely (personal_condor = !is_root()), so the
	// equivalent identity there is the user the pool runs as. Hence the
	// knob -- see HandlerConfig.SuperuserFallbackIdentity.
	fallback string
	refresh  time.Duration
	logger   *logging.Logger

	mu        sync.RWMutex
	users     map[string]bool
	fetchedAt time.Time
	lastErr   error
}

// newSuperuserPolicy builds a policy. A zero refresh interval selects
// defaultSuperuserRefresh.
func newSuperuserPolicy(source queueSuperUserSource, uidDomain, fallback string, refresh time.Duration, logger *logging.Logger) *superuserPolicy {
	if refresh <= 0 {
		refresh = defaultSuperuserRefresh
	}
	if strings.TrimSpace(fallback) == "" {
		fallback = qualifyUser("condor", uidDomain)
	} else {
		fallback = qualifyUser(strings.TrimSpace(fallback), uidDomain)
	}
	return &superuserPolicy{
		source:    source,
		uidDomain: uidDomain,
		fallback:  fallback,
		refresh:   refresh,
		logger:    logger,
	}
}

// Refresh re-reads the queue-superuser set. An error leaves the previous set
// in place: a schedd that is briefly unreachable should not silently demote
// every admin to the fallback identity.
func (p *superuserPolicy) Refresh(ctx context.Context) error {
	users, err := p.source.QueueSuperUsers(ctx)
	p.mu.Lock()
	defer p.mu.Unlock()
	p.lastErr = err
	if err != nil {
		if p.logger != nil {
			p.logger.Warn(logging.DestinationHTTP,
				"Could not read the schedd's queue superusers; keeping the previous set",
				"error", err, "known", len(p.users))
		}
		return err
	}
	set := make(map[string]bool, len(users))
	for _, u := range users {
		if u = strings.TrimSpace(u); u != "" {
			set[strings.ToLower(u)] = true
		}
	}
	p.users = set
	p.fetchedAt = time.Now()
	if p.logger != nil {
		p.logger.Info(logging.DestinationHTTP, "Refreshed the schedd's queue superusers",
			"count", len(set))
	}
	return nil
}

// Run polls until ctx is cancelled. The first poll happens immediately so a
// server that has just started does not spend a whole interval with no idea
// who the superusers are.
func (p *superuserPolicy) Run(ctx context.Context) {
	_ = p.Refresh(ctx)
	ticker := time.NewTicker(p.refresh)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = p.Refresh(ctx)
		}
	}
}

// ImpersonationIdentity returns the identity this server should authenticate
// as in order to act on behalf of someone else, and whether that identity is
// the actor themselves.
//
// Preferring the actor when they are themselves a queue superuser is what
// keeps the schedd's own audit trail honest: the schedd logs
// "real=<actor> ... allowed to set effective to <target>", naming the actual
// human. Falling back to a shared identity still works, but the schedd then
// only ever sees that shared identity, and the record of WHO acted exists
// solely in this server's logs and in the reason strings it writes.
//
// Reads the cache only; it never contacts the schedd.
func (p *superuserPolicy) ImpersonationIdentity(actor string) (identity string, actorIsSuperUser bool) {
	qualified := qualifyUser(actor, p.uidDomain)
	if qualified == "" {
		return p.fallback, false
	}

	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.users == nil {
		// Never successfully read. Use the fallback rather than guessing
		// at the schedd's compiled-in default.
		return p.fallback, false
	}
	if p.users[strings.ToLower(qualified)] {
		return qualified, true
	}
	// Also accept the bare form: QUEUE_SUPER_USERS may name "bob" while
	// the actor authenticated as "bob@domain", and QueueSuperUsers returns
	// both forms, but an actor who authenticated bare should still match a
	// qualified entry.
	if bare := strings.SplitN(qualified, "@", 2)[0]; p.users[strings.ToLower(bare)] {
		return qualified, true
	}
	return p.fallback, false
}

// Status reports what the policy currently knows, for the admin UI and for
// answering "why is this being done as condor?".
func (p *superuserPolicy) Status() (count int, fetchedAt time.Time, lastErr error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.users), p.fetchedAt, p.lastErr
}

// initSuperuserMode configures superuser mode from cfg, or leaves it off.
//
// The feature needs two independent things and refuses to run on one of them:
//
//   - somebody it is gated on, so that "may act as another user" is a
//     decision an operator made rather than a side effect of admin-UI
//     access: HTTP_API_SUPERUSER_GROUP for global scope, or project leads
//     (HTTP_API_PROJECT_LEADS_FILE / HTTP_API_PROJECT_LEADS_GROUP) for
//     project scope. Either alone is enough;
//   - a pool signing key, because acting as another identity means minting a
//     credential for it. Without the key there is nothing to mint and the
//     feature cannot work, so a deployment that sets the group but has no key
//     is misconfigured rather than partially enabled.
//
// Both states are logged: silently doing nothing here would leave an operator
// who set the group wondering why the UI never offers the mode.
func (h *Handler) initSuperuserMode(cfg HandlerConfig, logger *logging.Logger) {
	group := strings.TrimSpace(cfg.SuperuserGroup)
	// Always present, so a reconfigure can install a list without a nil
	// check, but empty until the feature is known to be usable: an
	// installed group is what the rest of the server reads as "superuser
	// mode is on".
	h.superuserGroups = newGroupSet("")
	// The leads are kept even when the mode cannot run. They also widen
	// what a lead may READ (projectLeadReadProjects), which needs no
	// signing key.
	h.projectLeads = newProjectLeads(cfg.ProjectLeadsFile, cfg.ProjectLeadsGroup, h.uidDomain, logger)
	leads := h.projectLeads.configured()

	if group == "" && !leads {
		logger.Info(logging.DestinationHTTP,
			"Superuser mode disabled (HTTP_API_SUPERUSER_GROUP and project leads are unset)")
		return
	}
	if h.signingKeyPath == "" || h.trustDomain == "" {
		logger.Warn(logging.DestinationHTTP,
			"Superuser mode is configured but cannot run: it needs a pool signing key and trust domain to mint the identity it acts under",
			"superuser_group", group,
			"project_leads", leads,
			"signing_key_path", h.signingKeyPath,
			"trust_domain", h.trustDomain)
		return
	}

	h.superuserGroups.set(group)
	h.superuserArmed = newSuperuserSessions(cfg.SuperuserArmTTL)
	h.superuserPolicy = newSuperuserPolicy(
		scheddSuperUserSource{get: h.getSchedd},
		h.uidDomain,
		cfg.SuperuserFallbackIdentity,
		cfg.SuperuserRefreshInterval,
		logger,
	)
	logger.Info(logging.DestinationHTTP, "Superuser mode enabled",
		"superuser_group", group,
		"project_leads_file", strings.TrimSpace(cfg.ProjectLeadsFile),
		"project_leads_group", strings.TrimSpace(cfg.ProjectLeadsGroup),
		"fallback_identity", h.superuserPolicy.fallback,
		"queue_superuser_refresh", h.superuserPolicy.refresh,
		"arm_ttl", h.superuserArmed.ttl)
}

// superuserModeAvailable reports whether the feature is configured at all.
// It says nothing about whether a given caller may use it.
func (h *Handler) superuserModeAvailable() bool {
	return h.superuserPolicy != nil && h.superuserArmed != nil &&
		(h.superuserGroups.configured() || h.projectLeads.configured())
}

// globalSuperuser reports whether groups grant global superuser scope.
//
// grants, not allows, is load-bearing. groupSet.allows treats an empty list
// as "no requirement" and admits everybody, which is right for access groups
// and catastrophically wrong here: with only project leads configured,
// HTTP_API_SUPERUSER_GROUP is empty, and allows() would make every session a
// global superuser.
func (h *Handler) globalSuperuser(groups []string) bool {
	return h.superuserGroups.grants(groups)
}

// superuserScopeFor works out what a session may act on, from the
// configuration as it stands now. Never cached: this is what makes removing
// someone from the leads file, or from the group, take effect on their next
// action rather than when their arm expires.
func (h *Handler) superuserScopeFor(session *SessionData) superuserScope {
	if session == nil {
		return superuserScope{}
	}
	return superuserScope{
		Global:   h.globalSuperuser(session.Groups),
		Projects: h.projectLeads.LedProjects(session.Username, session.Groups),
	}
}

// effectiveSuperuserScope is what an armed session may do right now: the
// current scope, capped by how the session was armed. A session armed as a
// project lead stays project-scoped even if its user has since become a
// global superuser; a session armed globally drops to project scope (or to
// nothing) if its user has since lost the group.
func effectiveSuperuserScope(armed armedSession, current superuserScope) superuserScope {
	if current.Global && !armed.projectScoped {
		return current
	}
	return superuserScope{Projects: current.Projects}
}

// mayUseSuperuserMode reports whether this request's session is allowed to act
// as other users, in either scope.
//
// Session-based only, deliberately. Superuser mode is an interactive posture
// an operator turns on and sees a banner for; letting a bearer token carry it
// would make it a silent ambient capability of any leaked credential.
func (h *Handler) mayUseSuperuserMode(r *http.Request) bool {
	if !h.superuserModeAvailable() {
		return false
	}
	session, ok := h.getSessionFromRequest(r)
	if !ok {
		return false
	}
	return h.superuserScopeFor(session).allowed()
}

// scheddSuperUserSource adapts the handler's schedd accessor to the narrow
// interface the policy needs. The accessor is re-read on each call because the
// handler replaces its Schedd when the daemon's address changes.
type scheddSuperUserSource struct {
	get func() *htcondor.Schedd
}

func (s scheddSuperUserSource) QueueSuperUsers(ctx context.Context) ([]string, error) {
	schedd := s.get()
	if schedd == nil {
		return nil, fmt.Errorf("no schedd configured")
	}
	return schedd.QueueSuperUsers(ctx)
}
