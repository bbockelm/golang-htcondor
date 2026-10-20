package httpserver

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/PelicanPlatform/classad/classad"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/webapi/multiap"
)

// Bootstrapping the credentials an access point requires before a job may be
// submitted.
//
// Some access points hold every job that arrives without particular OAuth
// service credentials on file, even when nothing in the job uses them. A
// schedd transform adds the services to OAuthServicesNeeded, and the shadow
// holds the job with "Job credentials are not available" when they are absent.
// condor_submit never trips over this, because before every submit it asks
// the credd to make sure the submitter holds them (CREDD_CHECK_CREDS), and the
// credd creates any its local credmons provide. Nothing in this server asked,
// so once the credd swept a user's credentials -- an hour after their last job
// left the queue -- every job they submitted here was held, and only a
// condor_submit on the access point brought them back.
//
// So every submit path asks first, the way condor_submit does. Two mechanisms:
//
//   - The check-creds request, made for every caller whenever a credd is
//     present. It names no services: the credd adds the ones its own local
//     credmons provide (SUBMIT_ADD_LOCAL_CREDMON_PROVIDERS), creates any that
//     are missing, and waits for the credmon to write the token. This needs no
//     configuration here.
//   - HTTP_API_REQUIRED_CREDENTIALS, for a service the access point checks for
//     but no credmon of its own produces. A placeholder is stored, because a
//     placeholder is what satisfies the check; a real one arrives later
//     through the ordinary OAuth flow and replaces it.

// placeholderCredential is stored for a required service that has none.
//
// It must be valid JSON: the credd stores whatever it is given and then fails
// every later read of a credential that is not, which turns a missing
// credential into a corrupt one (see ValidateOAuthCredential).
var placeholderCredential = []byte(`{"access_token":"placeholder"}`)

// requiredCredentialTTL is how long a service is assumed to still be present
// after it has been seen. Short enough that a credential deleted out from
// under us is noticed on the next submit but one, long enough that a burst of
// submissions does not become a burst of credd round trips.
const requiredCredentialTTL = 5 * time.Minute

// requiredCredCache remembers which (credd, user, service) triples were
// present, so a submit does not ask the credd about every required service
// every time. The credd is part of the key because in multi-AP mode each
// AP has its own: a credential present in one says nothing about another.
//
// Only presence is cached, never absence: a service that was missing has just
// been created, and the next submit should find it. Caching the miss would
// mean re-creating it, and worse, a failure to create it would be remembered
// as a fact rather than retried.
type requiredCredCache struct {
	ttl time.Duration
	now func() time.Time

	mu   sync.Mutex
	seen map[requiredCredKey]time.Time
}

type requiredCredKey struct {
	// scope names the credd: "" for the one credd of a single-AP
	// server, the AP's credd address in multi-AP mode.
	scope   string
	user    string
	service string
}

func newRequiredCredCache(ttl time.Duration) *requiredCredCache {
	return &requiredCredCache{ttl: ttl, now: time.Now, seen: map[requiredCredKey]time.Time{}}
}

// fresh reports whether this user's service was seen recently enough to skip
// the check.
func (c *requiredCredCache) fresh(scope, user, service string) bool {
	// An unidentified caller gets no cache entry at all rather than sharing
	// one: the cache is keyed by identity because credentials are per-user,
	// and a blank key would let one caller's result answer for another's.
	if user == "" {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	at, ok := c.seen[requiredCredKey{scope: scope, user: user, service: service}]
	return ok && c.now().Sub(at) < c.ttl
}

func (c *requiredCredCache) record(scope, user, service string) {
	if user == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.seen[requiredCredKey{scope: scope, user: user, service: service}] = c.now()
}

// forget drops a user's entry, so the next submit re-checks it.
func (c *requiredCredCache) forget(scope, user, service string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.seen, requiredCredKey{scope: scope, user: user, service: service})
}

// checkCredsKey is the requiredCredCache entry for the check-creds request,
// which names no service. No service is named "", so it cannot collide.
const checkCredsKey = ""

// checkCredsTimeout bounds the check-creds request. The credd holds its reply
// while a local credmon writes a token it has just asked for, polling once a
// second for up to 20 seconds.
const checkCredsTimeout = 30 * time.Second

// ensureRequiredCredentials makes sure the caller holds the credentials this
// access point requires: what the credd's local credmons provide, through the
// check-creds request, and every service named by
// HTTP_API_REQUIRED_CREDENTIALS, creating a placeholder for any that is
// missing.
//
// It never fails a submit. A credd that is unavailable, or that refuses the
// request, leaves the caller exactly where they were before this existed -- a
// job that may go on hold -- whereas refusing to submit would turn a
// best-effort convenience into a new way for submission to break. The reason
// is logged instead.
//
// The credd is the one the submission's AP uses (creddFor): in multi-AP
// mode the credd of the AP the submission was routed to, which is the only
// one whose credentials that AP's jobs will see.
func (s *Handler) ensureRequiredCredentials(ctx context.Context) {
	// One handle for the whole call: the address updater can replace it
	// between the nil check and the use, and a check that guarded a
	// different value than the one used guards nothing.
	credd, scope := s.creddFor(ctx)
	if credd == nil {
		if len(s.requiredCredentials) > 0 {
			s.logger.Warn(logging.DestinationHTTP,
				"cannot bootstrap the required credentials: no credd is available",
				"services", s.requiredCredentials, "access_point", routedSchedd(ctx))
		}
		return
	}

	user := htcondor.GetAuthenticatedUserFromContext(ctx)

	// First, so that a service a local credmon provides exists by the time
	// the loop below looks for it, and is never given a placeholder.
	s.checkSubmitCredentials(ctx, credd, scope, user)

	for _, service := range s.requiredCredentials {
		if s.requiredCredCache.fresh(scope, user, service) {
			continue
		}

		// The empty user means "the caller", which is how the rest of this
		// server talks to the credd: the connection carries the identity.
		// A credential that is not there is reported as an error, and it is
		// the one this loop exists to handle.
		status, err := credd.GetServiceCredStatus(ctx, htcondor.CredTypeOAuth, service, "", "")
		if err != nil && !errors.Is(err, htcondor.ErrCredentialNotFound) {
			s.logger.Warn(logging.DestinationHTTP, "could not check a required credential",
				"service", service, "user", user, "error", err)
			continue
		}
		// Pending is a credential stored and waiting for its credmon. Storing
		// a placeholder over it would replace the request it is acting on.
		if status.Exists || status.Pending {
			s.requiredCredCache.record(scope, user, service)
			continue
		}

		// Ask the credd for it by name first. A credd older than HTCondor
		// 25.13.2 does not add its local credmons' services to a request
		// that names none, so the check above created nothing; named, it
		// creates the credential the way condor_submit has it do. Only a
		// service no credmon there provides gets a placeholder.
		if s.requestFromCredd(ctx, credd, user, service) {
			s.requiredCredCache.record(scope, user, service)
			continue
		}

		if err := credd.PutServiceCred(ctx, htcondor.CredTypeOAuth, placeholderCredential, service, "", "", nil); err != nil {
			s.logger.Warn(logging.DestinationHTTP, "could not bootstrap a required credential",
				"service", service, "user", user, "error", err)
			// Not cached: the next submit tries again.
			s.requiredCredCache.forget(scope, user, service)
			continue
		}
		s.logger.Info(logging.DestinationHTTP, "bootstrapped a required credential before submit",
			"service", service, "user", user)
		s.requiredCredCache.record(scope, user, service)
	}
}

// requestFromCredd names one missing service in a check-creds request and
// reports whether the credd took care of it: created it (a local credmon's
// service), or answered with a URL the user must visit (a service that needs
// their consent, which a placeholder would only paper over). A refusal -- the
// credd has no credmon for the service -- or a failure to reach it reports
// false, leaving the caller to store a placeholder.
func (s *Handler) requestFromCredd(ctx context.Context, credd htcondor.CreddClient, user, service string) bool {
	cctx, cancel := context.WithTimeout(ctx, checkCredsTimeout)
	defer cancel()
	url, err := credd.CheckCreds(cctx, []htcondor.CredRequest{{Service: service}})
	switch {
	case err != nil:
		s.logger.Debug(logging.DestinationHTTP, "the credd did not create a required credential",
			"service", service, "user", user, "error", err)
		return false
	case url != "":
		s.logger.Warn(logging.DestinationHTTP, "a required credential needs the user to authorize it",
			"service", service, "user", user, "url", url)
		return true
	default:
		s.logger.Info(logging.DestinationHTTP, "requested a required credential from the credd before submit",
			"service", service, "user", user)
		return true
	}
}

// checkSubmitCredentials makes the request condor_submit makes before every
// submit, naming no services and letting the credd add its own.
//
// A credd that answers -- yes, or no with a reason -- is not asked again for
// the cache's lifetime: the same question gets the same answer until something
// on the access point changes, and a credd without OAuth configured would
// otherwise log the same refusal on every submit. Failing to reach it is not
// cached, so the next submit tries again.
func (s *Handler) checkSubmitCredentials(ctx context.Context, credd htcondor.CreddClient, scope, user string) {
	if s.requiredCredCache.fresh(scope, user, checkCredsKey) {
		return
	}

	cctx, cancel := context.WithTimeout(ctx, checkCredsTimeout)
	defer cancel()
	url, err := credd.CheckCreds(cctx, nil)

	var refusal *htcondor.CheckCredsRefusal
	switch {
	case errors.As(err, &refusal):
		s.logger.Warn(logging.DestinationHTTP, "the credd declined to supply the credentials a job needs",
			"user", user, "reason", refusal.Reason)
		s.requiredCredCache.record(scope, user, checkCredsKey)
	case err != nil:
		s.logger.Warn(logging.DestinationHTTP, "could not ask the credd for the credentials a job needs",
			"user", user, "error", err)
		s.requiredCredCache.forget(scope, user, checkCredsKey)
	case url != "":
		// Only a service that needs the user's consent produces a URL, and
		// the request names none, so this means the credd's own list does.
		s.logger.Warn(logging.DestinationHTTP, "the credd needs the user to authorize a credential before jobs can use it",
			"user", user, "url", url)
		s.requiredCredCache.record(scope, user, checkCredsKey)
	default:
		s.requiredCredCache.record(scope, user, checkCredsKey)
	}
}

// submitJob is the one door every job this daemon submits goes through:
// the credential bootstrap above, then the site's submit policy, then
// the schedd.
//
// It is a function because the two lines in front of the submit were
// something each surface had to remember. The REST endpoint, the web
// terminal, JupyterLab and VS Code each carried their own copy;
// interactive sessions, which are submitted by the manager in
// webapi/interactive rather than by anything here, carried the policy
// (it is one of that manager's options) and not the bootstrap. So a
// person who typed `ssh` at an access point that requires OAuth service
// credentials got a job held with "Job credentials are not available",
// for a reason with nothing to do with what they asked for -- while the
// same session started from the web UI worked.
//
// Surfaces outside this package reach the same preparation through the
// hook the MCP server is handed (mcpserver.Config.EnsureCredentials),
// which is a func value rather than a second implementation because the
// credd handle, the list of required services and the cache that keeps
// this off the hot path all live here.
func (s *Handler) submitJob(ctx context.Context, submitFile string) (int, []*classad.ClassAd, error) {
	applied, err := s.submitPolicy.Apply(submitFile)
	if err != nil {
		return 0, nil, err
	}
	s.ensureRequiredCredentials(ctx)
	// scheddFor: the one schedd, or in multi-AP mode the AP the
	// submission was assigned and routed to.
	schedd := s.scheddFor(ctx)
	return schedd.SubmitRemote(s.withSubmitDefaults(ctx, schedd), applied)
}

// withSubmitDefaults returns ctx carrying the JOB_DEFAULT_REQUEST* values
// of the access point a job goes to, as its schedd reports them -- what
// condor_submit there would apply, and what the MCP server's
// get_access_point_policy reports. When the schedd cannot be asked, this
// daemon's own configuration and then HTCondor's built-in defaults apply;
// the lookup never fails a submission.
func (s *Handler) withSubmitDefaults(ctx context.Context, schedd *htcondor.Schedd) context.Context {
	if schedd == nil {
		out, _ := s.apPolicy.SubmitContext(ctx, "", nil, s.htcondorConfig)
		return out
	}
	// Keyed as the MCP server keys it, so the two share one reading.
	name := schedd.Name()
	if t, ok := multiap.TargetFrom(ctx); ok {
		name = t.Member.Name
	}
	if name == "" {
		name = schedd.Address()
	}
	out, err := s.apPolicy.SubmitContext(ctx, name, schedd, s.htcondorConfig)
	if err != nil {
		s.logger.Warn(logging.DestinationHTTP,
			"could not read the access point's request defaults; submitting with this server's",
			"access_point", name, "error", err)
	}
	return out
}
