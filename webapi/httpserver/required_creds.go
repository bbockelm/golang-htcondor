package httpserver

import (
	"context"
	"sync"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/logging"
)

// Bootstrapping the credentials an access point requires before a job may be
// submitted.
//
// Some access points hold every job that arrives without a particular OAuth
// service credential on file, even when nothing in the job uses it -- the
// credential's presence is what the machinery checks, not its contents. An
// agent is told about this through the MCP instructions and stores one before
// submitting. The web UI has nobody to tell, so it submits, the job goes on
// hold, and the person who pressed the button sees a job that failed for a
// reason that has nothing to do with what they asked for.
//
// So the server does it: the operator names the services this access point
// requires, and every submit path makes sure they exist first. The credential
// stored is a placeholder, because a placeholder is what satisfies the check;
// a real one arrives later through the ordinary OAuth flow and replaces it.

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

// requiredCredCache remembers which (user, service) pairs were present, so a
// submit does not ask the credd about every required service every time.
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
	user    string
	service string
}

func newRequiredCredCache(ttl time.Duration) *requiredCredCache {
	return &requiredCredCache{ttl: ttl, now: time.Now, seen: map[requiredCredKey]time.Time{}}
}

// fresh reports whether this user's service was seen recently enough to skip
// the check.
func (c *requiredCredCache) fresh(user, service string) bool {
	// An unidentified caller gets no cache entry at all rather than sharing
	// one: the cache is keyed by identity because credentials are per-user,
	// and a blank key would let one caller's result answer for another's.
	if user == "" {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	at, ok := c.seen[requiredCredKey{user: user, service: service}]
	return ok && c.now().Sub(at) < c.ttl
}

func (c *requiredCredCache) record(user, service string) {
	if user == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.seen[requiredCredKey{user: user, service: service}] = c.now()
}

// forget drops a user's entry, so the next submit re-checks it.
func (c *requiredCredCache) forget(user, service string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.seen, requiredCredKey{user: user, service: service})
}

// ensureRequiredCredentials makes sure every service named by
// HTTP_API_REQUIRED_CREDENTIALS exists for this caller, creating a placeholder
// for any that does not.
//
// It never fails a submit. A credd that is unavailable, or that refuses the
// write, leaves the caller exactly where they were before this existed -- a
// job that may go on hold -- whereas refusing to submit would turn a
// best-effort convenience into a new way for submission to break. The reason
// is logged instead.
func (s *Handler) ensureRequiredCredentials(ctx context.Context) {
	if len(s.requiredCredentials) == 0 {
		return
	}
	// One handle for the whole call: the address updater can replace it
	// between the nil check and the use, and a check that guarded a
	// different value than the one used guards nothing.
	credd := s.getCredd()
	if credd == nil || !s.creddAvailable.Load() {
		s.logger.Warn(logging.DestinationHTTP,
			"cannot bootstrap the required credentials: no credd is available",
			"services", s.requiredCredentials)
		return
	}

	user := htcondor.GetAuthenticatedUserFromContext(ctx)
	for _, service := range s.requiredCredentials {
		if s.requiredCredCache.fresh(user, service) {
			continue
		}

		// The empty user means "the caller", which is how the rest of this
		// server talks to the credd: the connection carries the identity.
		status, err := credd.GetServiceCredStatus(ctx, htcondor.CredTypeOAuth, service, "", "")
		if err != nil {
			s.logger.Warn(logging.DestinationHTTP, "could not check a required credential",
				"service", service, "user", user, "error", err)
			continue
		}
		if status.Exists {
			s.requiredCredCache.record(user, service)
			continue
		}

		if err := credd.PutServiceCred(ctx, htcondor.CredTypeOAuth, placeholderCredential, service, "", "", nil); err != nil {
			s.logger.Warn(logging.DestinationHTTP, "could not bootstrap a required credential",
				"service", service, "user", user, "error", err)
			// Not cached: the next submit tries again.
			s.requiredCredCache.forget(user, service)
			continue
		}
		s.logger.Info(logging.DestinationHTTP, "bootstrapped a required credential before submit",
			"service", service, "user", user)
		s.requiredCredCache.record(user, service)
	}
}
