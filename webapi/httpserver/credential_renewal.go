package httpserver

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/bbockelm/cedar/security"
	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/config"
)

// The IDTOKENs this server mints for a caller last a minute or five,
// because each is minted for one request. What a request starts can last
// longer -- a stream that keeps polling the schedd, a watch poll shared by
// several viewers, an interactive session's lease -- and copying the
// request's token into it hands it a credential that expires under it.
// Every place that mints one therefore attaches a renewer beside it
// (htcondor.WithRenewableSecurityConfig), and the token is minted again
// from the same identity and authorization when it is about to expire.
//
// A renewal is a fresh act of minting, so it is never made on the strength
// of the original one alone: each renewer first re-checks whatever
// authorized the caller -- the session row, the OAuth2 grant, the API key,
// the live request -- and refuses once that has been revoked, logged out,
// disabled or has expired. The short token lifetime stays what bounds how
// long a revocation takes to reach running work.

// reminter mints a caller's token again, after re-checking the source it
// was minted from.
type reminter func(ctx context.Context) (string, error)

// renewWith is the renewer for base, a config built around a token this
// server minted: remint mints the token again, and the config is rebuilt
// around it as base was, keeping base's session cache and tag -- they stand
// for the grant, not for one token. Nil when remint is: a credential the
// caller presented cannot be renewed here.
func renewWith(cfg *config.Config, base *security.SecurityConfig, remint reminter) htcondor.SecurityConfigRenewer {
	if remint == nil {
		return nil
	}
	cache, tag := base.SessionCache, base.SecurityTag
	return func(ctx context.Context) (*security.SecurityConfig, error) {
		tok, err := remint(ctx)
		if err != nil {
			return nil, err
		}
		sc, err := configureSecurityForToken(cfg, tok, cache, false)
		if err != nil {
			return nil, err
		}
		sc.SecurityTag = tag
		return sc, nil
	}
}

var (
	// errGrantExpired is a renewal refused because the grant the
	// credential was minted from has itself expired.
	errGrantExpired = errors.New("the grant this credential was minted from has expired")
	// errGrantChanged is a renewal refused because the grant now carries
	// different scopes than the credential was minted with. Re-minting
	// under the old session tag would let the new token resume sessions
	// negotiated with the old authority, so the holder fails and the
	// caller's next request starts over.
	errGrantChanged = errors.New("the grant this credential was minted from has changed its scopes")
	// errSessionEnded is a renewal refused because the browser session it
	// was minted for has been logged out or has expired.
	errSessionEnded = errors.New("the session this credential was minted for has ended")
	// errRequestEnded is a renewal refused because the request whose
	// asserted identity it was minted for is over.
	errRequestEnded = errors.New("the request this credential was minted for has ended")
)

// grantReauthInterval is how often a renewal also re-runs the grant's
// authorization policy (reauthorizeGrant: lifetime cap, group policy,
// revocation oracles). Its liveness -- revoked, expired, or its parent
// grant gone -- is checked on every renewal; the policy, which can reach
// the schedd through the oracles, at most this often per grant.
const grantReauthInterval = 5 * time.Minute

// grantReauthLimiter remembers when each grant's policy was last re-run.
type grantReauthLimiter struct {
	mu   sync.Mutex
	last map[string]time.Time
}

// due reports whether grant id's policy should be re-run now, and if so
// records that it is being.
func (l *grantReauthLimiter) due(id string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.last == nil {
		l.last = map[string]time.Time{}
	}
	if t, ok := l.last[id]; ok && now.Sub(t) < grantReauthInterval {
		return false
	}
	if len(l.last) >= 4096 {
		for k, t := range l.last {
			if now.Sub(t) >= grantReauthInterval {
				delete(l.last, k)
			}
		}
	}
	l.last[id] = now
	return true
}

// checkOAuth2Grant re-validates the OAuth2 access token a credential was
// minted from: it is still active, unexpired and unrevoked, as is the grant
// it was exchanged from (the same introspection every bearer check uses),
// and it still carries the scopes the credential was minted with. Every
// few minutes it also re-runs the grant's authorization policy, which
// revokes the grant on a refusal exactly as a refresh would.
func (s *Handler) checkOAuth2Grant(ctx context.Context, bearer string, scopes []string) error {
	if s.oauth2Provider == nil {
		return errors.New("OAuth2 is not configured; the grant cannot be re-checked")
	}
	ar, err := s.oauth2Provider.IntrospectAccessToken(ctx, bearer)
	if err != nil {
		return fmt.Errorf("the OAuth2 grant behind this credential is no longer active: %w", err)
	}
	if !sameScopes(ar.GetGrantedScopes(), scopes) {
		return errGrantChanged
	}
	if s.grantReauth.due(ar.GetID(), time.Now()) {
		granted, err := s.reauthorizeGrant(ctx, ar)
		if err != nil {
			return fmt.Errorf("the OAuth2 grant behind this credential was refused on reauthorization: %w", err)
		}
		if !sameScopes(granted, scopes) {
			return errGrantChanged
		}
	}
	return nil
}

func sameScopes(a, b []string) bool {
	x, y := slices.Clone(a), slices.Clone(b)
	slices.Sort(x)
	slices.Sort(y)
	return slices.Equal(slices.Compact(x), slices.Compact(y))
}

// grantReminter mints the credential for an opaque OAuth2 bearer again,
// while the grant behind it is still good (checkOAuth2Grant) and before its
// expiry, and records it against the bearer so later requests start from
// the fresh one.
func (s *Handler) grantReminter(bearer, username string, scopes []string, notAfter time.Time) reminter {
	scopes = slices.Clone(scopes)
	return func(ctx context.Context) (string, error) {
		if !notAfter.IsZero() && !time.Now().Before(notAfter) {
			return "", errGrantExpired
		}
		if err := s.checkOAuth2Grant(ctx, bearer, scopes); err != nil {
			return "", err
		}
		tok, err := s.generateHTCondorTokenWithScopes(username, scopes)
		if err != nil {
			return "", err
		}
		s.tokenCache.SetCondorCredential(bearer, tok, scopes)
		return tok, nil
	}
}

// requestReminter mints a session-cookie or user-header request's token
// again for subject. Nil for a request whose token was presented, not
// minted (subject empty).
//
// A session-cookie token renews while its http_sessions row is still there
// and unexpired, so logging out ends it. A user-header identity has nothing
// behind it to re-check -- the proxy asserted it for one request -- so it
// renews only while that request is still in progress: a stream the caller
// holds open, not work the request left behind.
func (s *Handler) requestReminter(r *http.Request, subject string) reminter {
	if subject == "" {
		return nil
	}
	var live func() error
	if sid, err := getSessionCookie(r); err == nil && s.sessionStore != nil {
		if sd := s.sessionStore.Get(sid); sd != nil {
			user := sd.Username
			live = func() error {
				if now := s.sessionStore.Get(sid); now == nil || now.Username != user {
					return errSessionEnded
				}
				return nil
			}
		}
	}
	if live == nil {
		reqCtx := r.Context()
		live = func() error {
			if reqCtx.Err() != nil {
				return errRequestEnded
			}
			return nil
		}
	}
	return func(context.Context) (string, error) {
		if err := live(); err != nil {
			return "", err
		}
		tok, _, err := s.mintRequestToken(subject, "renewal")
		return tok, err
	}
}

// cachedGrantReminter is grantReminter for a bearer whose credential was
// minted from an opaque grant on its first request and cached: it expires
// long before the grant does. Nil when the cached credential is the bearer
// itself.
func (s *Handler) cachedGrantReminter(entry *TokenCacheEntry, bearer, credential string) reminter {
	if entry == nil || credential == bearer {
		return nil
	}
	return s.grantReminter(bearer, entry.Username, entry.Scopes, entry.Expiration)
}
