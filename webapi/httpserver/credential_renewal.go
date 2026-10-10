package httpserver

import (
	"context"
	"errors"
	"slices"
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

// renewWith is the renewer for base, a config built around a token this
// server minted: remint mints the token again, and the config is rebuilt
// around it as base was, keeping base's session cache and tag -- they stand
// for the grant, not for one token. Nil when remint is: a credential the
// caller presented cannot be renewed here.
func renewWith(cfg *config.Config, base *security.SecurityConfig, remint func() (string, error)) htcondor.SecurityConfigRenewer {
	if remint == nil {
		return nil
	}
	cache, tag := base.SessionCache, base.SecurityTag
	return func(context.Context) (*security.SecurityConfig, error) {
		tok, err := remint()
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

// errGrantExpired is a renewal refused because the grant the credential was
// minted from has itself expired.
var errGrantExpired = errors.New("the grant this credential was minted from has expired")

// grantReminter mints the credential for an opaque OAuth2 bearer again,
// for as long as the bearer's own grant lasts, and records it against the
// bearer so later requests start from the fresh one.
func (s *Handler) grantReminter(bearer, username string, scopes []string, notAfter time.Time) func() (string, error) {
	scopes = slices.Clone(scopes)
	return func() (string, error) {
		if !notAfter.IsZero() && !time.Now().Before(notAfter) {
			return "", errGrantExpired
		}
		tok, err := s.generateHTCondorTokenWithScopes(username, scopes)
		if err != nil {
			return "", err
		}
		s.tokenCache.SetCondorCredential(bearer, tok, scopes)
		return tok, nil
	}
}
