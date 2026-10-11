package htcondor

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/bbockelm/cedar/security"
)

// SecurityConfigRenewer re-creates a caller's credential: a SecurityConfig
// like the one it was attached with, carrying a newly minted token.
//
// It exists because the credential a server mints for a caller is meant for
// one request -- a minute or five -- while some of what a request starts
// outlives it: a stream that keeps polling, a watch shared by several
// viewers, a lease that removes a job when it runs out. Copying the
// request's token into those hands them a credential that expires under
// them. Copying the renewer instead lets them mint the caller's credential
// again, from the identity and authorization the original was minted for.
type SecurityConfigRenewer func(ctx context.Context) (*security.SecurityConfig, error)

// credentialRenewMargin is how close to its expiry a token is renewed
// rather than presented: far enough out that the handshake it is about to
// start does not outlast it.
const credentialRenewMargin = 30 * time.Second

type credentialRenewerContextKey struct{}

// boundRenewer ties a renewer to the SecurityConfig it renews, so a context
// that replaces the config -- impersonation, a daemon credential, a config
// built for some other peer -- does not have it silently swapped back for
// the caller's.
type boundRenewer struct {
	config *security.SecurityConfig
	renew  SecurityConfigRenewer
}

// WithRenewableSecurityConfig is WithSecurityConfig for a credential minted
// for the caller: when the token secConfig carries is about to expire,
// GetSecurityConfigOrDefault replaces it with what renew returns. renew may
// refuse -- the grant behind the credential has ended -- and the connection
// then fails rather than presenting the expired token.
func WithRenewableSecurityConfig(ctx context.Context, secConfig *security.SecurityConfig, renew SecurityConfigRenewer) context.Context {
	ctx = WithSecurityConfig(ctx, secConfig)
	if renew == nil {
		return ctx
	}
	return context.WithValue(ctx, credentialRenewerContextKey{}, boundRenewer{config: secConfig, renew: renew})
}

// CallerCredential is a caller's credential detached from the request that
// carried it, for work that outlives the request.
type CallerCredential struct {
	config security.SecurityConfig
	renew  SecurityConfigRenewer
}

// CallerCredentialFromContext copies the caller's credential off ctx, with
// the renewer that was attached alongside it, if any. The copy is the
// holder's own: nothing the request does afterwards changes it.
func CallerCredentialFromContext(ctx context.Context) (CallerCredential, bool) {
	sc, ok := ctx.Value(securityConfigContextKey{}).(*security.SecurityConfig)
	if !ok || sc == nil {
		return CallerCredential{}, false
	}
	cred := CallerCredential{config: *sc}
	if b, ok := ctx.Value(credentialRenewerContextKey{}).(boundRenewer); ok && b.config == sc {
		cred.renew = b.renew
	}
	return cred, true
}

// Attach returns ctx carrying the credential, renewable as it was on the
// request it came from.
func (c CallerCredential) Attach(ctx context.Context) context.Context {
	sc := c.config
	return WithRenewableSecurityConfig(ctx, &sc, c.renew)
}

// Renewable reports whether the credential can be re-minted. One that
// cannot -- a token the caller presented themselves -- lasts exactly as
// long as that token.
func (c CallerCredential) Renewable() bool { return c.renew != nil }

// Renew mints the credential again now, whatever its token's expiry.
func (c CallerCredential) Renew(ctx context.Context) (CallerCredential, error) {
	if c.renew == nil {
		return CallerCredential{}, fmt.Errorf("this credential cannot be renewed")
	}
	fresh, err := c.renew(ctx)
	if err != nil {
		return CallerCredential{}, fmt.Errorf("renewing the caller's credential: %w", err)
	}
	if fresh == nil {
		return CallerCredential{}, fmt.Errorf("renewing the caller's credential: no credential")
	}
	return CallerCredential{config: *fresh, renew: c.renew}, nil
}

// Token is the token the credential presents.
func (c CallerCredential) Token() string { return c.config.Token }

// renewSecurityConfig returns the renewed config for ctx when the config on
// it carries a renewer and a token about to expire; otherwise nil.
func renewSecurityConfig(ctx context.Context) (*security.SecurityConfig, error) {
	sc, _ := ctx.Value(securityConfigContextKey{}).(*security.SecurityConfig)
	b, ok := ctx.Value(credentialRenewerContextKey{}).(boundRenewer)
	if sc == nil || !ok || b.config != sc || b.renew == nil {
		return nil, nil
	}
	if !tokenExpiresWithin(sc.Token, credentialRenewMargin, time.Now()) {
		return nil, nil
	}
	fresh, err := b.renew(ctx)
	if err != nil {
		return nil, fmt.Errorf("renewing the caller's credential: %w", err)
	}
	if fresh == nil {
		return nil, fmt.Errorf("renewing the caller's credential: no credential")
	}
	return fresh, nil
}

// tokenExpiresWithin reports whether a JWT's exp falls within d of now.
// Anything that is not a JWT with an exp is not reported as expiring: there
// is nothing to renew it from.
func tokenExpiresWithin(token string, d time.Duration, now time.Time) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}
	var claims struct {
		Exp *int64 `json:"exp"`
	}
	if json.Unmarshal(raw, &claims) != nil || claims.Exp == nil {
		return false
	}
	return !now.Add(d).Before(time.Unix(*claims.Exp, 0))
}
