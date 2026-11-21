package connectors

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"
)

// The oauth2 kind: this server is the OAuth2 client, so it runs the
// authorization-code flow itself and holds a refresh token per user.
//
// Built on golang.org/x/oauth2, which this server already uses as a
// client of its upstream identity provider. What is here rather than
// there is the part that is ours: binding a flow to the session that
// started it, insisting on a refresh token, and telling a revoked grant
// apart from a provider having a bad minute.

// FlowTTL is how long an authorization may stay in flight.
//
// Generous for a person reading a consent screen, short enough that an
// abandoned flow does not sit in memory. Note this is also the window in
// which a stolen state value is worth anything.
const FlowTTL = 15 * time.Minute

// Grant is what completing a flow produced.
type Grant struct {
	RefreshToken    string
	AccessToken     string
	Expiry          time.Time
	GrantedScopes   []string
	ProviderSubject string
}

// AccessToken is one short-lived token, from an exchange or a refresh.
type AccessToken struct {
	Token  string
	Expiry time.Time
}

// ErrNeedsConsent means the provider will not renew this grant and the
// user has to authorize again.
//
// Separated from a transient failure deliberately. A revoked grant needs
// a person; retrying it forever is how a server starts being rate
// limited by somebody else's identity provider, and treating a provider
// having a bad minute as a revocation is how a working connector gets
// torn down. See classifyTokenError.
var ErrNeedsConsent = errors.New("the provider will not renew this credential; the user must authorize again")

// ErrNoRefreshToken means the exchange succeeded and returned nothing
// that outlives the access token.
//
// A hard failure rather than a shrug. Google returns a refresh token
// only when the authorization asked for offline access AND the user was
// actually prompted; without one the connector works for an hour and
// then stops, which is a failure that arrives detached from its cause.
// Better to refuse the grant now and say why.
var ErrNoRefreshToken = errors.New(
	"the provider returned no refresh token, so this credential would stop working within the hour")

// Flow runs authorization-code flows and remembers the ones in flight.
type Flow struct {
	// Client is the HTTP client used for token requests. Nil means the
	// default.
	Client *http.Client

	now func() time.Time
	ttl time.Duration

	mu      sync.Mutex
	pending map[string]*pendingFlow
}

type pendingFlow struct {
	subject  string
	id       ID
	verifier string
	started  time.Time
}

// NewFlow builds a Flow.
func NewFlow() *Flow {
	return &Flow{now: time.Now, ttl: FlowTTL, pending: map[string]*pendingFlow{}}
}

func (f *Flow) clock() time.Time {
	if f.now == nil {
		return time.Now()
	}
	return f.now()
}

func (f *Flow) ctxClient(ctx context.Context) context.Context {
	if f.Client == nil {
		return ctx
	}
	return context.WithValue(ctx, oauth2.HTTPClient, f.Client)
}

// config builds the x/oauth2 configuration for one connector.
func (d Definition) config(secret, redirectURI string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     d.ClientID,
		ClientSecret: secret,
		RedirectURL:  redirectURI,
		Scopes:       d.Scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:   d.AuthorizationURL,
			TokenURL:  d.TokenURL,
			AuthStyle: d.AuthStyle,
		},
	}
}

// Begin starts a flow and returns where to send the browser.
//
// subject is the authenticated session's user. It is recorded so that
// Complete can refuse a callback presented by anybody else: the state
// value travels through the user's browser and a query string, and
// binding it to the session is what stops a stolen or planted one from
// attaching somebody else's provider account to this user's connector.
func (f *Flow) Begin(d Definition, secret, subject, redirectURI string) (string, error) {
	if subject == "" {
		return "", errors.New("a connector flow needs an authenticated user")
	}
	if d.AuthorizationURL == "" || d.TokenURL == "" {
		return "", fmt.Errorf("connector %s has no endpoints configured", d.ID)
	}
	if d.ClientID == "" {
		return "", fmt.Errorf("connector %s has no %s", d.ID, d.ID.ConfigKey("CLIENT_ID"))
	}

	state, err := randomToken()
	if err != nil {
		return "", err
	}
	verifier, err := randomToken()
	if err != nil {
		return "", err
	}

	f.mu.Lock()
	f.sweepLocked()
	f.pending[state] = &pendingFlow{
		subject:  subject,
		id:       d.ID,
		verifier: verifier,
		started:  f.clock(),
	}
	f.mu.Unlock()

	sum := sha256.Sum256([]byte(verifier))
	opts := []oauth2.AuthCodeOption{
		// A refresh token comes back only when the authorization asked
		// for offline access.
		oauth2.SetAuthURLParam("access_type", "offline"),
		// And only when the user is actually prompted. Without this a
		// user who has authorized before is approved silently, no
		// refresh token is issued, and the connector works until the
		// access token expires -- see ErrNoRefreshToken.
		oauth2.SetAuthURLParam("prompt", "consent"),
		oauth2.SetAuthURLParam("code_challenge", base64.RawURLEncoding.EncodeToString(sum[:])),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	}
	return d.config(secret, redirectURI).AuthCodeURL(state, opts...), nil
}

// Complete finishes a flow from the callback's state and code.
//
// The subject is the session presenting the callback, and it has to be
// the session that began the flow.
func (f *Flow) Complete(ctx context.Context, d Definition, secret, subject, state, code, redirectURI string) (Grant, error) {
	f.mu.Lock()
	f.sweepLocked()
	p, ok := f.pending[state]
	if ok {
		// Single use, consumed whether or not the rest succeeds: a
		// state that survived a failed attempt could be replayed.
		delete(f.pending, state)
	}
	f.mu.Unlock()

	if !ok {
		return Grant{}, errors.New("this authorization is unknown or has expired; start it again")
	}
	if p.subject != subject {
		// Not reported in detail to the caller: the useful version of
		// this message belongs in a log, not in a response to whoever
		// presented somebody else's state.
		return Grant{}, errors.New("this authorization was not started by you")
	}
	if p.id != d.ID {
		return Grant{}, fmt.Errorf("this authorization was for %s, not %s", p.id, d.ID)
	}

	tok, err := d.config(secret, redirectURI).Exchange(f.ctxClient(ctx), code,
		oauth2.SetAuthURLParam("code_verifier", p.verifier))
	if err != nil {
		return Grant{}, classifyTokenError(err)
	}
	if tok.RefreshToken == "" {
		return Grant{}, ErrNoRefreshToken
	}

	g := Grant{
		RefreshToken: tok.RefreshToken,
		AccessToken:  tok.AccessToken,
		Expiry:       tok.Expiry,
	}
	// The scopes the provider actually granted, which are not always
	// the ones asked for.
	if raw, _ := tok.Extra("scope").(string); raw != "" {
		g.GrantedScopes = strings.Fields(raw)
	} else {
		g.GrantedScopes = append([]string(nil), d.Scopes...)
	}
	return g, nil
}

// Refresh exchanges a stored refresh token for an access token.
func (f *Flow) Refresh(ctx context.Context, d Definition, secret, refreshToken string) (AccessToken, error) {
	if refreshToken == "" {
		return AccessToken{}, ErrNeedsConsent
	}
	cfg := d.config(secret, "")
	src := cfg.TokenSource(f.ctxClient(ctx), &oauth2.Token{RefreshToken: refreshToken})
	tok, err := src.Token()
	if err != nil {
		return AccessToken{}, classifyTokenError(err)
	}
	return AccessToken{Token: tok.AccessToken, Expiry: tok.Expiry}, nil
}

// Pending reports how many flows are in flight, for a test and for a
// metric.
func (f *Flow) Pending() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sweepLocked()
	return len(f.pending)
}

func (f *Flow) sweepLocked() {
	cutoff := f.clock().Add(-f.ttl)
	for state, p := range f.pending {
		if p.started.Before(cutoff) {
			delete(f.pending, state)
		}
	}
}

// classifyTokenError separates "this grant is dead" from "try later".
//
// The distinction is the whole reason this function exists. A provider
// answering invalid_grant has told us the credential will never work
// again and the user must consent; retrying that on a timer is how a
// server earns a rate limit. A 503, a timeout or a 429 says nothing
// about the credential, and tearing one down over it would make a
// provider's bad minute into every user's re-consent.
//
// The error CODES are Google's documented names; the envelope they
// arrive in is RFC 6749's, which Google's own page does not document.
// See connectors/mockgoogle.
func classifyTokenError(err error) error {
	var re *oauth2.RetrieveError
	if !errors.As(err, &re) {
		return err
	}

	var body struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	_ = json.Unmarshal(re.Body, &body)

	switch body.Error {
	case "invalid_grant", "invalid_client", "unauthorized_client", "deleted_client":
		desc := body.ErrorDescription
		if desc == "" {
			desc = body.Error
		}
		return fmt.Errorf("%w (%s)", ErrNeedsConsent, desc)
	}

	// A 4xx that is not one of those is still the request's fault and
	// will not fix itself, but it is not a statement about the user's
	// grant, so it is returned as it is rather than as a revocation.
	return err
}

// randomToken is 256 bits, URL-safe.
//
// Used for both the state and the PKCE verifier. State has to be
// unguessable because possessing one is what lets a callback attach a
// provider account to a session; the verifier because that is what PKCE
// is.
func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating a random token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
