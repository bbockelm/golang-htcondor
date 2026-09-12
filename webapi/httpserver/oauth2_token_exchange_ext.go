package httpserver

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// Token exchange, stage C2: accept a subject_token from an external, configured
// trusted issuer (a signed JWT) and exchange it for one of our tokens.
//
// Trust is explicit and per-issuer: the operator lists each issuer with its JWKS
// URL, the audience the token must carry, the local domain its subjects map
// into, and the maximum scopes its tokens may obtain. An external token thus
// becomes the local identity <sub>@<identity_domain> (namespaced so two issuers
// cannot collide or spoof each other), and can obtain at most the issuer's
// allowed scopes -- further bounded, back in the handler, by the exchanging
// client's own scopes. Signature verification is RS256/ES256 only, keys come
// from the JWKS URL fetched with the same SSRF-hardened client CIMD uses.

const (
	//nolint:gosec // G101: OAuth token-type URNs, not credentials
	tokenTypeJWT = "urn:ietf:params:oauth:token-type:jwt"
	//nolint:gosec // G101: OAuth token-type URNs, not credentials
	tokenTypeIDToken = "urn:ietf:params:oauth:token-type:id_token"
)

const (
	jwksCacheTTL   = 10 * time.Minute
	jwtClockLeeway = 60 * time.Second
)

// trustedIssuer is one entry of HTTP_API_MCP_TOKEN_EXCHANGE_ISSUERS.
type trustedIssuer struct {
	Issuer         string   `json:"issuer"`          // exact `iss` the token must carry
	JWKSURI        string   `json:"jwks_uri"`        // where the issuer's signing keys live
	Audience       string   `json:"audience"`        // value the token's `aud` must include
	IdentityDomain string   `json:"identity_domain"` // local identity is <sub>@this; default: issuer host
	AllowedScopes  []string `json:"allowed_scopes"`  // ceiling of scopes a token from here may obtain
}

// parseTrustedIssuers parses and validates the issuer list. An empty/blank
// string yields no issuers (external exchange stays off).
func parseTrustedIssuers(s string) ([]trustedIssuer, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	var issuers []trustedIssuer
	if err := json.Unmarshal([]byte(s), &issuers); err != nil {
		return nil, fmt.Errorf("parsing token-exchange issuers: %w", err)
	}
	for i := range issuers {
		it := &issuers[i]
		if it.Issuer == "" || it.JWKSURI == "" || it.Audience == "" {
			return nil, fmt.Errorf("token-exchange issuer %d: issuer, jwks_uri and audience are required", i)
		}
		u, err := url.Parse(it.JWKSURI)
		if err != nil || u.Scheme != "https" {
			return nil, fmt.Errorf("token-exchange issuer %q: jwks_uri must be https", it.Issuer)
		}
		if it.IdentityDomain == "" {
			if iu, err := url.Parse(it.Issuer); err == nil && iu.Host != "" {
				it.IdentityDomain = iu.Hostname()
			} else {
				return nil, fmt.Errorf("token-exchange issuer %q: identity_domain required (issuer is not a URL)", it.Issuer)
			}
		}
	}
	return issuers, nil
}

type jwksEntry struct {
	keys   *jose.JSONWebKeySet
	expiry time.Time
}

// extIssuerValidator verifies external subject tokens against the configured
// trusted issuers, caching each issuer's JWKS.
type extIssuerValidator struct {
	issuers map[string]trustedIssuer // keyed by issuer
	fetch   func(ctx context.Context, jwksURI string) ([]byte, error)
	now     func() time.Time

	mu    sync.Mutex
	cache map[string]jwksEntry // keyed by jwks_uri
}

// newExtIssuerValidator builds a validator, or nil when no issuers are
// configured. fetch defaults to an SSRF-hardened GET (the CIMD client) when nil.
func newExtIssuerValidator(issuers []trustedIssuer, fetch func(context.Context, string) ([]byte, error)) *extIssuerValidator {
	if len(issuers) == 0 {
		return nil
	}
	if fetch == nil {
		client := cimdHTTPClient()
		fetch = func(ctx context.Context, jwksURI string) ([]byte, error) {
			return httpGetLimited(ctx, client, jwksURI, cimdMaxBodyBytes)
		}
	}
	m := make(map[string]trustedIssuer, len(issuers))
	for _, it := range issuers {
		m[it.Issuer] = it
	}
	return &extIssuerValidator{issuers: m, fetch: fetch, now: time.Now, cache: map[string]jwksEntry{}}
}

// jwtClaims are the registered claims we validate. aud is string-or-array.
type jwtClaims struct {
	Issuer    string       `json:"iss"`
	Subject   string       `json:"sub"`
	Audience  audienceList `json:"aud"`
	Expiry    int64        `json:"exp"`
	NotBefore int64        `json:"nbf"`
	Groups    []string     `json:"groups"`
}

// audienceList decodes the `aud` claim, which per RFC 7519 may be a single
// string or an array of strings.
type audienceList []string

func (a *audienceList) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		*a = []string{s}
		return nil
	}
	var arr []string
	if err := json.Unmarshal(b, &arr); err != nil {
		return err
	}
	*a = arr
	return nil
}

func (a audienceList) contains(v string) bool {
	for _, x := range a {
		if x == v {
			return true
		}
	}
	return false
}

// validate verifies an external subject token and returns the local identity,
// any group claim, and the issuer's allowed-scope ceiling. It returns an error
// for any token that is not a well-formed, signature-valid, unexpired token from
// a configured issuer with the required audience.
func (v *extIssuerValidator) validate(ctx context.Context, token string) (string, []string, []string, error) {
	jws, err := jose.ParseSigned(token, []jose.SignatureAlgorithm{jose.RS256, jose.ES256})
	if err != nil {
		return "", nil, nil, fmt.Errorf("subject_token is not a supported JWS: %w", err)
	}
	if len(jws.Signatures) != 1 {
		return "", nil, nil, fmt.Errorf("subject_token must carry exactly one signature")
	}

	// Read the issuer from the (still unverified) claims only to select which
	// issuer's keys to verify against; every claim is re-checked after
	// verification, so a forged iss just picks keys that will not verify.
	unverified, err := decodeJWTClaims(token)
	if err != nil {
		return "", nil, nil, err
	}
	issuer, ok := v.issuers[unverified.Issuer]
	if !ok {
		return "", nil, nil, fmt.Errorf("subject_token issuer is not trusted")
	}

	keys, err := v.jwksFor(ctx, issuer.JWKSURI)
	if err != nil {
		return "", nil, nil, fmt.Errorf("could not load issuer keys: %w", err)
	}
	payload, err := verifyWithKeySet(jws, keys, issuer.JWKSURI, v)
	if err != nil {
		return "", nil, nil, err
	}

	var claims jwtClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", nil, nil, fmt.Errorf("subject_token claims are not valid JSON")
	}
	now := v.now()
	switch {
	case claims.Issuer != issuer.Issuer:
		return "", nil, nil, fmt.Errorf("subject_token iss mismatch")
	case claims.Subject == "":
		return "", nil, nil, fmt.Errorf("subject_token has no subject")
	case !claims.Audience.contains(issuer.Audience):
		return "", nil, nil, fmt.Errorf("subject_token audience does not include this server")
	case claims.Expiry == 0 || now.After(time.Unix(claims.Expiry, 0).Add(jwtClockLeeway)):
		return "", nil, nil, fmt.Errorf("subject_token is expired")
	case claims.NotBefore != 0 && now.Add(jwtClockLeeway).Before(time.Unix(claims.NotBefore, 0)):
		return "", nil, nil, fmt.Errorf("subject_token is not yet valid")
	}

	identity := claims.Subject + "@" + issuer.IdentityDomain
	return identity, claims.Groups, issuer.AllowedScopes, nil
}

// verifyWithKeySet verifies the JWS against the key matching its kid, refetching
// the JWKS once on a kid miss (key rotation).
func verifyWithKeySet(jws *jose.JSONWebSignature, keys *jose.JSONWebKeySet, jwksURI string, v *extIssuerValidator) ([]byte, error) {
	kid := jws.Signatures[0].Header.KeyID
	try := func(ks *jose.JSONWebKeySet) ([]byte, bool) {
		candidates := ks.Keys
		if kid != "" {
			candidates = ks.Key(kid)
		}
		for i := range candidates {
			if payload, err := jws.Verify(candidates[i]); err == nil {
				return payload, true
			}
		}
		return nil, false
	}
	if payload, ok := try(keys); ok {
		return payload, nil
	}
	// A kid we have not seen may be a rotated key: drop the cache and retry once.
	if fresh, err := v.refetchJWKS(context.Background(), jwksURI); err == nil {
		if payload, ok := try(fresh); ok {
			return payload, nil
		}
	}
	return nil, fmt.Errorf("subject_token signature does not verify against the issuer keys")
}

func (v *extIssuerValidator) jwksFor(ctx context.Context, jwksURI string) (*jose.JSONWebKeySet, error) {
	v.mu.Lock()
	if e, ok := v.cache[jwksURI]; ok && v.now().Before(e.expiry) {
		v.mu.Unlock()
		return e.keys, nil
	}
	v.mu.Unlock()
	return v.refetchJWKS(ctx, jwksURI)
}

func (v *extIssuerValidator) refetchJWKS(ctx context.Context, jwksURI string) (*jose.JSONWebKeySet, error) {
	body, err := v.fetch(ctx, jwksURI)
	if err != nil {
		return nil, err
	}
	var ks jose.JSONWebKeySet
	if err := json.Unmarshal(body, &ks); err != nil {
		return nil, fmt.Errorf("JWKS is not valid JSON: %w", err)
	}
	v.mu.Lock()
	v.cache[jwksURI] = jwksEntry{keys: &ks, expiry: v.now().Add(jwksCacheTTL)}
	v.mu.Unlock()
	return &ks, nil
}

// decodeJWTClaims reads a JWT's claims WITHOUT verifying the signature. Used
// only to read the issuer so the right verification key can be selected; every
// claim is re-validated after signature verification.
func decodeJWTClaims(token string) (jwtClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return jwtClaims{}, fmt.Errorf("subject_token is not a JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return jwtClaims{}, fmt.Errorf("subject_token payload is not base64url")
	}
	var c jwtClaims
	if err := json.Unmarshal(payload, &c); err != nil {
		return jwtClaims{}, fmt.Errorf("subject_token claims are not valid JSON")
	}
	return c, nil
}

// httpGetLimited GETs a URL with a bounded body. The caller passes an
// SSRF-hardened client (cimdHTTPClient) for any input-derived URL.
func httpGetLimited(ctx context.Context, client *http.Client, u string, maxBytes int64) ([]byte, error) {
	//nolint:gosec // G704: JWKS URL comes from operator config and is fetched with the SSRF-guarded CIMD client
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	//nolint:gosec // G704: see above
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch %s: HTTP %d", u, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxBytes))
}
