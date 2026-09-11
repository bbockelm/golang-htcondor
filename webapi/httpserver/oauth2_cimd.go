package httpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ory/fosite"
)

// CIMD (Client ID Metadata Document) lets an MCP client identify itself by an
// https:// URL instead of registering (DCR). When a client_id is such a URL, the
// authorization server fetches a JSON client-metadata document from it and
// treats the result as a PUBLIC client (no secret; PKCE enforced via
// EnforcePKCEForPublicClients). This is the direction the MCP auth spec is
// moving, away from every client having to DCR.
//
// The document is attacker-influenced input fetched server-side, so the fetch is
// hardened against SSRF: https only, no redirects, a short timeout, a small body
// cap, and -- crucially -- a per-connection check of the RESOLVED IP that
// rejects loopback/private/link-local/etc. (blocking DNS rebinding to internal
// addresses, including the cloud metadata endpoint). An optional host allowlist
// narrows it further; empty means "any host, guards still apply".

const (
	cimdFetchTimeout = 5 * time.Second
	cimdMaxBodyBytes = 64 * 1024
	cimdCacheTTL     = 10 * time.Minute
	cimdNegCacheTTL  = 1 * time.Minute
)

// isCIMDClientID reports whether a client_id should be resolved as a Client ID
// Metadata Document URL rather than looked up in the client table. Only https is
// accepted -- a CIMD URL is fetched, so plaintext http is never valid.
func isCIMDClientID(clientID string) bool {
	return strings.HasPrefix(clientID, "https://")
}

// cimdMetadataDocument is the subset of RFC 7591 client metadata a CIMD document
// carries that we act on.
type cimdMetadataDocument struct {
	ClientID                string   `json:"client_id"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	Scope                   string   `json:"scope"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	ClientName              string   `json:"client_name"`
}

type cimdCacheEntry struct {
	client *fosite.DefaultClient
	err    error
	expiry time.Time
}

// cimdResolver fetches and caches CIMD documents, turning a URL client_id into a
// public *fosite.DefaultClient.
type cimdResolver struct {
	// allowedHosts, when non-empty, restricts CIMD to these hosts. A pattern is
	// matched exactly or as a parent domain (".example.org" matches
	// "mcp.example.org"). Empty = any host (SSRF guards still apply).
	allowedHosts []string
	client       *http.Client
	now          func() time.Time

	mu    sync.Mutex
	cache map[string]cimdCacheEntry
}

// newCIMDResolver builds a resolver. client is injected so production can pass an
// SSRF-guarded client (cimdHTTPClient) while tests can point one at httptest.
func newCIMDResolver(allowedHosts []string, client *http.Client) *cimdResolver {
	return &cimdResolver{
		allowedHosts: allowedHosts,
		client:       client,
		now:          time.Now,
		cache:        make(map[string]cimdCacheEntry),
	}
}

// cimdHTTPClient is the production HTTP client for CIMD fetches: it refuses to
// dial a disallowed IP (checked on the resolved address, so DNS rebinding cannot
// slip an internal host past), follows no redirects, and bounds the fetch time.
func cimdHTTPClient() *http.Client {
	dialer := &net.Dialer{
		Timeout: cimdFetchTimeout,
		Control: func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return fmt.Errorf("cimd: bad dial address %q: %w", address, err)
			}
			ip := net.ParseIP(host)
			if ip == nil || isDisallowedIP(ip) {
				return fmt.Errorf("cimd: refusing to connect to non-public address %q", host)
			}
			return nil
		},
	}
	return &http.Client{
		Timeout: cimdFetchTimeout,
		Transport: &http.Transport{
			DialContext:           dialer.DialContext,
			TLSHandshakeTimeout:   cimdFetchTimeout,
			ResponseHeaderTimeout: cimdFetchTimeout,
			DisableKeepAlives:     true,
		},
		// A CIMD document must live at its own URL; a redirect to somewhere else
		// would break the client_id==URL binding and is a classic SSRF pivot.
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return fmt.Errorf("cimd: redirects are not allowed")
		},
	}
}

// isDisallowedIP reports whether an IP must not be dialed for a CIMD fetch: any
// address that is not a routable public host. Pure, so it is unit-tested
// directly (the happy-path fetch test cannot go through the guarded dialer,
// since httptest binds loopback).
func isDisallowedIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() ||
		ip.IsInterfaceLocalMulticast() {
		return true
	}
	// 100.64.0.0/10 (RFC 6598 carrier-grade NAT) is not covered by IsPrivate.
	if v4 := ip.To4(); v4 != nil && v4[0] == 100 && v4[1]&0xc0 == 0x40 {
		return true
	}
	return false
}

// hostAllowed applies the optional allowlist.
func (r *cimdResolver) hostAllowed(host string) bool {
	if len(r.allowedHosts) == 0 {
		return true
	}
	host = strings.ToLower(host)
	for _, pat := range r.allowedHosts {
		pat = strings.ToLower(strings.TrimSpace(pat))
		if pat == "" {
			continue
		}
		if strings.HasPrefix(pat, ".") {
			if host == pat[1:] || strings.HasSuffix(host, pat) {
				return true
			}
			continue
		}
		if host == pat {
			return true
		}
	}
	return false
}

// resolve turns a CIMD URL into a public client, caching the result (and, briefly,
// failures). Returns fosite.ErrInvalidClient for a URL that is structurally or
// policy-invalid, so the token/authorize endpoints surface a clean OAuth error.
func (r *cimdResolver) resolve(ctx context.Context, clientID string) (fosite.Client, error) {
	now := r.now()
	r.mu.Lock()
	if e, ok := r.cache[clientID]; ok && now.Before(e.expiry) {
		r.mu.Unlock()
		if e.err != nil {
			return nil, e.err
		}
		return e.client, nil
	}
	r.mu.Unlock()

	client, err := r.fetch(ctx, clientID)

	r.mu.Lock()
	ttl := cimdCacheTTL
	if err != nil {
		ttl = cimdNegCacheTTL
	}
	r.cache[clientID] = cimdCacheEntry{client: client, err: err, expiry: now.Add(ttl)}
	r.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return client, nil
}

func (r *cimdResolver) fetch(ctx context.Context, clientID string) (*fosite.DefaultClient, error) {
	u, err := url.Parse(clientID)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" {
		return nil, fosite.ErrInvalidClient.WithHint("client_id is not a valid CIMD URL")
	}
	if !r.hostAllowed(u.Hostname()) {
		return nil, fosite.ErrInvalidClient.WithHint("client_id host is not an allowed CIMD source")
	}

	// G704 (SSRF): fetching an input-derived URL is the whole point of CIMD.
	// It is hardened, not unchecked: cimdHTTPClient's dialer rejects any
	// resolved non-public IP (loopback/private/link-local/CGNAT/metadata),
	// redirects are refused, and an optional host allowlist narrows it further.
	//nolint:gosec // G704: intentional, SSRF-guarded CIMD fetch (see above)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, clientID, nil)
	if err != nil {
		return nil, fosite.ErrInvalidClient.WithHint("could not build CIMD request")
	}
	req.Header.Set("Accept", "application/json")
	//nolint:gosec // G704: intentional, SSRF-guarded CIMD fetch (see above)
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, fosite.ErrInvalidClient.WithHintf("could not fetch CIMD document: %s", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fosite.ErrInvalidClient.WithHintf("CIMD document fetch returned HTTP %d", resp.StatusCode)
	}

	var doc cimdMetadataDocument
	if err := json.NewDecoder(io.LimitReader(resp.Body, cimdMaxBodyBytes)).Decode(&doc); err != nil {
		return nil, fosite.ErrInvalidClient.WithHint("CIMD document is not valid JSON")
	}
	// The document must claim exactly the URL it was fetched from -- the binding
	// that stops one client's URL from vouching for another's metadata.
	if doc.ClientID != clientID {
		return nil, fosite.ErrInvalidClient.WithHint("CIMD document client_id does not match its URL")
	}
	if len(doc.RedirectURIs) == 0 {
		return nil, fosite.ErrInvalidClient.WithHint("CIMD document has no redirect_uris")
	}
	// We can only act as a public client for a CIMD id: there is no shared secret
	// to authenticate one. Reject a document that asks for confidential auth.
	if m := doc.TokenEndpointAuthMethod; m != "" && m != "none" {
		return nil, fosite.ErrInvalidClient.WithHint("CIMD clients must use token_endpoint_auth_method=none")
	}

	return &fosite.DefaultClient{
		ID:            clientID,
		Public:        true,
		RedirectURIs:  doc.RedirectURIs,
		GrantTypes:    []string{"authorization_code", "refresh_token"},
		ResponseTypes: []string{"code"},
		Scopes:        cimdClientScopes(doc.Scope),
	}, nil
}

// cimdClientScopes is the scope set a CIMD client may request: the advertised
// set, narrowed to what the document declares when it declares any (least
// privilege when the client is specific, parity with a DCR client otherwise).
// The user still consents and the schedd's ALLOW_<LEVEL> still gates, so this
// bounds what can be *asked for*, not what is granted.
func cimdClientScopes(declared string) []string {
	if strings.TrimSpace(declared) == "" {
		return append([]string(nil), oauth2AdvertisedScopes...)
	}
	advertised := make(map[string]bool, len(oauth2AdvertisedScopes))
	for _, s := range oauth2AdvertisedScopes {
		advertised[s] = true
	}
	var out []string
	for _, s := range strings.Fields(declared) {
		if advertised[s] {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		// Declared only unknown scopes; fall back to offline_access so refresh
		// still works, plus the read scope, rather than an empty (unusable) set.
		return []string{"openid", "offline_access", "mcp:read"}
	}
	return out
}
