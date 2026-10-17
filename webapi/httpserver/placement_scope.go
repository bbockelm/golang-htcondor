package httpserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/ory/fosite"

	"github.com/bbockelm/golang-htcondor/logging"
)

// The placement scope (§7.3a): placement-client signs in through this
// server's own RFC 8628 device grant as the pre-registered public client
// placement_client and gets an access token holding "placement". That token
// reaches GET /api/v1/placement/me and POST /api/v1/placement/me/token and
// nothing else; the identity it acts for is the one that approved the grant,
// recorded on the grant's session.

const (
	// placementScope is the scope a placement grant holds.
	placementScope = "placement"
	// placementClientID is the pre-registered client placement-client uses.
	placementClientID = "placement_client"
)

// placementClientScopes are the only scopes placement_client may hold.
var placementClientScopes = []string{placementScope, "offline_access"}

// isPlacementGrant reports whether scopes hold the placement scope.
func isPlacementGrant(scopes []string) bool {
	return slices.Contains(scopes, placementScope)
}

// placementScopeMixError reports a request that asks for placement together
// with any scope other than offline_access: a placement grant is for
// placement and nothing else.
func placementScopeMixError(scopes []string) bool {
	if !isPlacementGrant(scopes) {
		return false
	}
	for _, s := range scopes {
		if s != placementScope && s != "offline_access" {
			return true
		}
	}
	return false
}

// placementOnlyScopes reports whether a grant's scopes are within
// {placement, offline_access} and include placement.
func placementOnlyScopes(scopes []string) bool {
	return isPlacementGrant(scopes) && !placementScopeMixError(scopes)
}

// seedPlacementClient makes sure placement_client exists: a public client
// with the device and refresh grants, allowed only the placement scopes.
func (h *Handler) seedPlacementClient(ctx context.Context) error {
	storage := h.oauth2Provider.GetStorage()
	if c, err := storage.GetClient(ctx, placementClientID); err == nil {
		if slices.Equal(c.GetScopes(), placementClientScopes) {
			return nil
		}
		// A client by this name with any other scope set would let the
		// placement scope ride along with something else.
		h.logger.Warn(logging.DestinationHTTP, "Resetting the placement client's scopes",
			"client_id", placementClientID, "had", c.GetScopes())
		scopes, _ := json.Marshal(placementClientScopes)
		grants, _ := json.Marshal([]string{deviceCodeGrant, "refresh_token"})
		_, err := storage.db.ExecContext(ctx,
			`UPDATE oauth2_clients SET scopes = ?, grant_types = ?, public = 1, client_secret = '' WHERE id = ?`,
			string(scopes), string(grants), placementClientID)
		return err
	}
	client := &fosite.DefaultClient{
		ID:         placementClientID,
		GrantTypes: []string{deviceCodeGrant, "refresh_token"},
		Scopes:     placementClientScopes,
		Public:     true,
	}
	if err := storage.CreateClient(ctx, client); err != nil {
		return err
	}
	h.markSeededClient(ctx, placementClientID, "placement-client")
	return nil
}

// placementBearerGate keeps a bearer token holding the placement scope to
// the two endpoints it is for. Every other route refuses it before a handler
// runs: such a token's subject may be a local user or empty, and nothing
// else should mint, list or act for it. It reports whether it refused.
//
// Whether a bearer holds the scope is cached by the token's hash: a grant's
// placement scope never changes (it can neither be added to nor removed
// from a grant; see the admin scope editor), so the answer is stable.
func (h *Handler) placementBearerGate(w http.ResponseWriter, r *http.Request) bool {
	if h.oauth2Provider == nil {
		return false
	}
	bearer, err := extractBearerToken(r)
	if err != nil || bearer == "" {
		return false
	}
	if placementBearerAllowed(r.Method, r.URL.Path) {
		return false
	}
	if !h.placementOnboard.bearers.holdsPlacement(r.Context(), h, bearer) {
		return false
	}
	h.writeError(w, http.StatusForbidden, "A placement token can only request a placement token.")
	return true
}

// placementBearerAllowed is what a placement bearer may call.
func placementBearerAllowed(method, path string) bool {
	path = strings.TrimSuffix(path, "/")
	return (method == http.MethodGet && path == "/api/v1/placement/me") ||
		(method == http.MethodPost && path == "/api/v1/placement/me/token")
}

// placementBearerCache remembers which bearers hold the placement scope.
type placementBearerCache struct {
	mu      sync.Mutex
	entries map[string]placementBearerEntry
}

type placementBearerEntry struct {
	placement bool
	until     time.Time
}

const placementBearerCacheMax = 10000

func (c *placementBearerCache) holdsPlacement(ctx context.Context, h *Handler, bearer string) bool {
	sum := sha256.Sum256([]byte(bearer))
	key := hex.EncodeToString(sum[:])
	now := time.Now()
	c.mu.Lock()
	if e, ok := c.entries[key]; ok && now.Before(e.until) {
		c.mu.Unlock()
		return e.placement
	}
	c.mu.Unlock()

	placement := false
	until := now.Add(time.Hour)
	if ar, err := h.oauth2Provider.IntrospectAccessToken(ctx, bearer); err == nil {
		placement = isPlacementGrant(ar.GetGrantedScopes())
		if exp := ar.GetSession().GetExpiresAt(fosite.AccessToken); !exp.IsZero() && exp.Before(until) {
			until = exp
		}
	} else {
		// Not a token this server issued, or not live: nothing to keep
		// out here, and the handler will refuse it if it must. Not
		// cached for long, so a token issued a moment later is seen.
		until = now.Add(time.Minute)
	}
	c.mu.Lock()
	if c.entries == nil || len(c.entries) >= placementBearerCacheMax {
		c.entries = make(map[string]placementBearerEntry)
	}
	c.entries[key] = placementBearerEntry{placement: placement, until: until}
	c.mu.Unlock()
	return placement
}

// placementBearerIdentity authenticates a placement bearer for the /me
// endpoints: the identity is the one on the grant's session, never the
// request's.
func (h *Handler) placementBearerIdentity(r *http.Request) (*SessionData, bool, error) {
	bearer, err := extractBearerToken(r)
	if err != nil || bearer == "" || h.oauth2Provider == nil {
		return nil, false, nil
	}
	ar, err := h.oauth2Provider.IntrospectAccessToken(r.Context(), bearer)
	if err != nil {
		return nil, true, err
	}
	if !isPlacementGrant(ar.GetGrantedScopes()) {
		return nil, true, errNotPlacementBearer
	}
	sess, ok := sessionFrom(ar)
	if !ok || sess.PlacementIdentity == "" {
		return nil, true, errNotPlacementBearer
	}
	return &SessionData{PlacementIdentity: sess.PlacementIdentity, Scope: sessionScopePlacement}, true, nil
}

var errNotPlacementBearer = fosite.ErrInvalidScope.WithHint("this token does not hold the placement scope")
