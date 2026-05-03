package httpserver

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/bbockelm/cedar/security"
	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/logging"
)

// Default and maximum lifetimes for shared download URLs. Kept short by
// design — the signed URL is meant for "drop this in chat so a colleague
// can grab the output", not for long-term sharing.
const (
	defaultShareTTL = 10 * time.Minute
	maxShareTTL     = 1 * time.Hour
)

// sharePayload is the data carried inside a signed URL token. We keep it
// tight: anything richer (e.g. a per-share revocation list) would need
// persistent state, which is out of scope for short-lived ephemeral
// shares.
type sharePayload struct {
	Cluster int    `json:"c"`
	Proc    int    `json:"p"`
	Owner   string `json:"o"`
	Exp     int64  `json:"e"`
}

// signShareToken produces a URL-safe token of the form base64(payload).base64(hmac).
// The HMAC is over the base64 payload bytes so verifiers don't need to
// JSON-parse anything before deciding the token is authentic.
func (s *Handler) signShareToken(p sharePayload) (string, error) {
	if len(s.shareSecret) == 0 {
		return "", fmt.Errorf("share secret not initialized")
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	enc := base64.RawURLEncoding.EncodeToString(raw)
	mac := hmac.New(sha256.New, s.shareSecret)
	mac.Write([]byte(enc))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return enc + "." + sig, nil
}

// verifyShareToken parses, authenticates, and expiry-checks a token.
// Returns the payload only when the token is fully valid.
func (s *Handler) verifyShareToken(tok string) (*sharePayload, error) {
	if len(s.shareSecret) == 0 {
		return nil, fmt.Errorf("share secret not initialized")
	}
	dot := strings.IndexByte(tok, '.')
	if dot <= 0 || dot == len(tok)-1 {
		return nil, fmt.Errorf("malformed token")
	}
	encPayload, encSig := tok[:dot], tok[dot+1:]

	mac := hmac.New(sha256.New, s.shareSecret)
	mac.Write([]byte(encPayload))
	expectSig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(expectSig), []byte(encSig)) {
		return nil, fmt.Errorf("invalid signature")
	}

	raw, err := base64.RawURLEncoding.DecodeString(encPayload)
	if err != nil {
		return nil, fmt.Errorf("invalid payload encoding: %w", err)
	}
	var p sharePayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("invalid payload: %w", err)
	}
	if time.Now().Unix() > p.Exp {
		return nil, fmt.Errorf("token expired")
	}
	return &p, nil
}

// shareURLBase returns the absolute URL prefix to use when minting share
// URLs. Falls back to deriving from the request when HTTPBaseURL is not
// configured — works for typical deployments behind a single proxy/host.
func (s *Handler) shareURLBase(r *http.Request) string {
	if s.httpBaseURL != "" {
		return strings.TrimRight(s.httpBaseURL, "/")
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		scheme = proto
	}
	host := r.Host
	if fwd := r.Header.Get("X-Forwarded-Host"); fwd != "" {
		host = fwd
	}
	return fmt.Sprintf("%s://%s", scheme, host)
}

// ShareOutputRequest is the body for POST /api/v1/jobs/{id}/output/share.
type ShareOutputRequest struct {
	TTLSeconds int `json:"ttl_seconds,omitempty"`
}

// ShareOutputResponse is what the SPA gets back. Owner is echoed for UX
// so the share preview can label the URL with "downloads as <owner>".
type ShareOutputResponse struct {
	URL        string    `json:"url"`
	ExpiresAt  time.Time `json:"expires_at"`
	TTLSeconds int       `json:"ttl_seconds"`
	Owner      string    `json:"owner"`
}

// handleJobOutputShare handles POST /api/v1/jobs/{id}/output/share.
// Mints a short-lived URL that anyone can use to download the job's
// sandbox without authenticating. The URL is bound to one specific job
// and to the requesting user (the URL impersonates them at redeem time).
func (s *Handler) handleJobOutputShare(w http.ResponseWriter, r *http.Request, jobID string) {
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Public shares need to act on behalf of the job owner at redeem time;
	// that requires a signing key for JWT minting. Bail early with a
	// helpful message rather than producing an unusable URL.
	if s.signingKeyPath == "" {
		s.writeError(w, http.StatusNotImplemented,
			"Share URLs require HTTP_API_SIGNING_KEY (or SEC_TOKEN_POOL_SIGNING_KEY_FILE) to be configured")
		return
	}

	ctx, needsRedirect, err := s.requireAuthentication(r)
	if err != nil {
		if needsRedirect {
			s.redirectToLogin(w, r)
			return
		}
		s.writeError(w, http.StatusUnauthorized, fmt.Sprintf("Authentication failed: %v", err))
		return
	}

	cluster, proc, err := parseJobID(jobID)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid job ID: %v", err))
		return
	}

	// TTL: default 10m, max 1h, sub-zero clamped to default.
	ttl := defaultShareTTL
	if r.Body != nil && r.ContentLength != 0 {
		var req ShareOutputRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err == nil && req.TTLSeconds > 0 {
			ttl = time.Duration(req.TTLSeconds) * time.Second
			if ttl > maxShareTTL {
				ttl = maxShareTTL
			}
		}
	}

	// Owner = authenticated user without "@uidDomain" — schedd's Owner
	// attribute uses the bare username; we re-add the suffix at redeem
	// time when minting the JWT.
	owner := strings.SplitN(htcondor.GetAuthenticatedUserFromContext(ctx), "@", 2)[0]
	if owner == "" {
		s.writeError(w, http.StatusUnauthorized, "Could not determine authenticated user")
		return
	}

	exp := time.Now().Add(ttl)
	tok, err := s.signShareToken(sharePayload{
		Cluster: cluster,
		Proc:    proc,
		Owner:   owner,
		Exp:     exp.Unix(),
	})
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to sign token: %v", err))
		return
	}

	url := fmt.Sprintf("%s/api/v1/share/output?t=%s", s.shareURLBase(r), tok)
	s.writeJSON(w, http.StatusOK, ShareOutputResponse{
		URL:        url,
		ExpiresAt:  exp,
		TTLSeconds: int(ttl.Seconds()),
		Owner:      owner,
	})
}

// handleSharedOutput handles GET /api/v1/share/output?t=<token>.
// Verifies the token, mints a fresh server-signed JWT for the embedded
// owner, and streams the job's sandbox as a tar. Possession of the URL
// is the only auth — the SPA's session cookie is intentionally ignored.
func (s *Handler) handleSharedOutput(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if s.signingKeyPath == "" {
		s.writeError(w, http.StatusNotImplemented, "Share URLs are not configured")
		return
	}

	tok := r.URL.Query().Get("t")
	if tok == "" {
		s.writeError(w, http.StatusBadRequest, "Missing token")
		return
	}
	payload, err := s.verifyShareToken(tok)
	if err != nil {
		// Don't leak which check failed (signature vs expiry).
		s.logger.Info(logging.DestinationHTTP, "Share token rejected", "error", err)
		s.writeError(w, http.StatusUnauthorized, "Invalid or expired token")
		return
	}

	// Mint an internal JWT for the original owner with a tight expiry.
	// Re-add the @uidDomain suffix the schedd's Owner attribute lacks.
	username := payload.Owner
	if !strings.Contains(username, "@") {
		if s.uidDomain == "" {
			s.writeError(w, http.StatusInternalServerError,
				"UID_DOMAIN not configured; cannot redeem share token")
			return
		}
		username = username + "@" + s.uidDomain
	}
	if s.trustDomain == "" {
		s.writeError(w, http.StatusInternalServerError,
			"TRUST_DOMAIN not configured; cannot redeem share token")
		return
	}

	now := time.Now()
	jwt, err := security.GenerateJWT(
		filepath.Dir(s.signingKeyPath),
		filepath.Base(s.signingKeyPath),
		username,
		s.trustDomain,
		now.Unix(),
		now.Add(2*time.Minute).Unix(),
		nil,
	)
	if err != nil {
		s.logger.Error(logging.DestinationHTTP, "Failed to mint redeem JWT", "error", err)
		s.writeError(w, http.StatusInternalServerError, "Failed to authorize download")
		return
	}

	// Build a SecurityConfig the schedd-facing code can use. WithToken
	// alone is not enough — every schedd path now reads the SecurityConfig
	// directly from ctx (see schedd_transfer.go, NewQmgmtConnection).
	// Mirrors the tail of createAuthenticatedContext: cache the JWT,
	// build a TOKEN-only security config, attach it + the username for
	// rate limiting.
	entry, err := s.tokenCache.AddValidated(jwt, username, now.Add(2*time.Minute))
	if err != nil {
		s.logger.Error(logging.DestinationHTTP, "Failed to cache redeem JWT", "error", err)
		s.writeError(w, http.StatusInternalServerError, "Failed to authorize download")
		return
	}
	secConfig, err := ConfigureSecurityForTokenWithCacheAndFallback(jwt, entry.SessionCache, false)
	if err != nil {
		s.logger.Error(logging.DestinationHTTP, "Failed to build security config for share", "error", err)
		s.writeError(w, http.StatusInternalServerError, "Failed to authorize download")
		return
	}
	ctx := WithToken(r.Context(), jwt)
	ctx = htcondor.WithSecurityConfig(ctx, secConfig)
	ctx = htcondor.WithAuthenticatedUser(ctx, username)

	jobID := fmt.Sprintf("%d.%d", payload.Cluster, payload.Proc)
	constraint := fmt.Sprintf("ClusterId == %d && ProcId == %d", payload.Cluster, payload.Proc)

	w.Header().Set("Content-Type", "application/x-tar")
	w.Header().Set("Content-Disposition",
		fmt.Sprintf("attachment; filename=\"job-%s-output.tar\"", jobID))
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	w.WriteHeader(http.StatusOK)

	errChan := s.getSchedd().ReceiveJobSandbox(ctx, constraint, w)
	if err := <-errChan; err != nil {
		// Headers and body already started; just log.
		s.logger.Error(logging.DestinationSchedd,
			"Error streaming shared sandbox", "job_id", jobID, "error", err)
	}
}
