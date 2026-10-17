package httpserver

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/webapi/httpserver/appdb/seal"
)

// The placement device flow is a wire-compatible stand-in for
// placement-webapp's /auth/device_authorization, which placement-client
// (github.com/htcondor/placement-client) and `curl` scripts speak.
//
// Byte-for-byte compatibility is the point. pdwebapp is a Flask app built on
// authlib's RFC 8628 classes, so every response here is what that stack
// writes: JSON from Python's json.dumps with sorted keys and ", " / ": "
// separators, the authlib error bodies, and pdwebapp's own success body
// {"access_token": "<jwt>\n", "expires_in": "<seconds>", "token_type":
// "Placement"}, whose trailing newline and string-typed expires_in existing
// clients rely on.
//
// It is deliberately separate from this server's own fosite device grant
// (device_code_handler.go), which issues this server's OAuth2 tokens.

const (
	placementDeviceGrantType = "urn:ietf:params:oauth:grant-type:device_code"
	// placementDeviceExpiresIn and placementDeviceInterval are authlib's
	// DeviceAuthorizationEndpoint.EXPIRES_IN and pdwebapp's INTERVAL.
	placementDeviceExpiresIn = 1800
	placementDeviceInterval  = 5
	// placementDeviceSlowDownSlack is pdwebapp's SLOW_DOWN_SLACK: a poll
	// up to one second early is not "too fast".
	placementDeviceSlowDownSlack = 1
	// placementUserCodeAlphabet is authlib's create_string_user_code
	// alphabet: consonants only, so a code cannot spell a word.
	placementUserCodeAlphabet = "BCDFGHJKLMNPQRSTVWXZ"
	// placementDeviceCodeAlphabet and length are authlib's generate_token(42).
	placementDeviceCodeAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	placementDeviceCodeLength   = 42

	placementDeviceStatePending  = "pending"
	placementDeviceStateApproved = "approved"
	placementDeviceStateDenied   = "denied"
)

var placementUserCodeRE = regexp.MustCompile(`^[A-Z]{4}-[A-Z]{4}$`)

// normalizePlacementUserCode is pdwebapp's _resolve_user_code clean-up:
// strip, upper-case, at most nine characters. It returns "" when the result
// is not a well-formed code.
func normalizePlacementUserCode(raw string) string {
	code := strings.ToUpper(strings.TrimSpace(raw))
	if r := []rune(code); len(r) > 9 {
		code = string(r[:9])
	}
	if !placementUserCodeRE.MatchString(code) {
		return ""
	}
	return code
}

// placementDeviceGrant is one row of placement_device_grants.
type placementDeviceGrant struct {
	DeviceCodeHash string
	UserCode       string
	ClientID       string
	CreatedAt      int64
	ExpiresAt      int64
	Interval       int64
	LastPoll       int64
	State          string
	ForeignID      string
	// Token is the unsealed placement token once approved, "" before.
	Token          string
	TokenExpiresAt int64
}

// expired is pdwebapp's DeviceCredential.is_expired.
func (g *placementDeviceGrant) expired(now int64) bool {
	return g.ExpiresAt != 0 && g.ExpiresAt < now
}

// placementDeviceStore keeps pending grants in the application database.
type placementDeviceStore struct {
	db     *sql.DB
	sealer *seal.Sealer
	now    func() time.Time
}

var errPlacementDeviceGrantGone = errors.New("the device request is no longer pending")

func randomFromAlphabet(alphabet string, n int) (string, error) {
	var b strings.Builder
	limit := big.NewInt(int64(len(alphabet)))
	for range n {
		i, err := rand.Int(rand.Reader, limit)
		if err != nil {
			return "", err
		}
		b.WriteByte(alphabet[i.Int64()])
	}
	return b.String(), nil
}

// create records a new pending grant and returns its device and user codes.
func (s *placementDeviceStore) create(ctx context.Context, clientID string) (deviceCode, userCode string, err error) {
	now := s.now().Unix()
	s.sweep(ctx)
	for attempt := 0; attempt < 5; attempt++ {
		deviceCode, err = randomFromAlphabet(placementDeviceCodeAlphabet, placementDeviceCodeLength)
		if err != nil {
			return "", "", err
		}
		a, err := randomFromAlphabet(placementUserCodeAlphabet, 4)
		if err != nil {
			return "", "", err
		}
		b, err := randomFromAlphabet(placementUserCodeAlphabet, 4)
		if err != nil {
			return "", "", err
		}
		userCode = a + "-" + b
		_, err = s.db.ExecContext(ctx, `INSERT INTO placement_device_grants
			(device_code_hash, user_code, client_id, created_at, expires_at, interval, state)
			VALUES (?, ?, ?, ?, ?, ?, ?)`,
			sessionKey(deviceCode), userCode, clientID, now, now+placementDeviceExpiresIn,
			placementDeviceInterval, placementDeviceStatePending)
		if err == nil {
			return deviceCode, userCode, nil
		}
		// A user code collision fails the UNIQUE constraint; draw again.
		if !strings.Contains(strings.ToLower(err.Error()), "unique") {
			return "", "", err
		}
	}
	return "", "", fmt.Errorf("could not draw an unused user code")
}

const placementDeviceColumns = `device_code_hash, user_code, client_id, created_at, expires_at, interval,
	last_poll, state, foreign_id, token_sealed, token_dek, token_expires_at`

func (s *placementDeviceStore) scan(row *sql.Row) (*placementDeviceGrant, error) {
	var g placementDeviceGrant
	var sealed, dek []byte
	err := row.Scan(&g.DeviceCodeHash, &g.UserCode, &g.ClientID, &g.CreatedAt, &g.ExpiresAt, &g.Interval,
		&g.LastPoll, &g.State, &g.ForeignID, &sealed, &dek, &g.TokenExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if len(sealed) > 0 {
		plain := sealed
		if len(dek) > 0 {
			if s.sealer == nil {
				return nil, errors.New("the device token is sealed but no KEK is configured (HTTP_API_KEK_FILE)")
			}
			if plain, err = s.sealer.Open(sealed, dek); err != nil {
				return nil, fmt.Errorf("unsealing the device token: %w", err)
			}
		}
		g.Token = string(plain)
	}
	return &g, nil
}

func (s *placementDeviceStore) byDeviceCode(ctx context.Context, deviceCode string) (*placementDeviceGrant, error) {
	return s.scan(s.db.QueryRowContext(ctx,
		`SELECT `+placementDeviceColumns+` FROM placement_device_grants WHERE device_code_hash = ?`,
		sessionKey(deviceCode)))
}

func (s *placementDeviceStore) byUserCode(ctx context.Context, userCode string) (*placementDeviceGrant, error) {
	return s.scan(s.db.QueryRowContext(ctx,
		`SELECT `+placementDeviceColumns+` FROM placement_device_grants WHERE user_code = ?`, userCode))
}

func (s *placementDeviceStore) touchPoll(ctx context.Context, hash string, now int64) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE placement_device_grants SET last_poll = ? WHERE device_code_hash = ?`, now, hash)
	return err
}

// approve binds a token to a pending, unexpired grant. A grant that was
// meanwhile denied, approved or expired yields errPlacementDeviceGrantGone.
func (s *placementDeviceStore) approve(ctx context.Context, userCode, foreignID, token string, tokenExp int64) error {
	stored, dek := []byte(token), []byte(nil)
	if s.sealer != nil {
		var err error
		if stored, dek, err = s.sealer.Seal([]byte(token)); err != nil {
			return fmt.Errorf("sealing the device token: %w", err)
		}
	}
	res, err := s.db.ExecContext(ctx, `UPDATE placement_device_grants
		SET state = ?, foreign_id = ?, token_sealed = ?, token_dek = ?, token_expires_at = ?
		WHERE user_code = ? AND state = ? AND expires_at >= ?`,
		placementDeviceStateApproved, foreignID, stored, dek, tokenExp,
		userCode, placementDeviceStatePending, s.now().Unix())
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errPlacementDeviceGrantGone
	}
	return nil
}

// deny refuses a pending, unexpired grant. Like pdwebapp's cancel_device,
// a grant that is already resolved or expired is left as it is, and that is
// not an error.
func (s *placementDeviceStore) deny(ctx context.Context, userCode, foreignID string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE placement_device_grants SET state = ?, foreign_id = ?
		WHERE user_code = ? AND state = ? AND expires_at >= ?`,
		placementDeviceStateDenied, foreignID, userCode, placementDeviceStatePending, s.now().Unix())
	return err
}

// consume deletes a grant whose token has been handed to its client.
func (s *placementDeviceStore) consume(ctx context.Context, hash string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM placement_device_grants WHERE device_code_hash = ?`, hash)
	return err
}

// sweep deletes expired grants, tokens included.
func (s *placementDeviceStore) sweep(ctx context.Context) {
	_, _ = s.db.ExecContext(ctx, `DELETE FROM placement_device_grants WHERE expires_at < ?`, s.now().Unix())
}

// --- Python-compatible JSON ---

// pyJSON renders a flat object the way Flask's json.dumps does by default:
// keys sorted, ", " and ": " separators, ASCII-only output with \uXXXX
// escapes. Values are strings or integers.
func pyJSON(obj map[string]any) []byte {
	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			b.WriteString(", ")
		}
		pyJSONString(&b, k)
		b.WriteString(": ")
		switch v := obj[k].(type) {
		case string:
			pyJSONString(&b, v)
		case int:
			b.WriteString(strconv.Itoa(v))
		case int64:
			b.WriteString(strconv.FormatInt(v, 10))
		default:
			panic(fmt.Sprintf("pyJSON: unsupported value type %T", v))
		}
	}
	b.WriteByte('}')
	return []byte(b.String())
}

func pyJSONString(b *strings.Builder, s string) {
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		default:
			switch {
			case r < 0x20 || (r >= 0x7f && r < 0x10000):
				if r == 0x7f {
					b.WriteRune(r)
				} else {
					fmt.Fprintf(b, `\u%04x`, r)
				}
			case r >= 0x10000:
				hi, lo := utf16.EncodeRune(r)
				fmt.Fprintf(b, `\u%04x\u%04x`, hi, lo)
			default:
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
}

// writePlacementDeviceJSON writes a response with authlib's
// default_json_headers.
func writePlacementDeviceJSON(w http.ResponseWriter, status int, body map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(status)
	_, _ = w.Write(pyJSON(body))
}

// placementOAuthError is an authlib OAuth2Error: status, error code and
// optional description.
type placementOAuthError struct {
	status      int
	code        string
	description string
	// basicChallenge adds authlib's WWW-Authenticate header, which it
	// sends with every 401 invalid_client.
	basicChallenge bool
}

func (e *placementOAuthError) write(w http.ResponseWriter) {
	body := map[string]any{"error": e.code}
	if e.description != "" {
		body["error_description"] = e.description
	}
	if e.basicChallenge {
		desc := strings.ReplaceAll(e.description, `"`, "|")
		w.Header().Set("WWW-Authenticate",
			`Basic error="`+e.code+`", error_description="`+desc+`"`)
	}
	writePlacementDeviceJSON(w, e.status, body)
}

const placementClientAuthMethods = "['client_secret_basic', 'client_secret_post', 'none']"

// authenticatePlacementDeviceClient is authlib's ClientAuthentication with
// methods [client_secret_basic, client_secret_post, none] and pdwebapp's
// DeviceClient, which has no secret: a client presenting one never
// authenticates, an unknown client_id is invalid_client, and a request
// with neither is the 401 authlib sends with a Basic challenge.
func (h *Handler) authenticatePlacementDeviceClient(r *http.Request) (string, *placementOAuthError) {
	known := h.placementOnboard.deviceClients
	unknown := func(status int) *placementOAuthError {
		return &placementOAuthError{status: status, code: "invalid_client",
			description: "The client does not exist on this server.", basicChallenge: status == http.StatusUnauthorized}
	}
	if id, secret, ok := r.BasicAuth(); ok && id != "" && secret != "" {
		if !known[id] {
			return "", unknown(http.StatusUnauthorized)
		}
		// Known, but a DeviceClient's secret check only passes an empty
		// secret: fall through to the next method.
	}
	// client_secret_post reads the form body only.
	if id, secret := r.PostForm.Get("client_id"), r.PostForm.Get("client_secret"); id != "" && secret != "" && !known[id] {
		return "", unknown(http.StatusBadRequest)
	}
	// none reads query and body together, as Flask's request.values.
	clientID := r.Form.Get("client_id")
	if clientID != "" && r.Form.Get("client_secret") == "" {
		if !known[clientID] {
			return "", unknown(http.StatusBadRequest)
		}
		return clientID, nil
	}
	return "", &placementOAuthError{status: http.StatusUnauthorized, code: "invalid_client",
		description:    "The client cannot authenticate with methods: " + placementClientAuthMethods,
		basicChallenge: true}
}

// handlePlacementDeviceAuthorization is POST /auth/device_authorization,
// multiplexed as pdwebapp does: a device_code with the device grant_type is
// a token poll, anything else asks for a new code.
func (h *Handler) handlePlacementDeviceAuthorization(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		h.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	po := &h.placementOnboard
	if po.devices == nil || !h.placementOnboardingEnabled(r.Context()) {
		h.writeError(w, http.StatusServiceUnavailable, "Placement tokens are not available on this server.")
		return
	}
	setBodyLimit(w, r, 1<<16)
	if err := r.ParseForm(); err != nil {
		writePlacementDeviceJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_request"})
		return
	}
	poll := r.PostForm.Get("device_code") != "" && r.PostForm.Get("grant_type") == placementDeviceGrantType

	if !po.deviceLimiter.Allow(clientIP(r, h.trustedProxies)) {
		if poll {
			// A client that is polling understands this one.
			(&placementOAuthError{status: http.StatusBadRequest, code: "slow_down"}).write(w)
			return
		}
		h.writeError(w, http.StatusTooManyRequests, "Too many requests; try again shortly.")
		return
	}

	if poll {
		h.placementDevicePoll(w, r)
		return
	}
	h.placementDeviceIssue(w, r)
}

func (h *Handler) placementDeviceIssue(w http.ResponseWriter, r *http.Request) {
	clientID, oerr := h.authenticatePlacementDeviceClient(r)
	if oerr != nil {
		oerr.write(w)
		return
	}
	deviceCode, userCode, err := h.placementOnboard.devices.create(r.Context(), clientID)
	if err != nil {
		h.logger.Error(logging.DestinationHTTP, "Failed to record a placement device grant", "error", err)
		h.writeError(w, http.StatusInternalServerError, "Could not start the request.")
		return
	}
	verify := h.placementDeviceVerificationURI(r)
	h.logger.Info(logging.DestinationHTTP, "Placement device request started",
		"client_id", clientID, "user_code", userCode)
	writePlacementDeviceJSON(w, http.StatusOK, map[string]any{
		"device_code":               deviceCode,
		"user_code":                 userCode,
		"verification_uri":          verify,
		"verification_uri_complete": verify + "?" + url.Values{"user_code": {userCode}}.Encode(),
		"expires_in":                placementDeviceExpiresIn,
		"interval":                  placementDeviceInterval,
	})
}

// placementDeviceVerificationURI is the absolute /auth/code URL: on
// HTTP_API_BASE_URL when configured, else on the host the client asked.
func (h *Handler) placementDeviceVerificationURI(r *http.Request) string {
	if h.httpBaseURL != "" {
		return strings.TrimRight(h.httpBaseURL, "/") + "/auth/code"
	}
	scheme := "https"
	if r.TLS == nil && !strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		scheme = "http"
	}
	return scheme + "://" + r.Host + "/auth/code"
}

func (h *Handler) placementDevicePoll(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	store := h.placementOnboard.devices
	clientID, oerr := h.authenticatePlacementDeviceClient(r)
	if oerr != nil {
		oerr.write(w)
		return
	}
	deviceCode := r.Form.Get("device_code")
	grant, err := store.byDeviceCode(ctx, deviceCode)
	if err != nil {
		h.logger.Error(logging.DestinationHTTP, "Failed to read a placement device grant", "error", err)
		h.writeError(w, http.StatusInternalServerError, "Could not read the request.")
		return
	}
	if grant == nil {
		(&placementOAuthError{status: http.StatusBadRequest, code: "invalid_request",
			description: "Invalid 'device_code' in payload"}).write(w)
		return
	}
	if grant.ClientID != clientID {
		(&placementOAuthError{status: http.StatusBadRequest, code: "unauthorized_client"}).write(w)
		return
	}
	now := store.now().Unix()
	if grant.expired(now) {
		(&placementOAuthError{status: http.StatusBadRequest, code: "expired_token"}).write(w)
		return
	}
	switch grant.State {
	case placementDeviceStateDenied:
		// authlib's AccessDeniedError carries a fixed description.
		(&placementOAuthError{status: http.StatusBadRequest, code: "access_denied",
			description: "The resource owner or authorization server denied the request"}).write(w)
		return
	case placementDeviceStateApproved:
		h.placementDeviceDeliver(w, r, grant, now)
		return
	}

	// Pending. pdwebapp's should_slow_down: a poll closer to the last one
	// than the interval (less one second of slack) is too fast. Either way
	// the poll time is recorded.
	tooFast := grant.LastPoll != 0 && grant.Interval > 0 &&
		now+placementDeviceSlowDownSlack-grant.LastPoll < grant.Interval
	if err := store.touchPoll(ctx, grant.DeviceCodeHash, now); err != nil {
		h.logger.Warn(logging.DestinationHTTP, "Failed to record a device poll", "error", err)
	}
	if tooFast {
		(&placementOAuthError{status: http.StatusBadRequest, code: "slow_down"}).write(w)
		return
	}
	(&placementOAuthError{status: http.StatusBadRequest, code: "authorization_pending"}).write(w)
}

// placementDeviceDeliver hands an approved grant's token to its client and
// forgets it.
func (h *Handler) placementDeviceDeliver(w http.ResponseWriter, r *http.Request, grant *placementDeviceGrant, now int64) {
	if grant.Token == "" {
		(&placementOAuthError{status: http.StatusBadRequest, code: "invalid_request",
			description: "Placement token is unavailable"}).write(w)
		return
	}
	if grant.TokenExpiresAt != 0 && grant.TokenExpiresAt < now {
		(&placementOAuthError{status: http.StatusBadRequest, code: "invalid_request",
			description: "Placement token is expired"}).write(w)
		return
	}
	// Deleted before it is written: a second poll with the same code
	// must never see the token again, even if this response is lost.
	if err := h.placementOnboard.devices.consume(r.Context(), grant.DeviceCodeHash); err != nil {
		h.logger.Error(logging.DestinationHTTP, "Failed to delete a delivered placement device grant", "error", err)
		h.writeError(w, http.StatusInternalServerError, "Could not complete the request.")
		return
	}
	// pdwebapp served the token file, which it wrote with a trailing
	// newline, and gave expires_in as a string, omitted for a token
	// without an expiry.
	body := map[string]any{
		"token_type":   "Placement",
		"access_token": grant.Token + "\n",
	}
	if grant.TokenExpiresAt != 0 {
		body["expires_in"] = strconv.FormatInt(max(0, grant.TokenExpiresAt-now), 10)
	}
	h.logger.Info(logging.DestinationHTTP, "Placement device token delivered",
		"client_id", grant.ClientID, "user_code", grant.UserCode, "foreign_id", grant.ForeignID)
	writePlacementDeviceJSON(w, http.StatusOK, body)
}

// handlePlacementDeviceCode is GET /auth/code, the verification URI the
// device shows: it sends the browser to the confirmation page.
func (h *Handler) handlePlacementDeviceCode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", http.MethodGet)
		h.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	target := "/placement/device"
	if code := r.URL.Query().Get("user_code"); code != "" {
		if rs := []rune(code); len(rs) > 16 {
			code = string(rs[:16])
		}
		target += "?" + url.Values{"user_code": {code}}.Encode()
	}
	http.Redirect(w, r, target, http.StatusFound)
}

// handlePlacementDeviceCancel is POST /auth/cancel_device, pdwebapp's
// cancel form target: the same as POST
// /api/v1/placement/me/device/{user_code}/deny, with the code in the form.
func (h *Handler) handlePlacementDeviceCancel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		h.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	setBodyLimit(w, r, 1<<16)
	if err := r.ParseForm(); err != nil {
		h.writeError(w, http.StatusBadRequest, "Invalid form")
		return
	}
	h.placementDeviceDeny(w, r, r.PostForm.Get("user_code"))
}

// placementDeviceDeny refuses a pending device request for the signed-in
// person. Unknown codes are 404; one already resolved or expired is left
// alone and reported as canceled, as pdwebapp does.
func (h *Handler) placementDeviceDeny(w http.ResponseWriter, r *http.Request, rawCode string) {
	session, ok := h.getAnySessionFromRequest(r)
	if !ok {
		h.writeError(w, http.StatusUnauthorized, "Authentication required")
		return
	}
	store := h.placementOnboard.devices
	if store == nil {
		h.writeError(w, http.StatusServiceUnavailable, "Placement tokens are not available on this server.")
		return
	}
	code := normalizePlacementUserCode(rawCode)
	if code == "" {
		h.writeError(w, http.StatusBadRequest, "The code must look like XXXX-XXXX.")
		return
	}
	grant, err := store.byUserCode(r.Context(), code)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "Could not read the request.")
		return
	}
	if grant == nil {
		h.writeError(w, http.StatusNotFound, "That code was not recognized.")
		return
	}
	if err := store.deny(r.Context(), code, session.PlacementForeignID); err != nil {
		h.writeError(w, http.StatusInternalServerError, "Could not cancel the request.")
		return
	}
	h.logger.Info(logging.DestinationHTTP, "Placement device request canceled",
		"user_code", code, "foreign_id", session.PlacementForeignID)
	h.writeJSON(w, http.StatusOK, map[string]string{"status": "canceled"})
}

// placementDeviceInfo is GET /api/v1/placement/me/device/{user_code}: what
// the confirmation page shows about a pending request.
type placementDeviceInfo struct {
	UserCode   string    `json:"user_code"`
	ClientID   string    `json:"client_id"`
	ClientName string    `json:"client_name"`
	State      string    `json:"state"`
	ExpiresAt  time.Time `json:"expires_at"`
}

func (h *Handler) placementDeviceLookup(w http.ResponseWriter, r *http.Request, rawCode string) {
	if r.Method != http.MethodGet {
		h.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	store := h.placementOnboard.devices
	if store == nil {
		h.writeError(w, http.StatusServiceUnavailable, "Placement tokens are not available on this server.")
		return
	}
	code := normalizePlacementUserCode(rawCode)
	if code == "" {
		h.writeError(w, http.StatusBadRequest, "The code must look like XXXX-XXXX.")
		return
	}
	grant, err := store.byUserCode(r.Context(), code)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "Could not read the request.")
		return
	}
	if grant == nil {
		h.writeError(w, http.StatusNotFound, "That code was not recognized.")
		return
	}
	state := grant.State
	if grant.expired(store.now().Unix()) {
		state = "expired"
	}
	h.writeJSON(w, http.StatusOK, placementDeviceInfo{
		UserCode:   grant.UserCode,
		ClientID:   grant.ClientID,
		ClientName: placementDeviceClientName(grant.ClientID),
		State:      state,
		ExpiresAt:  time.Unix(grant.ExpiresAt, 0).UTC(),
	})
}

func placementDeviceClientName(clientID string) string {
	if n, ok := placementDeviceClientNames[clientID]; ok {
		return n
	}
	return clientID
}

// decodePlacementTokenClaims reads a JWT's payload without verifying it. The placementd
// signed it with a key only it holds; the claims are read for display only.
func decodePlacementTokenClaims(token string) map[string]any {
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) != 3 {
		return nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return nil
	}
	var claims map[string]any
	if err := jsonUnmarshalUseNumber(raw, &claims); err != nil {
		return nil
	}
	return claims
}
