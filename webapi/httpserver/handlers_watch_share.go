package httpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/webapi/jobwatch"
	"github.com/bbockelm/golang-htcondor/webapi/shareurl"
	"github.com/bbockelm/golang-htcondor/webapi/watchpoll"
)

// ShareWatchRequest is the body for POST /api/v1/watches/{id}/share.
type ShareWatchRequest struct {
	TTLSeconds int `json:"ttl_seconds,omitempty"`
}

// ShareWatchResponse is what a mint call returns.
type ShareWatchResponse struct {
	URL        string    `json:"url"`
	WatchID    string    `json:"watch_id"`
	Owner      string    `json:"owner"`
	ExpiresAt  time.Time `json:"expires_at"`
	TTLSeconds int       `json:"ttl_seconds"`
	// MaxWaitSeconds is what the redeem endpoint will block for, so a
	// poller can size its own client timeout from the answer rather than
	// from a number hard-coded on its side.
	MaxWaitSeconds     int `json:"max_wait_seconds"`
	DefaultWaitSeconds int `json:"default_wait_seconds"`
}

// watchShareEnabled reports whether watch URLs can be served at all.
func (h *Handler) watchShareEnabled() bool {
	return h != nil && h.jobWatch != nil
}

// handleWatchShare handles POST /api/v1/watches/{id}/share, minting a
// URL that reports whether that one watch has fired, and waits for it to.
func (h *Handler) handleWatchShare(w http.ResponseWriter, r *http.Request, watchID string) {
	if r.Method != http.MethodPost {
		h.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if !h.watchShareEnabled() {
		h.writeError(w, http.StatusServiceUnavailable, "Job watches are not configured on this server")
		return
	}
	if h.signingKeyPath == "" {
		h.writeError(w, http.StatusNotImplemented,
			"Share URLs require HTTP_API_SIGNING_KEY (or SEC_TOKEN_POOL_SIGNING_KEY_FILE) to be configured")
		return
	}

	ctx, needsRedirect, err := h.requireAuthentication(r)
	if err != nil {
		if needsRedirect {
			h.redirectToLogin(w, r)
			return
		}
		h.writeError(w, http.StatusUnauthorized, fmt.Sprintf("Authentication failed: %v", err))
		return
	}

	owner := strings.SplitN(htcondor.GetAuthenticatedUserFromContext(ctx), "@", 2)[0]
	if owner == "" {
		h.writeError(w, http.StatusUnauthorized, "Could not determine authenticated user")
		return
	}
	watchID = strings.TrimSpace(watchID)
	if watchID == "" {
		h.writeError(w, http.StatusBadRequest, "No watch id in the path")
		return
	}

	// Confirm the watch exists and is this caller's before signing. The
	// token carries the owner and is redeemed as them, so without this a
	// caller could mint a URL naming somebody else's watch id.
	found, err := h.findWatch(ctx, owner, watchID)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, fmt.Sprintf("Looking up the watch failed: %v", err))
		return
	}
	if found == nil {
		// Absent and not-yours are the same answer on purpose: a 404 that
		// distinguished them would enumerate other users' watch ids.
		h.writeError(w, http.StatusNotFound, fmt.Sprintf("Watch %q not found", watchID))
		return
	}

	ttl := shareurl.ClampTTL(shareurl.KindWatch, watchShareTTL(r))
	exp := time.Now().Add(ttl)
	tok, err := h.signShareToken(shareurl.Payload{
		Owner: owner,
		Exp:   exp.Unix(),
		Kind:  shareurl.KindWatch,
		Watch: watchID,
	})
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to sign token: %v", err))
		return
	}

	h.writeJSON(w, http.StatusOK, ShareWatchResponse{
		URL:                fmt.Sprintf("%s/api/v1/share/watch?t=%s", h.shareURLBase(r), tok),
		WatchID:            watchID,
		Owner:              owner,
		ExpiresAt:          exp,
		TTLSeconds:         int(ttl.Seconds()),
		MaxWaitSeconds:     int(watchpoll.MaxWait.Seconds()),
		DefaultWaitSeconds: int(watchpoll.DefaultWait.Seconds()),
	})
}

// watchShareTTL reads the optional {"ttl_seconds": N} body. Absent,
// empty or unparseable means "use the default" -- refusing a share URL
// over a malformed optional knob is a worse answer than the default.
func watchShareTTL(r *http.Request) time.Duration {
	if r.Body == nil || r.ContentLength == 0 {
		return 0
	}
	var req ShareWatchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.TTLSeconds <= 0 {
		return 0
	}
	return time.Duration(req.TTLSeconds) * time.Second
}

// findWatch returns this owner's watch with the given id, or nil when
// there is none. Scoping the lookup by owner is what makes the token's
// owner authoritative: a watch that expired, was cancelled, or belongs to
// somebody else is simply absent.
func (h *Handler) findWatch(ctx context.Context, owner, id string) (*jobwatch.Watch, error) {
	all, err := h.jobWatch.ForOwner(ctx, owner, nil)
	if err != nil {
		return nil, err
	}
	for _, w := range all {
		if w.ID == id {
			return w, nil
		}
	}
	return nil, nil
}

// handleSharedWatch handles GET /api/v1/share/watch?t=<token>.
//
// Possession of the URL is the only auth; any session cookie on the
// request is ignored. The call blocks until the watch fires or the wait
// runs out, then answers. With Accept: text/event-stream (or ?stream=sse)
// it streams heartbeats while it waits and ends on the same answer.
func (h *Handler) handleSharedWatch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		h.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if !h.watchShareEnabled() {
		h.writeError(w, http.StatusServiceUnavailable, "Job watches are not configured on this server")
		return
	}
	if h.signingKeyPath == "" {
		h.writeError(w, http.StatusNotImplemented, "Share URLs are not configured")
		return
	}

	tok := r.URL.Query().Get("t")
	if tok == "" {
		h.writeError(w, http.StatusBadRequest, "Missing token")
		return
	}
	payload, err := h.verifyShareToken(tok, shareurl.KindWatch)
	if err != nil {
		// Don't leak which check failed (signature vs expiry vs kind).
		h.logger.Info(logging.DestinationHTTP, "Watch share token rejected", "error", err)
		h.writeError(w, http.StatusUnauthorized, "Invalid or expired token")
		return
	}
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}

	wait := watchpoll.ClampWait(r.URL.Query().Get("wait"))
	start := time.Now()
	deadline := start.Add(wait)

	if wantsSSE(r) {
		h.streamSharedWatch(w, r, payload, start, deadline)
		return
	}

	answer := h.awaitWatchAnswer(r.Context(), payload, start, deadline)
	h.writeJSON(w, http.StatusOK, answer)
}

// awaitWatchAnswer blocks until the named watch has an answer, the
// deadline passes, or the request ends, and reports what it found.
func (h *Handler) awaitWatchAnswer(ctx context.Context, p *shareurl.Payload, start, deadline time.Time) watchpoll.Answer {
	var found *jobwatch.Watch
	var missing bool
	err := jobwatch.Await(ctx, h.jobWatchEval, p.Owner, deadline, watchpoll.Refresh,
		func(err error) {
			h.logger.Warn(logging.DestinationHTTP, "evaluating job watches failed", "error", err)
		},
		func() (bool, error) {
			w, err := h.findWatch(ctx, p.Owner, p.Watch)
			if err != nil {
				return false, err
			}
			if w == nil {
				// Gone is an answer, and a final one: the watch expired,
				// was cancelled, or never existed. Waiting for it to come
				// back would hold a poller forever on a dead URL.
				missing = true
				return true, nil
			}
			found = w
			return !w.FiredAt.IsZero(), nil
		})
	waited := int(time.Since(start).Round(time.Second).Seconds())
	switch {
	case err != nil && ctx.Err() != nil:
		// The caller hung up; nothing will read this, but a value keeps
		// the caller's own bookkeeping simple.
		return watchpoll.Waiting(p.Watch, waited)
	case err != nil:
		h.logger.Warn(logging.DestinationHTTP, "watch poll failed", "watch_id", p.Watch, "error", err)
		return watchpoll.Waiting(p.Watch, waited)
	case missing || found == nil:
		return watchpoll.Gone(p.Watch, waited)
	}
	return watchpoll.From(found, waited, time.Now())
}

// wantsSSE reports whether the caller asked for the streaming form.
func wantsSSE(r *http.Request) bool {
	if strings.EqualFold(strings.TrimSpace(r.URL.Query().Get("stream")), "sse") {
		return true
	}
	return strings.Contains(strings.ToLower(r.Header.Get("Accept")), "text/event-stream")
}

// streamSharedWatch serves the same wait as Server-Sent Events: a
// heartbeat every watchHeartbeatInterval while the answer is pending,
// then one terminal frame carrying the answer.
//
// The heartbeats exist for two different readers. A proxy needs bytes on
// the connection or it reaps it mid-wait. A polling plugin needs to tell
// "still waiting" from "the server died", which a silent connection
// cannot. They carry only the elapsed seconds, because the party that
// eventually reads them is often an LLM and every frame it is handed
// costs context -- the answer itself arrives once, at the end.
func (h *Handler) streamSharedWatch(w http.ResponseWriter, r *http.Request, p *shareurl.Payload, start, deadline time.Time) {
	flusher, ok := sseSetup(w)
	if !ok {
		h.writeError(w, http.StatusInternalServerError, "server does not support streaming")
		return
	}
	defer h.streamOpened()()

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	// The wait runs on its own goroutine so this one can keep the
	// heartbeat on schedule; a single loop would have to choose between
	// heartbeat cadence and evaluation cadence.
	answers := make(chan watchpoll.Answer, 1)
	go func() {
		answers <- h.awaitWatchAnswer(ctx, p, start, deadline)
	}()

	ticker := time.NewTicker(h.watchHeartbeat())
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			elapsed := int(time.Since(start).Round(time.Second).Seconds())
			if err := writeWatchPollSSE(w, flusher, "heartbeat",
				map[string]any{"waited_seconds": elapsed}); err != nil {
				return
			}
		case answer := <-answers:
			// The state doubles as the event name, so a consumer can
			// dispatch on the SSE event rather than parsing the body:
			// "fired", "waiting" or "gone".
			_ = writeWatchPollSSE(w, flusher, answer.State, answer)
			return
		}
	}
}

// watchHeartbeat is the streaming heartbeat cadence: the package default
// unless a test has shortened it, since a test that waited the real 15s
// to see one frame would be a test nobody runs.
func (h *Handler) watchHeartbeat() time.Duration {
	if h.watchHeartbeatEvery > 0 {
		return h.watchHeartbeatEvery
	}
	return watchpoll.HeartbeatInterval
}

// writeWatchPollSSE writes one frame.
func writeWatchPollSSE(w http.ResponseWriter, flusher *http.ResponseController, event string, payload any) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, data); err != nil {
		return err
	}
	return flusher.Flush()
}

// handleWatchPath dispatches /api/v1/watches/{id}/... . Only the share
// mint is served here; registering and reading watches is MCP's, and a
// half-REST surface that answered some watch questions and not others
// would be the more confusing thing to offer.
func (h *Handler) handleWatchPath(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/v1/watches/")
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	if len(parts) == 2 && parts[1] == "share" && parts[0] != "" {
		h.handleWatchShare(w, r, parts[0])
		return
	}
	h.writeError(w, http.StatusNotFound, "No such watch endpoint")
}
