package httpserver

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/webapi/httpserver/chat"
)

// loadOperatorChatInstructions reads optional site-operator extra
// system-prompt rules from a file. The rules are appended to every
// chat turn's system prompt regardless of page, so site-specific
// constraints (resource caps, preferred runtimes, support contacts)
// can be expressed without touching code.
//
// Empty path = feature disabled (returns "", nil). Mode 0600/0400
// is enforced just like the API-key file: operator may include
// policy text they don't want every local user reading.
//
// Loaded once at startup via NewHandler. A change to the file does
// not take effect until restart — keep the file small and the
// guidance evergreen.
func loadOperatorChatInstructions(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("stat %s: %w", path, err)
	}
	if info.IsDir() {
		return "", fmt.Errorf("%s is a directory", path)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return "", fmt.Errorf("%s has world/group perms (mode %#o); must be 0600 or 0400", path, perm)
	}
	raw, err := os.ReadFile(path) //nolint:gosec // operator-controlled path
	if err != nil {
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	// Trim only the trailing newline operators reflexively add; preserve
	// internal whitespace which may be load-bearing for the prompt.
	return strings.TrimRight(string(raw), "\r\n"), nil
}

// handleChat is POST /api/v1/chat. It validates the session,
// streams the engine's output back to the browser using the AI
// SDK data-stream protocol, and lets the engine hop through tool
// calls server-side until the assistant produces a final reply (or
// hands off to a client-side tool, after which the next browser
// POST resumes the loop).
//
// The handler is also a feature-gate: 503 when chatEngine is nil
// (LLM key unset OR MCP disabled). The SPA polls /api/v1/chat/info
// to decide whether to render the panel; this 503 is also caught by
// useChat() so a misconfigured deployment fails loudly, not
// silently.
func (s *Handler) handleChat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if s.chatEngine == nil {
		s.writeError(w, http.StatusServiceUnavailable,
			"chat is not enabled on this server (set HTTP_API_LLM_API_KEY_FILE and enable MCP)")
		return
	}

	// Authenticate. Same path the rest of the API uses; the chat
	// endpoint is just another authenticated POST.
	ctx, needsRedirect, err := s.requireAuthentication(r)
	if err != nil {
		if needsRedirect {
			s.redirectToLogin(w, r)
			return
		}
		s.writeError(w, http.StatusUnauthorized, fmt.Sprintf("Authentication failed: %v", err))
		return
	}
	actor := htcondor.GetAuthenticatedUserFromContext(ctx)
	if actor == "" {
		// Should never happen — requireAuthentication already
		// validated. Belt-and-braces: refuse rather than fall
		// through to a chat session with an empty owner scope.
		s.writeError(w, http.StatusUnauthorized,
			"chat: authenticated context carries no username; refusing to proceed unscoped")
		return
	}

	// Parse the AI-SDK request payload. Cap the body — every chat
	// turn carries the full transcript, but no realistic chat is
	// over a few hundred KiB. 1 MiB is comfortable headroom while
	// blocking a hostile client from streaming gigabytes of fake
	// history at us.
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req chat.Request
	// AI-SDK v6 posts extra top-level fields (id, trigger, messageId,
	// …) that we ignore but the SDK may add to in any minor release.
	// Strict-decode would 400 the user on an SDK bump, so we accept
	// unknown fields and only validate what we actually consume.
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid chat request: %v", err))
		return
	}
	if len(req.Messages) == 0 {
		s.writeError(w, http.StatusBadRequest, "chat request has no messages")
		return
	}

	// Switch into streaming mode and run the engine.
	//
	// IMPORTANT: do NOT call w.WriteHeader before NewWriter. NewWriter
	// sets the SSE response headers (Content-Type: text/event-stream,
	// Cache-Control: no-store, x-vercel-ai-ui-message-stream: v1) by
	// calling rw.Header().Set(...), but those calls are no-ops once
	// WriteHeader has already been called. Without these headers, the
	// browser (or any intermediate proxy) buffers the response body
	// and the user sees the entire reply land at once instead of
	// streaming. Go auto-emits 200 + headers on the first body Write,
	// which happens when the first chunk flushes — so we don't need
	// to call WriteHeader explicitly at all.
	writer := chat.NewWriter(w)
	defer writer.Close()

	if err := s.chatEngine.Stream(ctx, writer, actor, req); err != nil {
		s.logger.Warn(logging.DestinationHTTP, "chat stream ended with error",
			"error", err, "user", actor)
		// The engine has already emitted an error frame to the
		// browser via writer.WriteError; nothing more to do here.
	}
	writer.WriteFinish("end_turn")
}

// handleChatInfo is GET /api/v1/chat/info — a tiny "is this feature
// enabled, and if so what model" probe. The SPA hits this on jobs-
// page mount to decide whether to render the chat surface; 200
// with `enabled:true` means "show the panel", 503 means "hide".
//
// We don't return the API key, the URL, or anything else sensitive.
func (s *Handler) handleChatInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	// No authentication required for the info probe — it leaks no
	// user data and the SPA needs to hit it before showing any
	// post-login UI. requireAuthentication adds latency we don't
	// need here.
	if s.chatEngine == nil {
		s.writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"enabled": false,
			"reason":  "HTTP_API_LLM_API_KEY_FILE not configured or MCP disabled",
		})
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{
		"enabled": true,
	})
}
