package httpserver

import (
	"encoding/json"
	"fmt"
	"net/http"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/httpserver/chat"
	"github.com/bbockelm/golang-htcondor/logging"
)

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
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid chat request: %v", err))
		return
	}
	if len(req.Messages) == 0 {
		s.writeError(w, http.StatusBadRequest, "chat request has no messages")
		return
	}

	// Switch into streaming mode and run the engine.
	w.WriteHeader(http.StatusOK)
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
