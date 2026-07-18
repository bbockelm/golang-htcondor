// HTTP handlers for the batch-submission template library.
//
// Routes:
//
//   GET    /api/v1/templates               list everything (built-in + global + user)
//   POST   /api/v1/templates               save a user template (Save-as-template)
//   DELETE /api/v1/templates/{id}          delete a user template
//
// Built-in and global templates are read-only. Attempting to delete a
// non-user template returns 400. The submit page picker uses the
// `source` field on each row ("builtin" | "global" | "user") to render
// a badge and to gate the Delete button.

package httpserver

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/webapi/templates"
)

// buildTemplateLibrary constructs the merged template catalog. The
// user-saved store rides on the unified application DB (db arg) so it
// stays in sync with the OAuth2/IDP/sessions tables — same file,
// same goose-managed schema. Returns nil only on a fatal error
// parsing the embedded built-in YAML, which is a programming bug we
// want to surface (the /api/v1/templates handler returns 503).
func buildTemplateLibrary(cfg HandlerConfig, logger *logging.Logger, db *sql.DB) *templates.Library {
	lib, err := templates.NewLibrary(templates.LibraryConfig{
		GlobalPath:  cfg.TemplateGlobalPath,
		UserStoreDB: db,
	})
	if err != nil {
		if logger != nil {
			logger.Error(logging.DestinationHTTP, "templates: failed to build library", "error", err)
		}
		return nil
	}
	return lib
}

// handleTemplates dispatches GET/POST on /api/v1/templates and DELETE
// on /api/v1/templates/{id}. We do the path split here instead of
// using two different HandleFunc registrations because the catch-all
// route is simpler to wire (matching the jupyter / jobs patterns).
func (s *Handler) handleTemplates(w http.ResponseWriter, r *http.Request) {
	if s.templateLibrary == nil {
		s.writeError(w, http.StatusServiceUnavailable, "templates library is not configured on this server")
		return
	}

	const prefix = "/api/v1/templates"
	rest := strings.TrimPrefix(r.URL.Path, prefix)

	if rest == "" || rest == "/" {
		switch r.Method {
		case http.MethodGet:
			s.handleListTemplates(w, r)
		case http.MethodPost:
			s.handleSaveTemplate(w, r)
		default:
			s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		}
		return
	}

	id := strings.TrimPrefix(rest, "/")
	if strings.ContainsRune(id, '/') {
		s.writeError(w, http.StatusNotFound, "no such template endpoint")
		return
	}

	switch r.Method {
	case http.MethodGet:
		s.handleGetTemplate(w, r, id)
	case http.MethodDelete:
		s.handleDeleteTemplate(w, r, id)
	default:
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

type templatesListResponse struct {
	Templates []templates.Template `json:"templates"`
}

func (s *Handler) handleListTemplates(w http.ResponseWriter, r *http.Request) {
	ctx, _, err := s.requireAuthentication(r)
	if err != nil {
		s.writeError(w, http.StatusUnauthorized, fmt.Sprintf("Authentication failed: %v", err))
		return
	}
	username := htcondor.GetAuthenticatedUserFromContext(ctx)
	all, storeErr := s.templateLibrary.AllWithError(username)
	if storeErr != nil {
		// Built-in / global rows still came back — log the user-store
		// error so an operator can see it but don't 500 the whole
		// page (the catalog is degraded, not broken).
		s.logger.Error(logging.DestinationHTTP, "templates: user store load failed",
			"owner", username, "error", storeErr)
	}
	s.writeJSON(w, http.StatusOK, templatesListResponse{Templates: all})
}

func (s *Handler) handleGetTemplate(w http.ResponseWriter, r *http.Request, id string) {
	ctx, _, err := s.requireAuthentication(r)
	if err != nil {
		s.writeError(w, http.StatusUnauthorized, fmt.Sprintf("Authentication failed: %v", err))
		return
	}
	username := htcondor.GetAuthenticatedUserFromContext(ctx)
	t, ok := s.templateLibrary.Get(id, username)
	if !ok {
		s.writeError(w, http.StatusNotFound, "no such template")
		return
	}
	s.writeJSON(w, http.StatusOK, t)
}

// templateSaveRequest is what the frontend POSTs. We intentionally
// reject the `source` field — the server always stamps it.
//
// Columns accept either a bare string ("foo") or {name, description}
// — both forms are decoded by templates.Column.UnmarshalJSON, so the
// REST shape is forgiving for older clients.
//
// InputFiles are optional; encoding/json handles `[]byte` as base64,
// which matches what the SPA's FileReader.readAsArrayBuffer + btoa
// pipeline produces.
type templateSaveRequest struct {
	ID          string                `json:"id"`
	Name        string                `json:"name"`
	Description string                `json:"description"`
	Columns     []templates.Column    `json:"columns"`
	Contents    string                `json:"contents"`
	InputFiles  []templates.InputFile `json:"input_files,omitempty"`
	// Visibility — "private" (default) or "shared". Shared templates
	// are visible to every authenticated user; the picker labels them
	// with the owner's name. Only the owner can edit / delete; other
	// users can load a shared template as a starting point.
	Visibility templates.Visibility `json:"visibility,omitempty"`
}

func (s *Handler) handleSaveTemplate(w http.ResponseWriter, r *http.Request) {
	// Bound the request body so a hostile client can't OOM the server
	// by streaming a giant JSON. Per-file 1 MiB × 5 + envelope slack.
	r.Body = http.MaxBytesReader(w, r.Body, 8*1024*1024)

	ctx, _, err := s.requireAuthentication(r)
	if err != nil {
		s.writeError(w, http.StatusUnauthorized, fmt.Sprintf("Authentication failed: %v", err))
		return
	}
	username := htcondor.GetAuthenticatedUserFromContext(ctx)

	var req templateSaveRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid JSON: %v", err))
		return
	}

	saved, err := s.templateLibrary.Save(templates.Template{
		ID:          req.ID,
		Name:        strings.TrimSpace(req.Name),
		Description: strings.TrimSpace(req.Description),
		Columns:     req.Columns,
		Contents:    req.Contents,
		InputFiles:  req.InputFiles,
		Visibility:  req.Visibility,
	}, username)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.logger.Info(logging.DestinationHTTP, "template saved",
		"id", saved.ID, "owner", username,
		"input_files", len(saved.InputFiles))
	s.writeJSON(w, http.StatusCreated, saved)
}

func (s *Handler) handleDeleteTemplate(w http.ResponseWriter, r *http.Request, id string) {
	ctx, _, err := s.requireAuthentication(r)
	if err != nil {
		s.writeError(w, http.StatusUnauthorized, fmt.Sprintf("Authentication failed: %v", err))
		return
	}
	username := htcondor.GetAuthenticatedUserFromContext(ctx)

	// Refuse to delete built-in / global templates: those don't live
	// in the user store, and a successful Delete should be a clear
	// "user template removed" signal. The Get call is owner-scoped, so
	// a request for someone else's user template surfaces here as
	// "not found" rather than "read-only" — which is the right answer
	// either way (don't leak the existence of other users' templates).
	t, ok := s.templateLibrary.Get(id, username)
	if !ok {
		s.writeError(w, http.StatusNotFound, "no such template")
		return
	}
	if t.Source != templates.SourceUser {
		s.writeError(w, http.StatusBadRequest,
			fmt.Sprintf("cannot delete %s template (read-only)", t.Source))
		return
	}
	// Get may return a SHARED template owned by someone else. The user
	// can load it as a starting point but cannot mutate it. Without
	// this check the Delete below would just no-op (templates_user is
	// keyed (owner, id), so deleting someone else's row matches no
	// rows) and the user would see a confusing 404.
	if t.Owner != "" && t.Owner != username {
		s.writeError(w, http.StatusForbidden,
			fmt.Sprintf("template %q is owned by %s; only the owner can delete it", id, t.Owner))
		return
	}

	deleted, err := s.templateLibrary.Delete(id, username)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !deleted {
		s.writeError(w, http.StatusNotFound, "no such user template")
		return
	}
	s.logger.Info(logging.DestinationHTTP, "template deleted",
		"id", id, "owner", username)
	s.writeJSON(w, http.StatusOK, map[string]any{"deleted": true})
}
