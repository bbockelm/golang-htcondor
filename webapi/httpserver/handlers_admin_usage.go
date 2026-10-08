package httpserver

import (
	"net/http"

	"github.com/bbockelm/golang-htcondor/webapi/toolstats"
)

// AdminUsageResponse is the admin usage page's data. Enabled=false
// means this server is not counting MCP tool calls (it has no
// application database); the summary fields are then absent.
type AdminUsageResponse struct {
	Enabled bool `json:"enabled"`
	*toolstats.Summary
}

// handleAdminUsage handles GET /api/v1/admin/usage: MCP tool-call
// statistics aggregated by tool, user and client.
//
// The optional tool, user and client query parameters narrow every
// aggregate to the matching calls. It reads the in-memory store rather
// than the table, because the store is the live view: the table lags it
// by up to one flush interval.
func (s *Handler) handleAdminUsage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if !s.requireAdmin(w, r) {
		return
	}
	if s.toolStats == nil {
		s.writeJSON(w, http.StatusOK, AdminUsageResponse{Enabled: false})
		return
	}

	q := r.URL.Query()
	summary := toolstats.Summarize(s.toolStats.Snapshot(), toolstats.Filter{
		Tool:   q.Get("tool"),
		User:   q.Get("user"),
		Client: q.Get("client"),
	})
	s.writeJSON(w, http.StatusOK, AdminUsageResponse{Enabled: true, Summary: &summary})
}
