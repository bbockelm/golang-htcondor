package httpserver

import (
	"context"
	"net/http"

	"github.com/bbockelm/golang-htcondor/webapi/usagestats"
)

// AdminUsageResponse is the admin usage page's data. Enabled=false
// means this server is not counting calls of the requested kind; the
// summary fields are then absent.
type AdminUsageResponse struct {
	Enabled bool `json:"enabled"`
	// Kinds lists every kind this server can report on, so the page
	// can draw its tabs from the server rather than hard-coding them.
	// Present whether or not the requested kind is enabled.
	Kinds []AdminUsageKind `json:"kinds"`
	*usagestats.Summary
}

// AdminUsageKind is one tab: a kind and whether it is being counted.
type AdminUsageKind struct {
	Kind    string `json:"kind"`
	Label   string `json:"label"`
	Enabled bool   `json:"enabled"`
}

// usageStoreFor returns the store counting the named kind.
func (s *Handler) usageStoreFor(kind string) *usagestats.Store {
	for _, store := range s.usageStores() {
		if store.Spec().Kind == kind {
			return store
		}
	}
	return nil
}

// usageKinds lists the tabs, in the order usagestats defines them.
func (s *Handler) usageKinds() []AdminUsageKind {
	labels := map[string]string{"mcp": "MCP tools", "rest": "REST API"}
	out := make([]AdminUsageKind, 0, len(usagestats.Specs()))
	for _, spec := range usagestats.Specs() {
		label := labels[spec.Kind]
		if label == "" {
			label = spec.Title
		}
		out = append(out, AdminUsageKind{
			Kind:    spec.Kind,
			Label:   label,
			Enabled: s.usageStoreFor(spec.Kind) != nil,
		})
	}
	return out
}

// handleAdminUsage handles GET /api/v1/admin/usage: call statistics
// aggregated by tool or endpoint, by user and by client.
//
// The kind parameter selects MCP tool calls or REST API requests and
// defaults to MCP, which is what the endpoint answered before REST
// counting existed. The optional name, user and client parameters
// narrow every aggregate to the matching calls.
//
// It reads the in-memory store rather than the table, because the
// store is the live view: the table lags it by up to one flush
// interval.
func (s *Handler) handleAdminUsage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if !s.requireAdmin(w, r) {
		return
	}

	q := r.URL.Query()
	kind := q.Get("kind")
	if kind == "" {
		kind = usagestats.MCPSpec().Kind
	}
	spec, ok := usagestats.SpecForKind(kind)
	if !ok {
		// Named a kind nobody defines. Answering about MCP instead
		// would be worse than refusing: the caller would read figures
		// for something it did not ask about.
		s.writeError(w, http.StatusBadRequest, "Unknown usage kind: "+kind)
		return
	}

	kinds := s.usageKinds()
	store := s.usageStoreFor(spec.Kind)
	if store == nil {
		s.writeJSON(w, http.StatusOK, AdminUsageResponse{Enabled: false, Kinds: kinds})
		return
	}

	summary := usagestats.Summarize(spec, store.Snapshot(), usagestats.Filter{
		Name:   q.Get("name"),
		User:   q.Get("user"),
		Client: q.Get("client"),
	})
	s.resolveUsageClientNames(r.Context(), &summary)
	s.writeJSON(w, http.StatusOK, AdminUsageResponse{
		Enabled: true, Kinds: kinds, Summary: &summary,
	})
}

// resolveUsageClientNames turns the recorded "oauth:<id>" client
// strings into the names the admin Clients page shows.
//
// Done here, on an admin page load, rather than when the call was
// counted: naming a client is a database read, and the request path
// should not pay for a label.
//
// The recorded value is left in place and the name added beside it, so
// the string the page sends back as a filter is still the one the
// store holds. Replacing it outright would make every client filter
// miss as soon as a client had a name.
func (s *Handler) resolveUsageClientNames(ctx context.Context, summary *usagestats.Summary) {
	if s.restStatsClients == nil || summary == nil {
		return
	}
	label := func(v string) string {
		if resolved := s.restStatsClients.resolve(ctx, s.db, v); resolved != v {
			return resolved
		}
		return ""
	}
	for i := range summary.ByClient {
		summary.ByClient[i].Label = label(summary.ByClient[i].Name)
	}
	labels := map[string]string{}
	for _, c := range summary.Options.Clients {
		if l := label(c); l != "" {
			labels[c] = l
		}
	}
	if len(labels) > 0 {
		summary.ClientLabels = labels
	}
}
