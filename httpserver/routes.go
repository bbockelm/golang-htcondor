package httpserver

import (
	"net/http"
)

// setupRoutes sets up all HTTP routes
func (s *Server) setupRoutes(mux *http.ServeMux) {
	// CORS middleware: allow all origins
	cors := func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "*")
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			h.ServeHTTP(w, r)
		})
	}

	// OpenAPI schema
	mux.HandleFunc("/openapi.json", s.handleOpenAPISchema)

	// Job management endpoints
	mux.HandleFunc("/api/v1/jobs", s.handleJobs)
	mux.HandleFunc("/api/v1/jobs/", s.handleJobByID) // Pattern with trailing slash catches /api/v1/jobs/{id}

	// Metrics endpoint (if enabled)
	if s.prometheusExporter != nil {
		mux.HandleFunc("/metrics", s.handleMetrics)
	}

	// Wrap all routes with CORS
	*mux = *http.NewServeMux()
	mux.Handle("/openapi.json", cors(http.HandlerFunc(s.handleOpenAPISchema)))
	mux.Handle("/api/v1/jobs", cors(http.HandlerFunc(s.handleJobs)))
	mux.Handle("/api/v1/jobs/", cors(http.HandlerFunc(s.handleJobByID)))
}
