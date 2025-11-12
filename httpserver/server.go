package httpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
)

// Server represents the HTTP API server
type Server struct {
	httpServer     *http.Server
	schedd         *htcondor.Schedd
	userHeader     string
	signingKeyPath string
}

// Config holds server configuration
type Config struct {
	ListenAddr     string // Address to listen on (e.g., ":8080")
	ScheddName     string // Schedd name
	ScheddAddr     string // Schedd address
	ScheddPort     int    // Schedd port
	UserHeader     string // HTTP header to extract username from (optional)
	SigningKeyPath string // Path to token signing key (optional, for token generation)
}

// NewServer creates a new HTTP API server
func NewServer(cfg Config) (*Server, error) {
	schedd := htcondor.NewSchedd(cfg.ScheddName, cfg.ScheddAddr, cfg.ScheddPort)

	s := &Server{
		schedd:         schedd,
		userHeader:     cfg.UserHeader,
		signingKeyPath: cfg.SigningKeyPath,
	}

	mux := http.NewServeMux()
	s.setupRoutes(mux)

	s.httpServer = &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	return s, nil
} // Start starts the HTTP server
func (s *Server) Start() error {
	log.Printf("Starting HTCondor API server on %s", s.httpServer.Addr)
	return s.httpServer.ListenAndServe()
}

// Shutdown gracefully shuts down the HTTP server
func (s *Server) Shutdown(ctx context.Context) error {
	log.Println("Shutting down HTTP server...")
	return s.httpServer.Shutdown(ctx)
}

// ErrorResponse represents an error response
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
	Code    int    `json:"code"`
}

// writeError writes an error response
func writeError(w http.ResponseWriter, statusCode int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(ErrorResponse{
		Error:   http.StatusText(statusCode),
		Message: message,
		Code:    statusCode,
	})
}

// writeJSON writes a JSON response
func writeJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if data != nil {
		if err := json.NewEncoder(w).Encode(data); err != nil {
			log.Printf("Error encoding JSON response: %v", err)
		}
	}
}

// extractBearerToken extracts the bearer token from the Authorization header
func extractBearerToken(r *http.Request) (string, error) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return "", fmt.Errorf("no authorization header")
	}

	const prefix = "Bearer "
	if len(auth) < len(prefix) || auth[:len(prefix)] != prefix {
		return "", fmt.Errorf("invalid authorization header format")
	}

	return auth[len(prefix):], nil
}

// extractOrGenerateToken extracts a bearer token from the Authorization header,
// or if userHeader is set and no auth token is present, generates a token for
// the username from the specified header
func (s *Server) extractOrGenerateToken(r *http.Request) (string, error) {
	// Try to extract bearer token first
	token, err := extractBearerToken(r)
	if err == nil {
		return token, nil
	}

	// If userHeader is configured and signing key is available, try to generate token
	if s.userHeader != "" && s.signingKeyPath != "" {
		username := r.Header.Get(s.userHeader)
		if username == "" {
			return "", fmt.Errorf("no authorization token and %s header is empty", s.userHeader)
		}

		// Generate token for this user
		log.Printf("Generating token for user: %s (from header %s)", username, s.userHeader)
		token, err := GenerateToken(username, s.signingKeyPath)
		if err != nil {
			return "", fmt.Errorf("failed to generate token for user %s: %w", username, err)
		}

		return token, nil
	}

	// No token and can't generate one
	return "", fmt.Errorf("no authorization token and user header not configured")
}
