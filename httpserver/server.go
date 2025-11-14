package httpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/security"
	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/metricsd"
)

// Server represents the HTTP API server
type Server struct {
	httpServer         *http.Server
	schedd             *htcondor.Schedd
	userHeader         string
	signingKeyPath     string
	trustDomain        string
	uidDomain          string
	metricsRegistry    *metricsd.Registry
	prometheusExporter *metricsd.PrometheusExporter
}

// Config holds server configuration
type Config struct {
	ListenAddr      string              // Address to listen on (e.g., ":8080")
	ScheddName      string              // Schedd name
	ScheddAddr      string              // Schedd address (e.g., "127.0.0.1:9618"). If empty, discovered from collector.
	UserHeader      string              // HTTP header to extract username from (optional)
	SigningKeyPath  string              // Path to token signing key (optional, for token generation)
	TrustDomain     string              // Trust domain for token issuer (optional; only used if UserHeader is set)
	UIDDomain       string              // UID domain for generated token username (optional; only used if UserHeader is set)
	TLSCertFile     string              // Path to TLS certificate file (optional, enables HTTPS)
	TLSKeyFile      string              // Path to TLS key file (optional, enables HTTPS)
	ReadTimeout     time.Duration       // HTTP read timeout (default: 30s)
	WriteTimeout    time.Duration       // HTTP write timeout (default: 30s)
	IdleTimeout     time.Duration       // HTTP idle timeout (default: 120s)
	Collector       *htcondor.Collector // Collector for metrics (optional)
	EnableMetrics   bool                // Enable /metrics endpoint (default: true if Collector is set)
	MetricsCacheTTL time.Duration       // Metrics cache TTL (default: 10s)
}

// NewServer creates a new HTTP API server
func NewServer(cfg Config) (*Server, error) {
	// Discover schedd address if not provided
	scheddAddr := cfg.ScheddAddr
	if scheddAddr == "" {
		if cfg.Collector == nil {
			return nil, fmt.Errorf("ScheddAddr not provided and Collector not configured for discovery")
		}

		log.Printf("ScheddAddr not provided, discovering schedd '%s' from collector...", cfg.ScheddName)
		var err error
		scheddAddr, err = discoverSchedd(cfg.Collector, cfg.ScheddName, 10*time.Second)
		if err != nil {
			return nil, fmt.Errorf("failed to discover schedd: %w", err)
		}
		log.Printf("Discovered schedd at: %s", scheddAddr)
	}

	// Create schedd with the address as-is (can be host:port or sinful string)
	schedd := htcondor.NewSchedd(cfg.ScheddName, scheddAddr)

	s := &Server{
		schedd:         schedd,
		trustDomain:    cfg.TrustDomain,
		uidDomain:      cfg.UIDDomain,
		userHeader:     cfg.UserHeader,
		signingKeyPath: cfg.SigningKeyPath,
	}

	// Setup metrics if collector is provided
	enableMetrics := cfg.EnableMetrics
	if cfg.Collector != nil && !cfg.EnableMetrics {
		enableMetrics = true // Enable by default if collector is provided
	}

	if enableMetrics && cfg.Collector != nil {
		registry := metricsd.NewRegistry()

		// Set cache TTL
		cacheTTL := cfg.MetricsCacheTTL
		if cacheTTL == 0 {
			cacheTTL = 10 * time.Second
		}
		registry.SetCacheTTL(cacheTTL)

		// Register collectors
		poolCollector := metricsd.NewPoolCollector(cfg.Collector)
		registry.Register(poolCollector)

		processCollector := metricsd.NewProcessCollector()
		registry.Register(processCollector)

		s.metricsRegistry = registry
		s.prometheusExporter = metricsd.NewPrometheusExporter(registry)

		log.Printf("Metrics endpoint enabled at /metrics")
	}

	mux := http.NewServeMux()
	s.setupRoutes(mux)

	// Set default timeouts if not specified
	readTimeout := cfg.ReadTimeout
	if readTimeout == 0 {
		readTimeout = 30 * time.Second
	}
	writeTimeout := cfg.WriteTimeout
	if writeTimeout == 0 {
		writeTimeout = 30 * time.Second
	}
	idleTimeout := cfg.IdleTimeout
	if idleTimeout == 0 {
		idleTimeout = 120 * time.Second
	}

	s.httpServer = &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      mux,
		ReadTimeout:  readTimeout,
		WriteTimeout: writeTimeout,
		IdleTimeout:  idleTimeout,
	}

	return s, nil
}

// Start starts the HTTP server
func (s *Server) Start() error {
	log.Printf("Starting HTCondor API server on %s", s.httpServer.Addr)
	return s.httpServer.ListenAndServe()
}

// StartTLS starts the HTTPS server with TLS
func (s *Server) StartTLS(certFile, keyFile string) error {
	log.Printf("Starting HTCondor API server on %s (TLS enabled)", s.httpServer.Addr)
	return s.httpServer.ListenAndServeTLS(certFile, keyFile)
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
	if err := json.NewEncoder(w).Encode(ErrorResponse{
		Error:   http.StatusText(statusCode),
		Message: message,
		Code:    statusCode,
	}); err != nil {
		log.Printf("Failed to encode error response: %v", err)
	}
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
		iat := time.Now().Unix()
		exp := time.Now().Add(1 * time.Minute).Unix()
		issuer := s.trustDomain
		if issuer == "" {
			return "", fmt.Errorf("TRUST_DOMAIN not configured for server; cannot generate token")
		}
		if !strings.Contains(username, "@") {
			if s.uidDomain == "" {
				return "", fmt.Errorf("UID_DOMAIN not configured for server; cannot create username %s", username)
			}
			username = username + "@" + s.uidDomain
		}
		token, err := security.GenerateJWT(filepath.Dir(s.signingKeyPath), filepath.Base(s.signingKeyPath), username, issuer, iat, exp, nil)
		if err != nil {
			return "", fmt.Errorf("failed to generate token for user %s: %w", username, err)
		}

		return token, nil
	}

	// No token and can't generate one
	return "", fmt.Errorf("no authorization token and user header not configured")
}

// createAuthenticatedContext creates a context with both token and SecurityConfig set
// This is a helper to avoid duplicating security setup code in every handler
func (s *Server) createAuthenticatedContext(r *http.Request) (context.Context, error) {
	// Extract bearer token or generate from user header
	token, err := s.extractOrGenerateToken(r)
	if err != nil {
		return nil, err
	}

	// Create context with token
	ctx := WithToken(r.Context(), token)

	// Convert token to SecurityConfig and add to context
	secConfig, err := GetSecurityConfigFromToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to configure security: %w", err)
	}
	ctx = htcondor.WithSecurityConfig(ctx, secConfig)

	return ctx, nil
}

// discoverSchedd discovers the schedd address from the collector
func discoverSchedd(collector *htcondor.Collector, scheddName string, timeout time.Duration) (string, error) {
	deadline := time.Now().Add(timeout)
	pollInterval := 1 * time.Second

	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)

		// Query collector for schedd ads
		constraint := ""
		if scheddName != "" {
			constraint = fmt.Sprintf("Name == \"%s\"", scheddName)
		}

		ads, err := collector.QueryAds(ctx, "ScheddAd", constraint)
		cancel()

		if err == nil && len(ads) > 0 {
			var selectedAd *classad.ClassAd

			// If scheddName is empty, try to match hostname or use first schedd
			if scheddName == "" {
				hostname, err := os.Hostname()
				if err == nil {
					// Try to find a schedd whose name matches the hostname
					for _, ad := range ads {
						if nameExpr, ok := ad.Lookup("Name"); ok {
							name := nameExpr.String()
							name = strings.Trim(name, "\"")
							if name == hostname {
								selectedAd = ad
								log.Printf("Found schedd matching hostname: %s", hostname)
								break
							}
						}
					}
				}

				// If no match found, use the first schedd
				if selectedAd == nil {
					selectedAd = ads[0]
					if nameExpr, ok := selectedAd.Lookup("Name"); ok {
						name := nameExpr.String()
						name = strings.Trim(name, "\"")
						log.Printf("Using first schedd found: %s", name)
					}
				}
			} else {
				// Use the first ad (which should match the constraint)
				selectedAd = ads[0]
			}

			// Extract MyAddress from the selected schedd ad
			myAddressExpr, ok := selectedAd.Lookup("MyAddress")
			if !ok {
				return "", fmt.Errorf("schedd ad missing MyAddress attribute")
			}

			// ClassAd String() returns a quoted string; trim surrounding
			// quotes and whitespace. Also remove surrounding angle brackets so
			// the cedar client receives a clean sinful-like address.
			myAddress := strings.TrimSpace(myAddressExpr.String())
			myAddress = strings.Trim(myAddress, "\"")
			myAddress = strings.TrimPrefix(myAddress, "<")
			myAddress = strings.TrimSuffix(myAddress, ">")

			// Reconstruct as a sinful string without outer angle brackets
			// (client.ConnectToAddress accepts either form; normalizing
			// avoids shared-port parsing issues that include trailing '>').
			sinful := fmt.Sprintf("<%s>", myAddress)

			log.Printf("Schedd MyAddress from collector: %s", sinful)

			return sinful, nil
		}

		// Wait before retrying
		if time.Now().Add(pollInterval).Before(deadline) {
			time.Sleep(pollInterval)
		}
	}

	if scheddName != "" {
		return "", fmt.Errorf("timeout after %v: schedd '%s' not found in collector", timeout, scheddName)
	}
	return "", fmt.Errorf("timeout after %v: no schedds found in collector", timeout)
}
