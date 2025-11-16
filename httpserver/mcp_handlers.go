package httpserver

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/bbockelm/cedar/security"
	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/mcpserver"
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
	"golang.org/x/oauth2"
)

// MCPHandler handles MCP protocol over HTTP
type MCPHandler struct {
	mcpServer      *mcpserver.Server
	oauth2Provider *OAuth2Provider
	oauth2Config   *oauth2.Config // For SSO client mode
	logger         *logging.Logger
}

// handleMCPMessage handles MCP JSON-RPC messages over HTTP
func (s *Server) handleMCPMessage(w http.ResponseWriter, r *http.Request) {
	// Validate OAuth2 token
	token, err := s.validateOAuth2Token(r)
	if err != nil {
		s.logger.Error(logging.DestinationHTTP, "OAuth2 validation failed", "error", err)
		s.writeError(w, http.StatusUnauthorized, "Invalid or missing OAuth2 token")
		return
	}

	// Extract username from token
	username := token.GetSession().GetSubject()
	if username == "" {
		s.writeError(w, http.StatusUnauthorized, "Token missing subject")
		return
	}

	// Read MCP message from request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		s.logger.Error(logging.DestinationHTTP, "Failed to read request body", "error", err)
		s.writeError(w, http.StatusBadRequest, "Failed to read request body")
		return
	}

	// Parse MCP message
	var mcpRequest mcpserver.MCPMessage
	if err := json.Unmarshal(body, &mcpRequest); err != nil {
		s.logger.Error(logging.DestinationHTTP, "Failed to parse MCP message", "error", err)
		s.writeError(w, http.StatusBadRequest, "Invalid MCP message format")
		return
	}

	s.logger.Debug(logging.DestinationHTTP, "Received MCP message", "method", mcpRequest.Method, "username", username)

	// Create context with security config for HTCondor operations
	ctx := r.Context()
	
	// If we have a signing key, generate an HTCondor token for this user
	if s.signingKeyPath != "" && s.trustDomain != "" {
		htcToken, err := s.generateHTCondorToken(username)
		if err != nil {
			s.logger.Error(logging.DestinationHTTP, "Failed to generate HTCondor token", "error", err, "username", username)
			s.writeError(w, http.StatusInternalServerError, "Failed to generate authentication token")
			return
		}
		
		// Create security config with the token
		secConfig := &security.SecurityConfig{
			AuthMethods:    []security.AuthMethod{security.AuthToken},
			Authentication: security.SecurityRequired,
			CryptoMethods:  []security.CryptoMethod{security.CryptoAES},
			Encryption:     security.SecurityOptional,
			Integrity:      security.SecurityOptional,
			Token:          htcToken,
		}
		ctx = htcondor.WithSecurityConfig(ctx, secConfig)
	}

	// Create a temporary MCP server to handle this request
	mcpServer, err := mcpserver.NewServer(mcpserver.Config{
		ScheddName:     s.schedd.Name(),
		ScheddAddr:     s.schedd.Address(),
		SigningKeyPath: s.signingKeyPath,
		TrustDomain:    s.trustDomain,
		UIDDomain:      s.uidDomain,
		Logger:         s.logger,
	})
	if err != nil {
		s.logger.Error(logging.DestinationHTTP, "Failed to create MCP server", "error", err)
		s.writeError(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	// Create pipes for stdin/stdout simulation
	var responseBuffer bytes.Buffer
	
	// Write the request to a buffer that the MCP server can read
	requestBuffer := bytes.NewBuffer(body)
	
	// Temporarily replace the server's stdin/stdout
	originalStdin := mcpServer.SetStdin(requestBuffer)
	originalStdout := mcpServer.SetStdout(&responseBuffer)
	defer func() {
		mcpServer.SetStdin(originalStdin)
		mcpServer.SetStdout(originalStdout)
	}()

	// Handle the message directly using the MCP server's handler
	response := mcpServer.HandleMessage(ctx, &mcpRequest)

	// Write response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		s.logger.Error(logging.DestinationHTTP, "Failed to encode response", "error", err)
	}
}

// validateOAuth2Token validates an OAuth2 token from the Authorization header
func (s *Server) validateOAuth2Token(r *http.Request) (fosite.AccessRequester, error) {
	if s.oauth2Provider == nil {
		return nil, fmt.Errorf("OAuth2 not configured")
	}

	// Extract token from Authorization header
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return nil, fmt.Errorf("missing Authorization header")
	}

	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return nil, fmt.Errorf("invalid Authorization header format")
	}

	tokenString := parts[1]

	// Validate the token using fosite
	ctx := r.Context()
	session := &openid.DefaultSession{}
	
	tokenType, accessRequest, err := s.oauth2Provider.GetProvider().IntrospectToken(
		ctx,
		tokenString,
		fosite.AccessToken,
		session,
	)
	_ = tokenType // Not used but returned by IntrospectToken
	
	if err != nil {
		return nil, fmt.Errorf("token validation failed: %w", err)
	}

	return accessRequest, nil
}

// handleOAuth2Authorize handles OAuth2 authorization requests
func (s *Server) handleOAuth2Authorize(w http.ResponseWriter, r *http.Request) {
	if s.oauth2Provider == nil {
		s.writeError(w, http.StatusInternalServerError, "OAuth2 not configured")
		return
	}

	ctx := r.Context()
	
	// Parse authorization request
	ar, err := s.oauth2Provider.GetProvider().NewAuthorizeRequest(ctx, r)
	if err != nil {
		s.logger.Error(logging.DestinationHTTP, "Failed to create authorize request", "error", err)
		s.oauth2Provider.GetProvider().WriteAuthorizeError(ctx, w, ar, err)
		return
	}

	// Extract username from user header if configured
	username := ""
	if s.userHeader != "" {
		username = r.Header.Get(s.userHeader)
	}
	
	// If no user header, check for username in query parameters (for SSO flow)
	if username == "" {
		username = r.URL.Query().Get("username")
	}

	if username == "" {
		s.writeError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	// Create session for this user
	session := DefaultOpenIDConnectSession(username)

	// Generate response
	response, err := s.oauth2Provider.GetProvider().NewAuthorizeResponse(ctx, ar, session)
	if err != nil {
		s.logger.Error(logging.DestinationHTTP, "Failed to create authorize response", "error", err)
		s.oauth2Provider.GetProvider().WriteAuthorizeError(ctx, w, ar, err)
		return
	}

	s.oauth2Provider.GetProvider().WriteAuthorizeResponse(ctx, w, ar, response)
}

// handleOAuth2Token handles OAuth2 token requests
func (s *Server) handleOAuth2Token(w http.ResponseWriter, r *http.Request) {
	if s.oauth2Provider == nil {
		s.writeError(w, http.StatusInternalServerError, "OAuth2 not configured")
		return
	}

	ctx := r.Context()
	
	// Create the session object
	session := &openid.DefaultSession{}

	// Create access request
	accessRequest, err := s.oauth2Provider.GetProvider().NewAccessRequest(ctx, r, session)
	if err != nil {
		s.logger.Error(logging.DestinationHTTP, "Failed to create access request", "error", err)
		s.oauth2Provider.GetProvider().WriteAccessError(ctx, w, accessRequest, err)
		return
	}

	// If this is a client credentials grant and user header is set, use it
	if accessRequest.GetGrantTypes().ExactOne("client_credentials") && s.userHeader != "" {
		username := r.Header.Get(s.userHeader)
		if username != "" {
			session = DefaultOpenIDConnectSession(username)
		}
	}

	// Create access response
	response, err := s.oauth2Provider.GetProvider().NewAccessResponse(ctx, accessRequest)
	if err != nil {
		s.logger.Error(logging.DestinationHTTP, "Failed to create access response", "error", err)
		s.oauth2Provider.GetProvider().WriteAccessError(ctx, w, accessRequest, err)
		return
	}

	s.oauth2Provider.GetProvider().WriteAccessResponse(ctx, w, accessRequest, response)
}

// handleOAuth2Introspect handles OAuth2 token introspection requests
func (s *Server) handleOAuth2Introspect(w http.ResponseWriter, r *http.Request) {
	if s.oauth2Provider == nil {
		s.writeError(w, http.StatusInternalServerError, "OAuth2 not configured")
		return
	}

	ctx := r.Context()
	session := &openid.DefaultSession{}

	ir, err := s.oauth2Provider.GetProvider().NewIntrospectionRequest(ctx, r, session)
	if err != nil {
		s.logger.Error(logging.DestinationHTTP, "Failed to create introspection request", "error", err)
		s.oauth2Provider.GetProvider().WriteIntrospectionError(ctx, w, err)
		return
	}

	s.oauth2Provider.GetProvider().WriteIntrospectionResponse(ctx, w, ir)
}

// handleOAuth2Revoke handles OAuth2 token revocation requests
func (s *Server) handleOAuth2Revoke(w http.ResponseWriter, r *http.Request) {
	if s.oauth2Provider == nil {
		s.writeError(w, http.StatusInternalServerError, "OAuth2 not configured")
		return
	}

	ctx := r.Context()
	
	err := s.oauth2Provider.GetProvider().NewRevocationRequest(ctx, r)
	if err != nil {
		s.logger.Error(logging.DestinationHTTP, "Failed to revoke token", "error", err)
		s.oauth2Provider.GetProvider().WriteRevocationResponse(ctx, w, err)
		return
	}

	s.oauth2Provider.GetProvider().WriteRevocationResponse(ctx, w, nil)
}

// generateHTCondorToken generates an HTCondor token for a user
func (s *Server) generateHTCondorToken(username string) (string, error) {
	if s.signingKeyPath == "" {
		return "", fmt.Errorf("signing key path not configured")
	}

	if s.trustDomain == "" {
		return "", fmt.Errorf("trust domain not configured")
	}

	// Ensure username has domain suffix
	if !strings.Contains(username, "@") {
		if s.uidDomain == "" {
			return "", fmt.Errorf("UID domain not configured")
		}
		username = username + "@" + s.uidDomain
	}

	iat := time.Now().Unix()
	exp := time.Now().Add(1 * time.Hour).Unix()

	token, err := security.GenerateJWT(
		s.signingKeyPath, // directory
		"POOL",           // key name
		username,
		s.trustDomain,
		iat,
		exp,
		nil,
	)
	if err != nil {
		return "", fmt.Errorf("failed to generate JWT: %w", err)
	}

	return token, nil
}
