package httpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/bbockelm/cedar/security"
	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/mcpserver"
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
	"golang.org/x/crypto/bcrypt"
)

// extractUsernameFromToken extracts the username from an OAuth2 token using the configured claim
func (s *Server) extractUsernameFromToken(token fosite.AccessRequester) string {
	// If user header is configured, that takes precedence (already set in context)
	if s.userHeader != "" {
		// This should have been handled earlier, but return subject as fallback
		return token.GetSession().GetSubject()
	}

	// Use configured claim name (default: "sub")
	claimName := s.oauth2UsernameClaim
	if claimName == "" {
		claimName = "sub"
	}

	// If using default "sub" claim, use GetSubject() method
	if claimName == "sub" {
		return token.GetSession().GetSubject()
	}

	// For other claims, get from session's extra claims
	session := token.GetSession()
	if oidcSession, ok := session.(*openid.DefaultSession); ok {
		if claims := oidcSession.IDTokenClaims(); claims != nil {
			if username, ok := claims.Extra[claimName].(string); ok && username != "" {
				return username
			}
		}
	}

	// Fallback to subject if custom claim not found
	return token.GetSession().GetSubject()
}

// handleMCPMessage handles MCP JSON-RPC messages over HTTP
func (s *Server) handleMCPMessage(w http.ResponseWriter, r *http.Request) {
	// Validate OAuth2 token
	token, err := s.validateOAuth2Token(r)
	if err != nil {
		s.logger.Error(logging.DestinationHTTP, "OAuth2 validation failed", "error", err)
		s.writeOAuthError(w, http.StatusUnauthorized, "invalid_token", "Invalid or missing OAuth2 token")
		return
	}

	// Extract username from token using configured claim
	username := s.extractUsernameFromToken(token)
	if username == "" {
		s.writeOAuthError(w, http.StatusUnauthorized, "invalid_token", "Token missing username claim")
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

	s.logger.Info(logging.DestinationHTTP, "Received MCP message", "method", mcpRequest.Method, "username", username)

	// Check if the requested MCP method is allowed based on OAuth2 scopes
	if !s.isMethodAllowedByScopes(token, &mcpRequest) {
		s.logger.Warn(logging.DestinationHTTP, "MCP method not allowed by scopes", "method", mcpRequest.Method, "scopes", token.GetGrantedScopes())
		s.writeOAuthError(w, http.StatusForbidden, "insufficient_scope", "Insufficient permissions for requested operation")
		return
	}

	// Create context with security config for HTCondor operations
	ctx := r.Context()

	s.logger.Info(logging.DestinationHTTP, "Signing key path", "path", s.signingKeyPath, "trust_domain", s.trustDomain)

	// Generate HTCondor token with appropriate permissions based on OAuth2 scopes
	// If we have a signing key, generate an HTCondor token for this user
	if s.signingKeyPath != "" && s.trustDomain != "" {
		htcToken, err := s.generateHTCondorTokenWithScopes(username, token.GetGrantedScopes())
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
			SecurityTag:    username,
		}
		ctx = htcondor.WithSecurityConfig(ctx, secConfig)
	}

	// Create a temporary MCP server to handle this request
	// IMPORTANT: Reuse the HTTP server's schedd connection to avoid redundant
	// authentication and key exchange on every MCP request
	mcpServer, err := mcpserver.NewServer(mcpserver.Config{
		Schedd:         s.schedd,
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

// filterRequestedScopes filters the requested scopes to only include those allowed for the client.
// This prevents errors when clients request scopes that were added after registration.
func (s *Server) filterRequestedScopes(ctx context.Context, r *http.Request) (*http.Request, error) {
	// Get client_id from the request
	clientID := r.FormValue("client_id")
	if clientID == "" {
		// No client_id, can't filter - return original request
		return r, nil
	}

	// Get the client from storage
	client, err := s.oauth2Provider.GetStorage().GetClient(ctx, clientID)
	if err != nil {
		// Client not found or error - let fosite handle it
		return r, nil
	}

	// Get requested scopes from the request
	requestedScopesStr := r.FormValue("scope")
	if requestedScopesStr == "" {
		// No scopes requested, nothing to filter
		return r, nil
	}

	requestedScopes := strings.Fields(requestedScopesStr)
	allowedScopes := client.GetScopes()

	// Create a map of allowed scopes for quick lookup
	allowedScopeMap := make(map[string]bool)
	for _, scope := range allowedScopes {
		allowedScopeMap[scope] = true
	}

	// Filter to only allowed scopes
	filteredScopes := make([]string, 0, len(requestedScopes))
	for _, scope := range requestedScopes {
		if allowedScopeMap[scope] {
			filteredScopes = append(filteredScopes, scope)
		} else {
			s.logger.Info(logging.DestinationHTTP, "Filtering out unavailable scope for client",
				"client_id", clientID, "scope", scope)
		}
	}

	// If no scopes were filtered, return original request
	if len(filteredScopes) == len(requestedScopes) {
		return r, nil
	}

	// Create a new request with filtered scopes
	// Clone the request and modify the Form values
	newReq := r.Clone(ctx)
	if err := newReq.ParseForm(); err != nil {
		return r, err
	}

	// Update the scope parameter
	newReq.Form.Set("scope", strings.Join(filteredScopes, " "))

	s.logger.Info(logging.DestinationHTTP, "Filtered scopes for client",
		"client_id", clientID,
		"requested", len(requestedScopes),
		"allowed", len(filteredScopes))

	return newReq, nil
}

// handleOAuth2Authorize handles OAuth2 authorization requests
func (s *Server) handleOAuth2Authorize(w http.ResponseWriter, r *http.Request) {
	if s.oauth2Provider == nil {
		s.writeError(w, http.StatusInternalServerError, "OAuth2 not configured")
		return
	}

	ctx := r.Context()

	// Filter requested scopes to only those allowed for the client
	filteredReq, err := s.filterRequestedScopes(ctx, r)
	if err != nil {
		s.logger.Error(logging.DestinationHTTP, "Failed to filter scopes", "error", err)
		// Continue with original request if filtering fails
		filteredReq = r
	}

	// Parse authorization request
	ar, err := s.oauth2Provider.GetProvider().NewAuthorizeRequest(ctx, filteredReq)
	if err != nil {
		s.logger.Error(logging.DestinationHTTP, "Failed to create authorize request", "error", err)
		s.oauth2Provider.GetProvider().WriteAuthorizeError(ctx, w, ar, err)
		return
	}

	// Determine authentication method:
	// 1. If userHeader is configured, use that (for demo/testing mode)
	// 2. If existing session, use that
	// 3. If OAuth2 SSO is configured and no userHeader, initiate SSO flow

	username := ""

	// Method 1: User header (demo mode)
	if s.userHeader != "" {
		username = r.Header.Get(s.userHeader)
		if username != "" {
			s.logger.Info(logging.DestinationHTTP, "User authenticated via header",
				"username", username, "header", s.userHeader)
		}
	}

	// Method 2: Existing session
	if username == "" {
		// Check if user has a session
		if session, ok := s.getSessionFromRequest(r); ok {
			username = session.Username
			s.logger.Info(logging.DestinationHTTP, "User authenticated via session", "username", username)
		}
	}

	// Method 3: OAuth2 SSO flow
	if username == "" {
		// If OAuth2 SSO is configured, redirect to upstream IDP
		if s.oauth2Config != nil {
			// Generate state parameter
			state, err := s.oauth2StateStore.GenerateState()
			if err != nil {
				s.logger.Error(logging.DestinationHTTP, "Failed to generate OAuth2 state", "error", err)
				s.writeError(w, http.StatusInternalServerError, "Failed to initiate authorization")
				return
			}

			// Store authorize request for later retrieval
			s.oauth2StateStore.Store(state, ar)

			// Build authorization URL
			authURL := s.oauth2Config.AuthCodeURL(state)

			s.logger.Info(logging.DestinationHTTP, "Redirecting to IDP for authentication",
				"client_id", ar.GetClient().GetID(), "state", state, "auth_url", authURL)

			// Redirect to IDP
			http.Redirect(w, r, authURL, http.StatusFound)
			return
		}
	}

	// If still no username, authentication is required
	if username == "" {
		s.logger.Error(logging.DestinationHTTP, "No authentication method available")
		s.writeError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	// User authenticated via header or query parameter - redirect to consent page
	s.logger.Info(logging.DestinationHTTP, "User authenticated, redirecting to consent page",
		"username", username, "client_id", ar.GetClient().GetID())

	// Generate state parameter for consent
	state, err := s.oauth2StateStore.GenerateState()
	if err != nil {
		s.logger.Error(logging.DestinationHTTP, "Failed to generate consent state", "error", err)
		s.writeError(w, http.StatusInternalServerError, "Failed to initiate authorization")
		return
	}

	// Store authorize request and username for consent page
	s.oauth2StateStore.StoreWithUsername(state, ar, "", username)

	// Redirect to consent page
	consentURL := fmt.Sprintf("/mcp/oauth2/consent?state=%s", state)
	http.Redirect(w, r, consentURL, http.StatusFound)
}

// getScopeDescription returns a human-readable description of an OAuth2 scope
func getScopeDescription(scope string) string {
	descriptions := map[string]string{
		"openid":                   "Basic authentication information",
		"profile":                  "Access to your profile information",
		"email":                    "Access to your email address",
		"offline_access":           "Ability to refresh access tokens",
		"mcp:read":                 "Read-only access to HTCondor jobs and resources via MCP protocol",
		"mcp:write":                "Full access to submit and manage HTCondor jobs via MCP protocol",
		"condor:/READ":             "HTCondor READ authorization - allows reading job and daemon information",
		"condor:/WRITE":            "HTCondor WRITE authorization - allows submitting and managing jobs",
		"condor:/ADVERTISE_STARTD": "HTCondor ADVERTISE_STARTD authorization - allows advertising startd daemons",
		"condor:/ADVERTISE_SCHEDD": "HTCondor ADVERTISE_SCHEDD authorization - allows advertising schedd daemons",
		"condor:/ADVERTISE_MASTER": "HTCondor ADVERTISE_MASTER authorization - allows advertising master daemons",
		"condor:/ADMINISTRATOR":    "HTCondor ADMINISTRATOR authorization - full administrative access",
		"condor:/CONFIG":           "HTCondor CONFIG authorization - allows modifying configuration",
		"condor:/DAEMON":           "HTCondor DAEMON authorization - allows daemon-to-daemon communication",
		"condor:/NEGOTIATOR":       "HTCondor NEGOTIATOR authorization - allows negotiator operations",
	}

	if desc, ok := descriptions[scope]; ok {
		return desc
	}

	// Handle custom condor:/* scopes
	if strings.HasPrefix(scope, "condor:/") {
		authLevel := strings.TrimPrefix(scope, "condor:/")
		return fmt.Sprintf("HTCondor %s authorization", authLevel)
	}

	// Default for unknown scopes
	return fmt.Sprintf("Access with scope: %s", scope)
}

// handleOAuth2Consent handles the OAuth2 consent page
func (s *Server) handleOAuth2Consent(w http.ResponseWriter, r *http.Request) {
	if s.oauth2Provider == nil {
		s.writeError(w, http.StatusInternalServerError, "OAuth2 not configured")
		return
	}

	ctx := r.Context()

	// Get state from query parameter for GET or form value for POST
	state := r.URL.Query().Get("state")
	if state == "" && r.Method == http.MethodPost {
		// Parse form first if POST
		if err := r.ParseForm(); err == nil {
			state = r.FormValue("state")
		}
	}

	if state == "" {
		s.writeError(w, http.StatusBadRequest, "Missing state parameter")
		return
	}

	// Retrieve the authorize request and username
	ar, username, ok := s.oauth2StateStore.GetWithUsername(state)
	if !ok || ar == nil {
		s.logger.Error(logging.DestinationHTTP, "Invalid or expired consent state", "state", state)
		s.writeError(w, http.StatusBadRequest, "Invalid or expired consent request")
		return
	}

	if r.Method == http.MethodGet {
		// Display consent form
		client := ar.GetClient()
		requestedScopes := ar.GetRequestedScopes()

		// Build scopes list with descriptions
		type scopeInfo struct {
			Name        string
			Description string
		}
		var scopes []scopeInfo
		for _, scope := range requestedScopes {
			scopes = append(scopes, scopeInfo{
				Name:        scope,
				Description: getScopeDescription(scope),
			})
		}

		// Generate HTML for scopes list
		var scopesHTML strings.Builder
		scopesHTML.WriteString("<ul class=\"scopes-list\">\n")
		for _, scope := range scopes {
			scopesHTML.WriteString(fmt.Sprintf("                <li>\n"+
				"                    <strong>%s</strong>\n"+
				"                    <p>%s</p>\n"+
				"                </li>\n", scope.Name, scope.Description))
		}
		scopesHTML.WriteString("            </ul>")

		html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <title>Authorize Application</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        .container {
            background: white;
            border-radius: 12px;
            box-shadow: 0 10px 40px rgba(0, 0, 0, 0.2);
            max-width: 600px;
            width: 100%%;
            padding: 40px;
        }
        h1 {
            color: #333;
            margin-bottom: 10px;
            font-size: 28px;
        }
        .user-info {
            color: #666;
            font-size: 14px;
            margin-bottom: 30px;
            padding: 15px;
            background: #f8f9fa;
            border-radius: 6px;
        }
        .user-info strong {
            color: #333;
        }
        .client-info {
            margin-bottom: 30px;
            padding: 20px;
            background: #f0f4ff;
            border-left: 4px solid #667eea;
            border-radius: 6px;
        }
        .client-info h2 {
            font-size: 16px;
            color: #667eea;
            margin-bottom: 10px;
        }
        .client-info p {
            color: #555;
            font-size: 14px;
            line-height: 1.6;
        }
        .permissions {
            margin-bottom: 30px;
        }
        .permissions h2 {
            font-size: 18px;
            color: #333;
            margin-bottom: 15px;
        }
        .scopes-list {
            list-style: none;
            border: 1px solid #e0e0e0;
            border-radius: 8px;
            overflow: hidden;
        }
        .scopes-list li {
            padding: 16px 20px;
            border-bottom: 1px solid #e0e0e0;
        }
        .scopes-list li:last-child {
            border-bottom: none;
        }
        .scopes-list li strong {
            display: block;
            color: #667eea;
            font-size: 14px;
            margin-bottom: 4px;
            font-weight: 600;
        }
        .scopes-list li p {
            color: #666;
            font-size: 13px;
            line-height: 1.5;
            margin: 0;
        }
        .actions {
            display: flex;
            gap: 15px;
            margin-top: 30px;
        }
        button {
            flex: 1;
            padding: 14px 24px;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
        }
        button.approve {
            background: #667eea;
            color: white;
        }
        button.approve:hover {
            background: #5568d3;
            transform: translateY(-1px);
            box-shadow: 0 4px 12px rgba(102, 126, 234, 0.4);
        }
        button.deny {
            background: #e0e0e0;
            color: #666;
        }
        button.deny:hover {
            background: #d0d0d0;
            color: #333;
        }
        .warning {
            margin-top: 20px;
            padding: 15px;
            background: #fff3cd;
            border-left: 4px solid #ffc107;
            border-radius: 6px;
            font-size: 13px;
            color: #856404;
            line-height: 1.5;
        }
        @media (max-width: 600px) {
            .container {
                padding: 30px 20px;
            }
            h1 {
                font-size: 24px;
            }
            .actions {
                flex-direction: column;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Authorize Application</h1>
        <div class="user-info">
            Logged in as <strong>%s</strong>
        </div>

        <div class="client-info">
            <h2>Application Information</h2>
            <p><strong>Client ID:</strong> %s</p>
        </div>

        <div class="permissions">
            <h2>Requested Permissions</h2>
            <p style="color: #666; font-size: 14px; margin-bottom: 15px;">
                This application is requesting access to:
            </p>
            %s
        </div>

        <form method="POST" action="/mcp/oauth2/consent">
            <input type="hidden" name="state" value="%s">
            <div class="actions">
                <button type="submit" name="action" value="approve" class="approve">Authorize</button>
                <button type="submit" name="action" value="deny" class="deny">Deny</button>
            </div>
        </form>

        <div class="warning">
            <strong>⚠️ Security Notice:</strong> Only authorize applications you trust.
            This will allow the application to perform actions on your behalf with the permissions listed above.
        </div>
    </div>
</body>
</html>`, username, client.GetID(), scopesHTML.String(), state)

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(html))
		return
	}

	if r.Method == http.MethodPost {
		// Form already parsed above when getting state
		// Handle approval/denial
		action := r.FormValue("action")

		if action == "approve" {
			// User approved - create session and complete authorization
			session := DefaultOpenIDConnectSession(username)

			// Grant all requested scopes
			requestedScopes := ar.GetRequestedScopes()
			for _, scope := range requestedScopes {
				ar.GrantScope(scope)
			}

			s.logger.Info(logging.DestinationHTTP, "User approved consent",
				"username", username, "client_id", ar.GetClient().GetID(), "scopes", requestedScopes)

			// Generate OAuth2 response
			response, err := s.oauth2Provider.GetProvider().NewAuthorizeResponse(ctx, ar, session)
			if err != nil {
				s.logger.Error(logging.DestinationHTTP, "Failed to create authorize response after consent",
					"error", err, "username", username)
				s.oauth2Provider.GetProvider().WriteAuthorizeError(ctx, w, ar, err)
				// Remove the state entry
				s.oauth2StateStore.Remove(state)
				return
			}

			s.logger.Info(logging.DestinationHTTP, "Successfully created authorize response after consent", "username", username)

			// Remove the state entry
			s.oauth2StateStore.Remove(state)

			// Write the OAuth2 response
			s.oauth2Provider.GetProvider().WriteAuthorizeResponse(ctx, w, ar, response)
			return
		}

		if action == "deny" {
			// User denied - return access denied error
			s.logger.Info(logging.DestinationHTTP, "User denied consent",
				"username", username, "client_id", ar.GetClient().GetID())

			// Remove the state entry
			s.oauth2StateStore.Remove(state)

			// Return access denied error to client
			accessDeniedErr := fosite.ErrAccessDenied.WithDescription("User denied authorization")
			s.oauth2Provider.GetProvider().WriteAuthorizeError(ctx, w, ar, accessDeniedErr)
			return
		}

		// Invalid action
		s.writeError(w, http.StatusBadRequest, "Invalid action")
		return
	}

	s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
}

// handleOAuth2Token handles OAuth2 token requests
func (s *Server) handleOAuth2Token(w http.ResponseWriter, r *http.Request) {
	if s.oauth2Provider == nil {
		s.writeError(w, http.StatusInternalServerError, "OAuth2 not configured")
		return
	}

	ctx := r.Context()

	// Parse form data
	if err := r.ParseForm(); err != nil {
		s.logger.Error(logging.DestinationHTTP, "Failed to parse form", "error", err)
		s.writeOAuthError(w, http.StatusBadRequest, "invalid_request", "Failed to parse request")
		return
	}

	// Filter requested scopes to only those allowed for the client
	filteredReq, err := s.filterRequestedScopes(ctx, r)
	if err != nil {
		s.logger.Error(logging.DestinationHTTP, "Failed to filter scopes", "error", err)
		// Continue with original request if filtering fails
		filteredReq = r
	}
	r = filteredReq

	grantType := r.FormValue("grant_type")

	// Log the incoming request for debugging
	s.logger.Info(logging.DestinationHTTP, "Token request received",
		"grant_type", grantType,
		"client_id", r.FormValue("client_id"),
		"scope", r.FormValue("scope"))

	// Handle device_code grant type separately
	if grantType == "urn:ietf:params:oauth:grant-type:device_code" {
		s.handleDeviceCodeTokenRequest(w, r)
		return
	}

	// Create the session object
	session := &openid.DefaultSession{}

	// Create access request
	accessRequest, err := s.oauth2Provider.GetProvider().NewAccessRequest(ctx, r, session)
	if err != nil {
		// Extract more detailed error information
		errorDetails := fmt.Sprintf("%v", err)
		var rfc6749Err *fosite.RFC6749Error
		if errors.As(err, &rfc6749Err) {
			errorDetails = fmt.Sprintf("RFC6749Error: name=%s, description=%s, hint=%s, debug=%s",
				rfc6749Err.ErrorField, rfc6749Err.DescriptionField, rfc6749Err.HintField, rfc6749Err.DebugField)
		}
		s.logger.Error(logging.DestinationHTTP, "Failed to create access request",
			"error", err, "error_details", errorDetails,
			"client_id", r.FormValue("client_id"))
		s.oauth2Provider.GetProvider().WriteAccessError(ctx, w, accessRequest, err)
		return
	}

	// Create access response (for all flows - this generates tokens including refresh token)
	s.logger.Info(logging.DestinationHTTP, "Creating access response",
		"grant_type", accessRequest.GetRequestForm().Get("grant_type"),
		"requested_scopes", accessRequest.GetRequestedScopes())
	response, err := s.oauth2Provider.GetProvider().NewAccessResponse(ctx, accessRequest)
	if err != nil {
		// Log more details about the error - unwrap to see the root cause
		rootErr := err
		for errors.Unwrap(rootErr) != nil {
			rootErr = errors.Unwrap(rootErr)
		}
		s.logger.Error(logging.DestinationHTTP, "Failed to create access response",
			"error", err,
			"root_error", rootErr,
			"grant_type", accessRequest.GetRequestForm().Get("grant_type"),
			"client_id", accessRequest.GetClient().GetID())
		s.oauth2Provider.GetProvider().WriteAccessError(ctx, w, accessRequest, err)
		return
	}
	s.logger.Info(logging.DestinationHTTP, "Successfully created access response")

	// Check if condor:/* scopes are requested
	requestedScopes := accessRequest.GetRequestedScopes()
	if hasCondorScopes(requestedScopes) {
		// Generate HTCondor IDTOKEN and replace the access token
		s.replaceWithCondorToken(ctx, w, r, accessRequest, response)
		return
	}

	// Standard OAuth2 flow - write the response as-is
	s.oauth2Provider.GetProvider().WriteAccessResponse(ctx, w, accessRequest, response)
}

// replaceWithCondorToken replaces the OAuth2 access token with an HTCondor IDTOKEN
// while preserving the refresh token and other fields
func (s *Server) replaceWithCondorToken(ctx context.Context, w http.ResponseWriter, _ *http.Request, accessRequest fosite.AccessRequester, response fosite.AccessResponder) {
	// Check if we can generate HTCondor tokens
	if s.signingKeyPath == "" || s.trustDomain == "" {
		s.logger.Error(logging.DestinationHTTP, "Cannot generate condor tokens: signing key or trust domain not configured")
		err := &fosite.RFC6749Error{
			ErrorField:       "server_error",
			DescriptionField: "Server not configured to issue HTCondor tokens",
			HintField:        "Contact administrator to configure signing key and trust domain",
			CodeField:        http.StatusInternalServerError,
		}
		s.oauth2Provider.GetProvider().WriteAccessError(ctx, w, accessRequest, err)
		return
	}

	// Get the username from the session
	username := accessRequest.GetSession().GetSubject()
	if username == "" {
		s.logger.Error(logging.DestinationHTTP, "Cannot generate condor token: no username in session")
		err := &fosite.RFC6749Error{
			ErrorField:       "invalid_request",
			DescriptionField: "Cannot determine user identity",
			CodeField:        http.StatusBadRequest,
		}
		s.oauth2Provider.GetProvider().WriteAccessError(ctx, w, accessRequest, err)
		return
	}

	// Get requested scopes
	requestedScopes := accessRequest.GetRequestedScopes()

	// Generate HTCondor IDTOKEN
	idtoken, err := s.generateHTCondorTokenWithScopes(username, requestedScopes)
	if err != nil {
		s.logger.Error(logging.DestinationHTTP, "Failed to generate HTCondor IDTOKEN",
			"error", err,
			"username", username,
			"scopes", requestedScopes)
		fositeErr := &fosite.RFC6749Error{
			ErrorField:       "server_error",
			DescriptionField: "Failed to generate HTCondor IDTOKEN",
			CodeField:        http.StatusInternalServerError,
		}
		s.oauth2Provider.GetProvider().WriteAccessError(ctx, w, accessRequest, fositeErr)
		return
	}

	s.logger.Info(logging.DestinationHTTP, "Generated HTCondor IDTOKEN for condor scopes",
		"username", username,
		"scopes", requestedScopes)

	// Get the response as a map and replace the access token with HTCondor IDTOKEN
	// The response already has the refresh token and other OAuth2 fields
	tokenResponse := response.ToMap()
	s.logger.Info(logging.DestinationHTTP, "Token response map created", "has_refresh_token", tokenResponse["refresh_token"] != nil)
	tokenResponse["access_token"] = idtoken
	tokenResponse["token_type"] = "Bearer"

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusOK)

	if err := json.NewEncoder(w).Encode(tokenResponse); err != nil {
		s.logger.Error(logging.DestinationHTTP, "Failed to encode token response", "error", err)
	}
}

// handleDeviceCodeTokenRequest handles token requests with device_code grant type
func (s *Server) handleDeviceCodeTokenRequest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	deviceCode := r.FormValue("device_code")
	if deviceCode == "" {
		s.writeOAuthError(w, http.StatusBadRequest, "invalid_request", "device_code is required")
		return
	}

	// Create device code handler
	deviceHandler := NewDeviceCodeHandler(s.oauth2Provider.GetStorage(), s.oauth2Provider.config)

	// Create session
	session := &openid.DefaultSession{}

	// Handle device code access request
	request, err := deviceHandler.HandleDeviceAccessRequest(ctx, deviceCode, session)
	if err != nil {
		// Map errors to OAuth error responses
		if errors.Is(err, ErrAuthorizationPending) {
			s.writeOAuthError(w, http.StatusBadRequest, "authorization_pending", "Authorization pending")
			return
		}
		if errors.Is(err, fosite.ErrAccessDenied) {
			s.writeOAuthError(w, http.StatusBadRequest, "access_denied", "Authorization denied by user")
			return
		}
		s.logger.Error(logging.DestinationHTTP, "Device code token request failed", "error", err)
		s.writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "Invalid device code")
		return
	}

	// Check if condor:/* scopes are requested - generate HTCondor IDTOKEN instead
	grantedScopes := request.GetGrantedScopes()
	if hasCondorScopes(grantedScopes) {
		s.handleDeviceCodeCondorToken(ctx, w, r, request)
		return
	}

	// Generate tokens using fosite
	strategy := s.oauth2Provider.GetStrategy()
	accessToken, _, err := strategy.GenerateAccessToken(ctx, request)
	if err != nil {
		s.logger.Error(logging.DestinationHTTP, "Failed to generate access token", "error", err)
		s.writeOAuthError(w, http.StatusInternalServerError, "server_error", "Failed to generate token")
		return
	}

	refreshToken, _, err := strategy.GenerateRefreshToken(ctx, request)
	if err != nil {
		s.logger.Error(logging.DestinationHTTP, "Failed to generate refresh token", "error", err)
		s.writeOAuthError(w, http.StatusInternalServerError, "server_error", "Failed to generate token")
		return
	}

	// Store tokens
	signature := strategy.AccessTokenSignature(ctx, accessToken)
	if err := s.oauth2Provider.GetStorage().CreateAccessTokenSession(ctx, signature, request); err != nil {
		s.logger.Error(logging.DestinationHTTP, "Failed to store access token", "error", err)
		s.writeOAuthError(w, http.StatusInternalServerError, "server_error", "Failed to store token")
		return
	}

	refreshSignature := strategy.RefreshTokenSignature(ctx, refreshToken)
	if err := s.oauth2Provider.GetStorage().CreateRefreshTokenSession(ctx, refreshSignature, request); err != nil {
		s.logger.Error(logging.DestinationHTTP, "Failed to store refresh token", "error", err)
		s.writeOAuthError(w, http.StatusInternalServerError, "server_error", "Failed to store token")
		return
	}

	// Build response
	response := map[string]interface{}{
		"access_token":  accessToken,
		"token_type":    "Bearer",
		"expires_in":    int(s.oauth2Provider.config.GetAccessTokenLifespan(ctx).Seconds()),
		"refresh_token": refreshToken,
		"scope":         strings.Join(request.GetGrantedScopes(), " "),
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		s.logger.Error(logging.DestinationHTTP, "Failed to encode response", "error", err)
	}
}

// handleDeviceCodeCondorToken handles device code token requests when condor scopes are requested
// It generates an HTCondor IDTOKEN instead of a standard OAuth2 access token
func (s *Server) handleDeviceCodeCondorToken(ctx context.Context, w http.ResponseWriter, _ *http.Request, request fosite.Requester) {
	// Check if we can generate HTCondor tokens
	if s.signingKeyPath == "" || s.trustDomain == "" {
		s.logger.Error(logging.DestinationHTTP, "Cannot generate condor tokens: signing key or trust domain not configured")
		s.writeOAuthError(w, http.StatusInternalServerError, "server_error", "Server not configured to issue HTCondor tokens")
		return
	}

	// Get the username from the session
	username := request.GetSession().GetSubject()
	if username == "" {
		s.logger.Error(logging.DestinationHTTP, "Cannot generate condor token: no username in session")
		s.writeOAuthError(w, http.StatusBadRequest, "invalid_request", "Cannot determine user identity")
		return
	}

	// Get granted scopes
	grantedScopes := request.GetGrantedScopes()

	// Generate HTCondor IDTOKEN
	idtoken, err := s.generateHTCondorTokenWithScopes(username, grantedScopes)
	if err != nil {
		s.logger.Error(logging.DestinationHTTP, "Failed to generate HTCondor IDTOKEN",
			"error", err,
			"username", username,
			"scopes", grantedScopes)
		s.writeOAuthError(w, http.StatusInternalServerError, "server_error", "Failed to generate HTCondor IDTOKEN")
		return
	}

	s.logger.Info(logging.DestinationHTTP, "Generated HTCondor IDTOKEN for device code flow",
		"username", username,
		"scopes", grantedScopes)

	// Generate refresh token using fosite
	strategy := s.oauth2Provider.GetStrategy()
	refreshToken, _, err := strategy.GenerateRefreshToken(ctx, request)
	if err != nil {
		s.logger.Error(logging.DestinationHTTP, "Failed to generate refresh token", "error", err)
		s.writeOAuthError(w, http.StatusInternalServerError, "server_error", "Failed to generate token")
		return
	}

	// Store the refresh token session
	refreshSignature := strategy.RefreshTokenSignature(ctx, refreshToken)
	if err := s.oauth2Provider.GetStorage().CreateRefreshTokenSession(ctx, refreshSignature, request); err != nil {
		s.logger.Error(logging.DestinationHTTP, "Failed to store refresh token", "error", err)
		s.writeOAuthError(w, http.StatusInternalServerError, "server_error", "Failed to store token")
		return
	}

	// Build response with HTCondor IDTOKEN as access token
	response := map[string]interface{}{
		"access_token":  idtoken,
		"token_type":    "Bearer",
		"expires_in":    int(s.oauth2Provider.config.GetAccessTokenLifespan(ctx).Seconds()),
		"refresh_token": refreshToken,
		"scope":         strings.Join(grantedScopes, " "),
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		s.logger.Error(logging.DestinationHTTP, "Failed to encode response", "error", err)
	}
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

// handleOAuth2Register handles dynamic client registration (RFC 7591)
func (s *Server) handleOAuth2Register(w http.ResponseWriter, r *http.Request) {
	if s.oauth2Provider == nil {
		s.writeError(w, http.StatusInternalServerError, "OAuth2 not configured")
		return
	}

	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	ctx := r.Context()

	// Parse registration request
	var regReq struct {
		RedirectURIs  []string `json:"redirect_uris"`
		GrantTypes    []string `json:"grant_types"`
		ResponseTypes []string `json:"response_types"`
		Scopes        []string `json:"scope"`
		ClientName    string   `json:"client_name"`
	}

	if err := json.NewDecoder(r.Body).Decode(&regReq); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid registration request")
		return
	}

	// Validate redirect URIs
	if len(regReq.RedirectURIs) == 0 {
		s.writeError(w, http.StatusBadRequest, "At least one redirect_uri is required")
		return
	}

	// Generate client ID and secret
	clientID := fmt.Sprintf("client_%d", time.Now().UnixNano())
	clientSecret := generateRandomString(32)

	// Hash the client secret with bcrypt (fosite expects bcrypt-hashed secrets)
	hashedSecret, err := bcrypt.GenerateFromPassword([]byte(clientSecret), bcrypt.DefaultCost)
	if err != nil {
		s.logger.Error(logging.DestinationHTTP, "Failed to hash client secret", "error", err)
		s.writeError(w, http.StatusInternalServerError, "Failed to register client")
		return
	}

	// Default values
	if len(regReq.GrantTypes) == 0 {
		regReq.GrantTypes = []string{"authorization_code", "refresh_token"}
	}
	if len(regReq.ResponseTypes) == 0 {
		regReq.ResponseTypes = []string{"code"}
	}
	if len(regReq.Scopes) == 0 {
		regReq.Scopes = []string{"openid", "profile", "email", "mcp:read", "mcp:write"}
	}

	// Validate requested scopes against supported scopes
	supportedScopes := map[string]bool{
		"openid":    true,
		"profile":   true,
		"email":     true,
		"mcp:read":  true,
		"mcp:write": true,
	}
	for _, scope := range regReq.Scopes {
		// Allow condor:/* scopes
		if strings.HasPrefix(scope, "condor:/") {
			continue
		}
		if !supportedScopes[scope] {
			s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Unsupported scope: %s", scope))
			return
		}
	}

	// Create the client
	client := &fosite.DefaultClient{
		ID:            clientID,
		Secret:        hashedSecret,
		RedirectURIs:  regReq.RedirectURIs,
		GrantTypes:    regReq.GrantTypes,
		ResponseTypes: regReq.ResponseTypes,
		Scopes:        regReq.Scopes,
		Public:        false,
	}

	if err := s.oauth2Provider.GetStorage().CreateClient(ctx, client); err != nil {
		s.logger.Error(logging.DestinationHTTP, "Failed to create client", "error", err)
		s.writeError(w, http.StatusInternalServerError, "Failed to register client")
		return
	}

	// Return registration response
	resp := map[string]interface{}{
		"client_id":      clientID,
		"client_secret":  clientSecret,
		"redirect_uris":  regReq.RedirectURIs,
		"grant_types":    regReq.GrantTypes,
		"response_types": regReq.ResponseTypes,
		"scope":          strings.Join(regReq.Scopes, " "),
		"client_name":    regReq.ClientName,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		s.logger.Error(logging.DestinationHTTP, "Failed to encode response", "error", err)
	}
}

// generateRandomString generates a random string of specified length
func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[time.Now().UnixNano()%int64(len(charset))]
		time.Sleep(time.Nanosecond) // Ensure different values
	}
	return string(b)
}

// handleOAuth2Metadata handles OAuth2 authorization server metadata discovery
// Implements RFC 8414: OAuth 2.0 Authorization Server Metadata
func (s *Server) handleOAuth2Metadata(w http.ResponseWriter, _ *http.Request) {
	if s.oauth2Provider == nil {
		s.writeError(w, http.StatusNotFound, "OAuth2 not configured")
		return
	}

	// Get the issuer URL from the OAuth2 provider config
	issuer := s.oauth2Provider.config.AccessTokenIssuer

	metadata := map[string]interface{}{
		"issuer":                                issuer,
		"authorization_endpoint":                issuer + "/mcp/oauth2/authorize",
		"token_endpoint":                        issuer + "/mcp/oauth2/token",
		"registration_endpoint":                 issuer + "/mcp/oauth2/register",
		"introspection_endpoint":                issuer + "/mcp/oauth2/introspect",
		"revocation_endpoint":                   issuer + "/mcp/oauth2/revoke",
		"device_authorization_endpoint":         issuer + "/mcp/oauth2/device/authorize",
		"response_types_supported":              []string{"code", "token", "id_token", "code token", "code id_token", "token id_token", "code token id_token"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:device_code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "profile", "email", "mcp:read", "mcp:write", "condor:/READ", "condor:/WRITE", "condor:/ADVERTISE_STARTD", "condor:/ADVERTISE_SCHEDD", "condor:/ADVERTISE_MASTER"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
		"code_challenge_methods_supported":      []string{"plain", "S256"},
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(metadata); err != nil {
		s.logger.Error(logging.DestinationHTTP, "Failed to encode metadata", "error", err)
	}
}

// handleOAuth2ProtectedResourceMetadata handles OAuth 2.0 Protected Resource metadata discovery
// Implements RFC 9068: OAuth 2.0 Protected Resource Metadata
// See: https://datatracker.ietf.org/doc/html/rfc9068
func (s *Server) handleOAuth2ProtectedResourceMetadata(w http.ResponseWriter, _ *http.Request) {
	if s.oauth2Provider == nil {
		s.writeError(w, http.StatusNotFound, "OAuth2 not configured")
		return
	}

	// Get the issuer URL from the OAuth2 provider config
	issuer := s.oauth2Provider.config.AccessTokenIssuer

	metadata := map[string]interface{}{
		"resource":                              issuer,
		"authorization_servers":                 []string{issuer},
		"bearer_methods_supported":              []string{"header"},
		"resource_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "profile", "email", "mcp:read", "mcp:write", "condor:/READ", "condor:/WRITE", "condor:/ADVERTISE_STARTD", "condor:/ADVERTISE_SCHEDD", "condor:/ADVERTISE_MASTER"},
		"resource_documentation":                issuer + "/mcp",
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(metadata); err != nil {
		s.logger.Error(logging.DestinationHTTP, "Failed to encode protected resource metadata", "error", err)
	}
}

// handleOAuth2DeviceAuthorize handles device authorization requests (RFC 8628)
func (s *Server) handleOAuth2DeviceAuthorize(w http.ResponseWriter, r *http.Request) {
	if s.oauth2Provider == nil {
		s.writeError(w, http.StatusInternalServerError, "OAuth2 not configured")
		return
	}

	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	ctx := r.Context()

	// Parse client credentials from request
	clientID := r.FormValue("client_id")
	if clientID == "" {
		s.writeOAuthError(w, http.StatusBadRequest, "invalid_request", "client_id is required")
		return
	}

	// Get client
	client, err := s.oauth2Provider.GetStorage().GetClient(ctx, clientID)
	if err != nil {
		s.logger.Error(logging.DestinationHTTP, "Failed to get client", "error", err, "client_id", clientID)
		s.writeOAuthError(w, http.StatusUnauthorized, "invalid_client", "Client not found")
		return
	}

	// Parse requested scopes
	scopeStr := r.FormValue("scope")
	var scopes []string
	if scopeStr != "" {
		scopes = strings.Split(scopeStr, " ")
	} else {
		// Default scopes
		scopes = []string{"openid", "mcp:read", "mcp:write"}
	}

	// Filter scopes to only those allowed for the client
	allowedScopes := client.GetScopes()
	allowedScopeMap := make(map[string]bool)
	for _, scope := range allowedScopes {
		allowedScopeMap[scope] = true
	}

	filteredScopes := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		if allowedScopeMap[scope] {
			filteredScopes = append(filteredScopes, scope)
		} else {
			s.logger.Info(logging.DestinationHTTP, "Filtering out unavailable scope for device authorization",
				"client_id", clientID, "scope", scope)
		}
	}
	scopes = filteredScopes

	if len(scopes) > 0 {
		s.logger.Info(logging.DestinationHTTP, "Device authorization with filtered scopes",
			"client_id", clientID, "scopes", strings.Join(scopes, " "))
	}

	// Create device code handler
	deviceHandler := NewDeviceCodeHandler(s.oauth2Provider.GetStorage(), s.oauth2Provider.config)

	// Handle device authorization
	resp, err := deviceHandler.HandleDeviceAuthorizationRequest(ctx, client, scopes)
	if err != nil {
		s.logger.Error(logging.DestinationHTTP, "Device authorization failed", "error", err)
		s.writeOAuthError(w, http.StatusBadRequest, "invalid_request", "Device authorization failed")
		return
	}

	// Return device authorization response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		s.logger.Error(logging.DestinationHTTP, "Failed to encode response", "error", err)
	}
}

// handleOAuth2DeviceVerify handles the user code verification page
func (s *Server) handleOAuth2DeviceVerify(w http.ResponseWriter, r *http.Request) {
	if s.oauth2Provider == nil {
		s.writeError(w, http.StatusInternalServerError, "OAuth2 not configured")
		return
	}

	ctx := r.Context()

	if r.Method == http.MethodGet {
		// Check authentication before showing the form (same as handleOAuth2Authorize)
		username := ""

		// Method 1: User header (demo mode)
		if s.userHeader != "" {
			username = r.Header.Get(s.userHeader)
			if username != "" {
				s.logger.Info(logging.DestinationHTTP, "User authenticated via header",
					"username", username, "header", s.userHeader)
			}
		}

		// Method 2: Check for session
		if username == "" {
			if session, ok := s.getSessionFromRequest(r); ok {
				username = session.Username
				s.logger.Info(logging.DestinationHTTP, "User authenticated via session", "username", username)
			}
		}

		// If no authentication and OAuth2 SSO is configured, redirect to upstream IDP
		if username == "" && s.oauth2Config != nil {
			// Generate state parameter
			state, err := s.oauth2StateStore.GenerateState()
			if err != nil {
				s.logger.Error(logging.DestinationHTTP, "Failed to generate OAuth2 state", "error", err)
				s.writeError(w, http.StatusInternalServerError, "Failed to initiate authentication")
				return
			}

			// Store the return URL (current device verification URL)
			returnURL := r.URL.String()
			s.oauth2StateStore.StoreWithUsername(state, nil, returnURL, "")

			// Build authorization URL
			authURL := s.oauth2Config.AuthCodeURL(state)

			s.logger.Info(logging.DestinationHTTP, "Redirecting to IDP for device verification authentication",
				"state", state, "auth_url", authURL, "return_url", returnURL)

			// Redirect to IDP
			http.Redirect(w, r, authURL, http.StatusFound)
			return
		}

		// If still no username, authentication is required
		if username == "" {
			s.logger.Error(logging.DestinationHTTP, "No authentication method available for device verification")
			s.writeError(w, http.StatusUnauthorized, "Authentication required")
			return
		}

		// Get user code from query parameter
		userCode := r.URL.Query().Get("user_code")

		// If user code is provided, look up the device code session and show consent page
		if userCode != "" {
			userCode = strings.ToUpper(strings.TrimSpace(userCode))

			// Get device code session by user code
			_, request, err := s.oauth2Provider.GetStorage().GetDeviceCodeSessionByUserCode(ctx, userCode)
			if err != nil {
				s.logger.Error(logging.DestinationHTTP, "Failed to get device code session", "error", err, "user_code", userCode)
				s.writeHTMLError(w, "Invalid or expired user code")
				return
			}

			// Show consent page with scopes
			s.renderDeviceConsentPage(w, r, username, userCode, request)
			return
		}

		// Display verification form (for entering user code)
		html := `<!DOCTYPE html>
<html>
<head>
    <title>Device Authorization</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 500px; margin: 50px auto; padding: 20px; }
        h1 { color: #333; }
        form { margin-top: 20px; }
        input[type="text"] { font-size: 18px; padding: 10px; width: 100%; margin: 10px 0; text-transform: uppercase; }
        button { background-color: #4CAF50; color: white; padding: 12px 20px; border: none; cursor: pointer; font-size: 16px; width: 100%; margin: 5px 0; }
        button:hover { opacity: 0.8; }
        .error { color: red; margin: 10px 0; }
        .success { color: green; margin: 10px 0; }
    </style>
</head>
<body>
    <h1>Device Authorization</h1>
    <p>Enter the code displayed on your device:</p>
    <form method="GET" action="/mcp/oauth2/device/verify">
        <input type="text" name="user_code" placeholder="Enter code" required pattern="[A-Z0-9-]+" />
        <button type="submit">Continue</button>
    </form>
</body>
</html>`
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(html))
		return
	}

	if r.Method == http.MethodPost {
		// Handle approval/denial
		userCode := strings.ToUpper(strings.TrimSpace(r.FormValue("user_code")))
		action := r.FormValue("action")

		if userCode == "" {
			s.writeHTMLError(w, "User code is required")
			return
		}

		// Get device code session by user code
		_, request, err := s.oauth2Provider.GetStorage().GetDeviceCodeSessionByUserCode(ctx, userCode)
		if err != nil {
			s.logger.Error(logging.DestinationHTTP, "Failed to get device code session", "error", err, "user_code", userCode)
			s.writeHTMLError(w, "Invalid or expired user code")
			return
		}

		// Determine authentication method (same as handleOAuth2Authorize):
		// 1. If userHeader is configured, use that (for demo/testing mode)
		// 2. If OAuth2 SSO is configured and no userHeader, check for session
		// 3. If neither, authentication is required
		username := ""

		// Method 1: User header (demo mode)
		if s.userHeader != "" {
			username = r.Header.Get(s.userHeader)
			if username != "" {
				s.logger.Info(logging.DestinationHTTP, "User authenticated via header",
					"username", username, "header", s.userHeader)
			}
		}

		// Method 2: Check for session
		if username == "" {
			if session, ok := s.getSessionFromRequest(r); ok {
				username = session.Username
				s.logger.Info(logging.DestinationHTTP, "User authenticated via session", "username", username)
			}
		}

		// If still no username, authentication is required
		if username == "" {
			s.logger.Error(logging.DestinationHTTP, "No authentication method available for device verification")
			s.writeHTMLError(w, "Authentication required")
			return
		}

		switch action {
		case "approve":
			// Create session for user
			session := DefaultOpenIDConnectSession(username)

			// Approve the device code
			if err := s.oauth2Provider.GetStorage().ApproveDeviceCodeSession(ctx, userCode, username, session); err != nil {
				s.logger.Error(logging.DestinationHTTP, "Failed to approve device code", "error", err)
				s.writeHTMLError(w, "Failed to approve device")
				return
			}

			s.logger.Info(logging.DestinationHTTP, "Device code approved", "user_code", userCode, "username", username, "client_id", request.GetClient().GetID())

			// Return success page
			html := `<!DOCTYPE html>
<html>
<head>
    <title>Authorization Complete</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 500px; margin: 50px auto; padding: 20px; text-align: center; }
        h1 { color: #4CAF50; }
        p { font-size: 18px; margin: 20px 0; }
    </style>
</head>
<body>
    <h1>Authorization Complete</h1>
    <p>You have successfully authorized the device.</p>
    <p>You can close this window now.</p>
</body>
</html>`
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(html))
		case "deny":
			// Deny the device code
			if err := s.oauth2Provider.GetStorage().DenyDeviceCodeSession(ctx, userCode); err != nil {
				s.logger.Error(logging.DestinationHTTP, "Failed to deny device code", "error", err)
				s.writeHTMLError(w, "Failed to deny device")
				return
			}

			s.logger.Info(logging.DestinationHTTP, "Device code denied", "user_code", userCode, "username", username)

			// Return denial page
			html := `<!DOCTYPE html>
<html>
<head>
    <title>Authorization Denied</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 500px; margin: 50px auto; padding: 20px; text-align: center; }
        h1 { color: #f44336; }
        p { font-size: 18px; margin: 20px 0; }
    </style>
</head>
<body>
    <h1>✗ Authorization Denied</h1>
    <p>You have denied authorization for this device.</p>
    <p>You can close this window now.</p>
</body>
</html>`
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(html))
		default:
			s.writeHTMLError(w, "Invalid action")
		}
		return
	}

	s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
}

// renderDeviceConsentPage renders the consent page for device code flow
func (s *Server) renderDeviceConsentPage(w http.ResponseWriter, _ *http.Request, username, userCode string, request fosite.Requester) {
	client := request.GetClient()
	requestedScopes := request.GetRequestedScopes()

	// Build scopes list with descriptions
	type scopeInfo struct {
		Name        string
		Description string
	}
	var scopes []scopeInfo
	for _, scope := range requestedScopes {
		scopes = append(scopes, scopeInfo{
			Name:        scope,
			Description: getScopeDescription(scope),
		})
	}

	// Generate HTML for scopes list
	var scopesHTML strings.Builder
	scopesHTML.WriteString("<ul class=\"scopes-list\">\n")
	for _, scope := range scopes {
		scopesHTML.WriteString(fmt.Sprintf("                <li>\n"+
			"                    <strong>%s</strong>\n"+
			"                    <p>%s</p>\n"+
			"                </li>\n", scope.Name, scope.Description))
	}
	scopesHTML.WriteString("            </ul>")

	html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <title>Authorize Device</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        .container {
            background: white;
            border-radius: 12px;
            box-shadow: 0 10px 40px rgba(0, 0, 0, 0.2);
            max-width: 600px;
            width: 100%%;
            padding: 40px;
        }
        h1 {
            color: #333;
            margin-bottom: 10px;
            font-size: 28px;
        }
        .user-info {
            color: #666;
            font-size: 14px;
            margin-bottom: 30px;
            padding: 15px;
            background: #f8f9fa;
            border-radius: 6px;
        }
        .user-info strong {
            color: #333;
        }
        .client-info {
            margin-bottom: 30px;
            padding: 20px;
            background: #f0f4ff;
            border-left: 4px solid #667eea;
            border-radius: 6px;
        }
        .client-info h2 {
            font-size: 16px;
            color: #667eea;
            margin-bottom: 10px;
        }
        .client-info p {
            color: #555;
            font-size: 14px;
            line-height: 1.6;
        }
        .device-code {
            font-size: 24px;
            font-weight: bold;
            color: #667eea;
            font-family: monospace;
            letter-spacing: 2px;
        }
        .permissions {
            margin-bottom: 30px;
        }
        .permissions h2 {
            font-size: 18px;
            color: #333;
            margin-bottom: 15px;
        }
        .scopes-list {
            list-style: none;
            border: 1px solid #e0e0e0;
            border-radius: 8px;
            overflow: hidden;
        }
        .scopes-list li {
            padding: 16px 20px;
            border-bottom: 1px solid #e0e0e0;
        }
        .scopes-list li:last-child {
            border-bottom: none;
        }
        .scopes-list li strong {
            display: block;
            color: #667eea;
            font-size: 14px;
            margin-bottom: 4px;
            font-weight: 600;
        }
        .scopes-list li p {
            color: #666;
            font-size: 13px;
            line-height: 1.5;
            margin: 0;
        }
        .actions {
            display: flex;
            gap: 15px;
            margin-top: 30px;
        }
        .actions button {
            flex: 1;
            padding: 14px 28px;
            border: none;
            border-radius: 6px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s ease;
        }
        .btn-approve {
            background: #667eea;
            color: white;
        }
        .btn-approve:hover {
            background: #5568d3;
            transform: translateY(-1px);
            box-shadow: 0 4px 12px rgba(102, 126, 234, 0.4);
        }
        .btn-deny {
            background: #f0f0f0;
            color: #666;
        }
        .btn-deny:hover {
            background: #e0e0e0;
        }
        @media (max-width: 600px) {
            .container {
                padding: 30px 20px;
            }
            h1 {
                font-size: 24px;
            }
            .actions {
                flex-direction: column-reverse;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Authorize Device</h1>
        <div class="user-info">
            Logged in as: <strong>%s</strong>
        </div>
        <div class="client-info">
            <h2>Device Code</h2>
            <p class="device-code">%s</p>
            <p style="margin-top: 10px; font-size: 12px;">Verify this code matches the one shown on your device.</p>
        </div>
        <div class="client-info">
            <h2>Application</h2>
            <p><strong>%s</strong> wants to access your account on your device.</p>
        </div>
        <div class="permissions">
            <h2>This application will be able to:</h2>
            %s
        </div>
        <form method="POST" action="/mcp/oauth2/device/verify">
            <input type="hidden" name="user_code" value="%s">
            <div class="actions">
                <button type="submit" name="action" value="deny" class="btn-deny">Deny</button>
                <button type="submit" name="action" value="approve" class="btn-approve">Approve</button>
            </div>
        </form>
    </div>
</body>
</html>`, username, userCode, client.GetID(), scopesHTML.String(), userCode)

	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(html))
}

// writeHTMLError writes an HTML error page
func (s *Server) writeHTMLError(w http.ResponseWriter, message string) {
	html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <title>Error</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 500px; margin: 50px auto; padding: 20px; }
        .error { color: red; font-size: 18px; }
    </style>
</head>
<body>
    <h1>Error</h1>
    <p class="error">%s</p>
    <a href="/mcp/oauth2/device/verify">Try again</a>
</body>
</html>`, message)
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusBadRequest)
	_, _ = w.Write([]byte(html))
}

// isMethodAllowedByScopes checks if an MCP method is allowed based on OAuth2 scopes
func (s *Server) isMethodAllowedByScopes(token fosite.AccessRequester, mcpRequest *mcpserver.MCPMessage) bool {
	scopes := token.GetGrantedScopes()

	// Check if user has mcp:write or mcp:read scopes
	hasRead := false
	hasWrite := false
	for _, scope := range scopes {
		if scope == "mcp:read" {
			hasRead = true
		}
		if scope == "mcp:write" {
			hasWrite = true
		}
	}

	// Determine if the method requires write access
	requiresWrite := s.methodRequiresWrite(mcpRequest)

	// Allow if user has write access, or has read access and method doesn't require write
	if hasWrite {
		return true
	}
	if hasRead && !requiresWrite {
		return true
	}

	return false
}

// methodRequiresWrite determines if an MCP method requires write access
func (s *Server) methodRequiresWrite(mcpRequest *mcpserver.MCPMessage) bool {
	// Read-only methods
	readOnlyMethods := map[string]bool{
		"initialize":     true,
		"tools/list":     true,
		"resources/list": true,
		"resources/read": true,
	}

	// Check if method itself is read-only
	if readOnlyMethods[mcpRequest.Method] {
		return false
	}

	// For tools/call, check the tool name
	if mcpRequest.Method == "tools/call" {
		var params struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(mcpRequest.Params, &params); err == nil {
			// Read-only tools
			readOnlyTools := map[string]bool{
				"query_jobs": true,
				"get_job":    true,
			}
			if readOnlyTools[params.Name] {
				return false
			}
		}
	}

	// All other methods/tools require write access
	return true
}

// hasCondorScopes checks if any condor:/* scopes are present in the list
func hasCondorScopes(scopes []string) bool {
	for _, scope := range scopes {
		if strings.HasPrefix(scope, "condor:/") {
			return true
		}
	}
	return false
}

// mapCondorScopesToAuthz maps condor:/* scopes to HTCondor authorization levels
// Returns the authorization limits for the token
// Maps 1-to-1 from condor:/FOO to FOO
func mapCondorScopesToAuthz(scopes []string) []string {
	authzMap := make(map[string]bool)

	for _, scope := range scopes {
		if !strings.HasPrefix(scope, "condor:/") {
			continue
		}

		// Extract the authorization level from condor:/LEVEL
		authLevel := strings.TrimPrefix(scope, "condor:/")
		authLevel = strings.ToUpper(authLevel)

		// Map scope 1-to-1 to HTCondor authorization levels
		// Supported: READ, WRITE, ADVERTISE_STARTD, ADVERTISE_SCHEDD, ADVERTISE_MASTER
		switch authLevel {
		case "READ", "WRITE", "ADVERTISE_STARTD", "ADVERTISE_SCHEDD", "ADVERTISE_MASTER":
			authzMap[authLevel] = true
		default:
			// Unknown authorization level, ignore
			continue
		}
	}

	// Convert map to slice
	var authz []string
	for auth := range authzMap {
		authz = append(authz, auth)
	}

	return authz
}

// generateHTCondorTokenWithScopes generates an HTCondor token with scope-based permissions
func (s *Server) generateHTCondorTokenWithScopes(username string, scopes []string) (string, error) {
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

	// Check if condor:/* scopes are present
	var authz []string
	if hasCondorScopes(scopes) {
		// Map condor:/* scopes to HTCondor authorization levels
		authz = mapCondorScopesToAuthz(scopes)
	} else {
		// Map MCP scopes to HTCondor authorization levels (legacy behavior)
		hasWrite := false
		for _, scope := range scopes {
			if scope == "mcp:write" {
				hasWrite = true
				break
			}
		}

		if hasWrite {
			// Full access for write scope
			authz = []string{"WRITE", "READ", "ADVERTISE_STARTD", "ADVERTISE_SCHEDD", "ADVERTISE_MASTER"}
		} else {
			// Read-only access for read scope
			authz = []string{"READ"}
		}
	}

	s.logger.Info(logging.DestinationHTTP, "Generating HTCondor token",
		"username", username,
		"trust_domain", s.trustDomain,
		"iat", iat,
		"exp", exp,
		"authz", authz,
		"scopes", scopes,
		"signing_key_path", s.signingKeyPath,
	)
	token, err := security.GenerateJWT(
		filepath.Dir(s.signingKeyPath),
		filepath.Base(s.signingKeyPath),
		username,
		s.trustDomain,
		iat,
		exp,
		authz,
	)
	if err != nil {
		return "", fmt.Errorf("failed to generate JWT: %w", err)
	}

	return token, nil
}
