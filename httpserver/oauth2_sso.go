package httpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/ory/fosite"
	"golang.org/x/oauth2"

	"github.com/bbockelm/golang-htcondor/logging"
)

// UserInfo represents user information from the IDP
type UserInfo struct {
	Subject string                 `json:"sub"`
	Email   string                 `json:"email"`
	Name    string                 `json:"name"`
	Groups  interface{}            `json:"groups"` // Can be []string or string
	Claims  map[string]interface{} // Additional claims
}

// extractGroups extracts group names from the groups claim
// Groups can be:
// - []string: List of group names
// - string: Space-delimited list of group names
// - nil: No groups
func extractGroups(groupsClaim interface{}) []string {
	if groupsClaim == nil {
		return nil
	}

	switch v := groupsClaim.(type) {
	case []interface{}:
		groups := make([]string, 0, len(v))
		for _, item := range v {
			if str, ok := item.(string); ok {
				groups = append(groups, str)
			}
		}
		return groups
	case []string:
		return v
	case string:
		// Space-delimited
		if v == "" {
			return nil
		}
		return strings.Fields(v)
	default:
		return nil
	}
}

// hasGroup checks if the user has the specified group (case-insensitive)
func hasGroup(userGroups []string, requiredGroup string) bool {
	if requiredGroup == "" {
		return true // No group specified
	}
	requiredLower := strings.ToLower(requiredGroup)
	for _, group := range userGroups {
		if strings.ToLower(group) == requiredLower {
			return true
		}
	}
	return false
}

// validateGroupAccess checks if the user has access based on group membership
// Returns error if access is denied
func (s *Server) validateGroupAccess(userGroups []string) error {
	// If access group is configured, user must be in it
	if s.mcpAccessGroup != "" && !hasGroup(userGroups, s.mcpAccessGroup) {
		return fmt.Errorf("user not in required access group: %s", s.mcpAccessGroup)
	}
	return nil
}

// getScopesForGroups determines OAuth2 scopes based on group membership
func (s *Server) getScopesForGroups(userGroups []string, requestedScopes []string) []string {
	grantedScopes := []string{"openid"} // Always grant openid

	// Check each requested scope
	for _, scope := range requestedScopes {
		switch scope {
		case "openid":
			// Already added
			continue
		case "mcp:read":
			// Grant only if read group is configured AND user is in it
			if s.mcpReadGroup != "" && hasGroup(userGroups, s.mcpReadGroup) {
				grantedScopes = append(grantedScopes, scope)
			}
		case "mcp:write":
			// Grant only if write group is configured AND user is in it
			if s.mcpWriteGroup != "" && hasGroup(userGroups, s.mcpWriteGroup) {
				grantedScopes = append(grantedScopes, scope)
			}
		default:
			// Grant other scopes if requested (profile, email, etc.)
			grantedScopes = append(grantedScopes, scope)
		}
	}

	return grantedScopes
}

// fetchUserInfo fetches user information from the IDP user info endpoint
func (s *Server) fetchUserInfo(ctx context.Context, accessToken string) (*UserInfo, error) {
	if s.oauth2UserInfoURL == "" {
		return nil, fmt.Errorf("user info URL not configured")
	}

	req, err := http.NewRequestWithContext(ctx, "GET", s.oauth2UserInfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create user info request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	// Use custom HTTP client if configured
	client := s.getHTTPClient()
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch user info: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("user info request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var claims map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&claims); err != nil {
		return nil, fmt.Errorf("failed to decode user info: %w", err)
	}

	userInfo := &UserInfo{
		Claims: claims,
	}

	s.logger.Info(logging.DestinationHTTP, "Fetched user info from IDP", "claims", claims)

	// Extract standard claims
	if sub, ok := claims[s.oauth2UsernameClaim].(string); ok {
		userInfo.Subject = sub
	}
	if email, ok := claims["email"].(string); ok {
		userInfo.Email = email
	}
	if name, ok := claims["name"].(string); ok {
		userInfo.Name = name
	}

	// Extract groups from configured claim
	if groupsClaim, ok := claims[s.oauth2GroupsClaim]; ok {
		userInfo.Groups = groupsClaim
	}

	return userInfo, nil
}

// handleOAuth2Callback handles the OAuth2 callback from the IDP
func (s *Server) handleOAuth2Callback(w http.ResponseWriter, r *http.Request) {
	if s.oauth2Provider == nil || s.oauth2Config == nil {
		s.writeError(w, http.StatusInternalServerError, "OAuth2 not configured")
		return
	}

	ctx := r.Context()

	// Extract state and code from query parameters
	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")
	errorParam := r.URL.Query().Get("error")

	if errorParam != "" {
		errorDesc := r.URL.Query().Get("error_description")
		s.logger.Error(logging.DestinationHTTP, "OAuth2 callback error from IDP",
			"error", errorParam, "error_description", errorDesc)
		s.writeError(w, http.StatusUnauthorized, fmt.Sprintf("Authentication failed: %s", errorDesc))
		return
	}

	if state == "" || code == "" {
		s.writeError(w, http.StatusBadRequest, "Missing state or code parameter")
		return
	}

	// Retrieve the stored authorize request and original URL
	ar, originalURL, ok := s.oauth2StateStore.GetWithURL(state)
	if !ok {
		s.logger.Error(logging.DestinationHTTP, "Invalid or expired OAuth2 state", "state", state)
		s.writeError(w, http.StatusBadRequest, "Invalid or expired state parameter")
		return
	}

	// Check if this is a browser-initiated flow (no authorize request)
	isBrowserFlow := (ar == nil)

	if !isBrowserFlow {
		s.logger.Info(logging.DestinationHTTP, "Processing OAuth2 callback", "state", state, "client_id", ar.GetClient().GetID())
	} else {
		s.logger.Info(logging.DestinationHTTP, "Processing OAuth2 callback for browser flow", "state", state, "original_url", originalURL)
	}

	// Exchange authorization code for token
	// Use custom HTTP client if configured (e.g. for self-signed certs)
	client := s.getHTTPClient()
	ctx = context.WithValue(ctx, oauth2.HTTPClient, client)

	token, err := s.oauth2Config.Exchange(ctx, code)
	if err != nil {
		s.logger.Error(logging.DestinationHTTP, "Failed to exchange code for token", "error", err)
		s.writeError(w, http.StatusUnauthorized, "Failed to exchange authorization code")
		return
	}

	// Fetch user info from IDP
	// Use the same client for user info fetch
	userInfo, err := s.fetchUserInfo(ctx, token.AccessToken)
	if err != nil {
		s.logger.Error(logging.DestinationHTTP, "Failed to fetch user info", "error", err)
		s.writeError(w, http.StatusUnauthorized, "Failed to fetch user information")
		return
	}

	if userInfo.Subject == "" {
		s.logger.Error(logging.DestinationHTTP, "User info missing subject claim")
		s.writeError(w, http.StatusUnauthorized, "Invalid user information")
		return
	}

	// Extract groups
	userGroups := extractGroups(userInfo.Groups)
	s.logger.Info(logging.DestinationHTTP, "User authenticated via SSO",
		"subject", userInfo.Subject, "groups", userGroups)

	// Validate group-based access
	if err := s.validateGroupAccess(userGroups); err != nil {
		s.logger.Warn(logging.DestinationHTTP, "User denied access", "subject", userInfo.Subject, "error", err)

		// For browser flow, show an error page instead of OAuth2 error
		if isBrowserFlow {
			s.writeError(w, http.StatusForbidden, fmt.Sprintf("Access denied: %v", err))
			return
		}

		// Create RFC6749 error to redirect back to client
		accessDeniedErr := fosite.ErrAccessDenied.WithDescription(err.Error()).WithHintf("User does not have required group membership")
		s.oauth2Provider.GetProvider().WriteAuthorizeError(ctx, w, ar, accessDeniedErr)
		return
	}

	// For browser flow, create session and redirect back to original URL
	if isBrowserFlow {
		// Create HTTP session cookie for browser-based authentication
		sessionID, sessionData, err := s.sessionStore.Create(userInfo.Subject)
		if err != nil {
			s.logger.Error(logging.DestinationHTTP, "Failed to create HTTP session",
				"error", err, "subject", userInfo.Subject)
			s.writeError(w, http.StatusInternalServerError, "Failed to create session")
			return
		}
		s.setSessionCookie(w, sessionID, sessionData.ExpiresAt)
		s.logger.Info(logging.DestinationHTTP, "Created HTTP session cookie for browser flow",
			"subject", userInfo.Subject, "session_id", sessionID[:8]+"...",
			"expires_at", sessionData.ExpiresAt)

		// Redirect back to original URL or default to root
		redirectURL := originalURL
		if redirectURL == "" {
			redirectURL = "/"
		}
		s.logger.Info(logging.DestinationHTTP, "Browser authentication successful, redirecting",
			"subject", userInfo.Subject, "redirect_url", redirectURL)
		http.Redirect(w, r, redirectURL, http.StatusFound)
		return
	}

	// Determine granted scopes based on group membership
	requestedScopes := ar.GetRequestedScopes()
	grantedScopes := s.getScopesForGroups(userGroups, requestedScopes)

	s.logger.Info(logging.DestinationHTTP, "Granting scopes based on group membership",
		"subject", userInfo.Subject,
		"requested_scopes", requestedScopes,
		"granted_scopes", grantedScopes)

	// Grant scopes
	for _, scope := range grantedScopes {
		ar.GrantScope(scope)
	}

	// Create session with the authenticated user
	session := DefaultOpenIDConnectSession(userInfo.Subject)

	// Generate OAuth2 response
	response, err := s.oauth2Provider.GetProvider().NewAuthorizeResponse(ctx, ar, session)
	if err != nil {
		// Extract more detailed error information
		errorDetails := fmt.Sprintf("%v", err)
		var rfc6749Err *fosite.RFC6749Error
		if errors.As(err, &rfc6749Err) {
			errorDetails = fmt.Sprintf("RFC6749Error: name=%s, description=%s, hint=%s, debug=%s",
				rfc6749Err.ErrorField, rfc6749Err.DescriptionField, rfc6749Err.HintField, rfc6749Err.DebugField)
		}

		s.logger.Error(logging.DestinationHTTP, "Failed to create authorize response",
			"error", err, "error_details", errorDetails,
			"subject", userInfo.Subject, "client_id", ar.GetClient().GetID())
		s.oauth2Provider.GetProvider().WriteAuthorizeError(ctx, w, ar, err)
		return
	}

	s.logger.Info(logging.DestinationHTTP, "OAuth2 callback completed successfully",
		"subject", userInfo.Subject, "granted_scopes", grantedScopes)

	// OAuth2 client flow - write the standard OAuth2 response
	s.oauth2Provider.GetProvider().WriteAuthorizeResponse(ctx, w, ar, response)
}

// handleLogin initiates the OAuth2 login flow
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	// Check if already authenticated
	if _, ok := s.getSessionFromRequest(r); ok {
		// Already authenticated, redirect to return_to or root
		returnURL := r.URL.Query().Get("return_to")
		if returnURL == "" {
			returnURL = "/"
		}
		http.Redirect(w, r, returnURL, http.StatusFound)
		return
	}

	s.redirectToLogin(w, r)
}
