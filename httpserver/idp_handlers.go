package httpserver

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strings"

	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/ory/fosite"
)

// handleIDPLogin handles the IDP login page
func (s *Server) handleIDPLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		// Display login form
		s.serveIDPLoginForm(w, r)
		return
	}

	if r.Method == http.MethodPost {
		// Handle login submission
		s.handleIDPLoginSubmit(w, r)
		return
	}

	s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
}

// serveIDPLoginForm serves the login form HTML
func (s *Server) serveIDPLoginForm(w http.ResponseWriter, r *http.Request) {
	// Get redirect_uri from query params to pass through
	redirectURI := r.URL.Query().Get("redirect_uri")

	html := `<!DOCTYPE html>
<html>
<head>
    <title>HTCondor IDP Login</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f0f0f0;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
        }
        .login-container {
            background-color: white;
            padding: 2rem;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            width: 300px;
        }
        h2 {
            margin-top: 0;
            color: #333;
        }
        .form-group {
            margin-bottom: 1rem;
        }
        label {
            display: block;
            margin-bottom: 0.5rem;
            color: #555;
        }
        input[type="text"],
        input[type="password"] {
            width: 100%;
            padding: 0.5rem;
            border: 1px solid #ddd;
            border-radius: 4px;
            box-sizing: border-box;
        }
        button {
            width: 100%;
            padding: 0.75rem;
            background-color: #007bff;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 1rem;
        }
        button:hover {
            background-color: #0056b3;
        }
        .error {
            color: #d9534f;
            margin-bottom: 1rem;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <h2>HTCondor IDP Login</h2>
        <form method="POST" action="/idp/login">
            <input type="hidden" name="redirect_uri" value="` + redirectURI + `">
            <div class="form-group">
                <label for="username">Username:</label>
                <input type="text" id="username" name="username" required autofocus>
            </div>
            <div class="form-group">
                <label for="password">Password:</label>
                <input type="password" id="password" name="password" required>
            </div>
            <button type="submit">Login</button>
        </form>
    </div>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(html))
}

// handleIDPLoginSubmit handles login form submission
func (s *Server) handleIDPLoginSubmit(w http.ResponseWriter, r *http.Request) {
	// Rate limit login attempts by IP address
	ip := r.RemoteAddr
	if !s.idpLoginLimiter.Allow(ip) {
		s.logger.Warn(logging.DestinationHTTP, "IDP login rate limit exceeded", "ip", ip)
		s.writeError(w, http.StatusTooManyRequests, "Too many login attempts. Please try again later.")
		return
	}

	if err := r.ParseForm(); err != nil {
		s.writeError(w, http.StatusBadRequest, "Failed to parse form")
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")
	redirectURI := r.FormValue("redirect_uri")

	if username == "" || password == "" {
		s.writeError(w, http.StatusBadRequest, "Username and password required")
		return
	}

	// Authenticate user
	ctx := r.Context()
	if err := s.idpProvider.storage.AuthenticateUser(ctx, username, password); err != nil {
		s.logger.Warn(logging.DestinationHTTP, "IDP authentication failed", "username", username)
		s.writeError(w, http.StatusUnauthorized, "Invalid credentials")
		return
	}

	s.logger.Info(logging.DestinationHTTP, "IDP user authenticated", "username", username)

	// Create session for authenticated user
	// Store username in cookie or session store (using simple cookie for now)
	http.SetCookie(w, &http.Cookie{
		Name:     "idp_session",
		Value:    username,
		Path:     "/",
		HttpOnly: true,
		Secure:   true, // Always set to true - server should use HTTPS
		SameSite: http.SameSiteLaxMode,
		MaxAge:   3600, // 1 hour
	})

	// Redirect back to authorization endpoint or provided redirect_uri
	if redirectURI != "" {
		http.Redirect(w, r, redirectURI, http.StatusFound)
		return
	}

	// Default redirect to success page
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`<!DOCTYPE html>
<html>
<head><title>Login Successful</title></head>
<body>
    <h2>Login Successful</h2>
    <p>You are now logged in as ` + username + `</p>
</body>
</html>`))
}

// handleIDPAuthorize handles OAuth2 authorization requests for IDP
func (s *Server) handleIDPAuthorize(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Check if user is authenticated via session cookie
	cookie, err := r.Cookie("idp_session")
	if err != nil || cookie.Value == "" {
		// User not authenticated, redirect to login with return URL
		loginURL := "/idp/login?redirect_uri=" + url.QueryEscape(r.URL.String())
		http.Redirect(w, r, loginURL, http.StatusFound)
		return
	}

	username := cookie.Value

	// Create a new authorization request
	ar, err := s.idpProvider.oauth2.NewAuthorizeRequest(ctx, r)
	if err != nil {
		s.logger.Error(logging.DestinationHTTP, "Failed to create authorize request", "error", err)
		s.idpProvider.oauth2.WriteAuthorizeError(ctx, w, ar, err)
		return
	}

	// Create session for the user
	session := DefaultIDPSession(username)

	// Only grant standard OIDC scopes (openid, profile, email, offline_access)
	// Don't blindly approve all client-requested scopes
	allowedScopes := map[string]bool{
		"openid":         true,
		"profile":        true,
		"email":          true,
		"offline_access": true,
	}
	for _, scope := range ar.GetRequestedScopes() {
		if allowedScopes[scope] {
			ar.GrantScope(scope)
		}
	}

	// Create the authorization response
	response, err := s.idpProvider.oauth2.NewAuthorizeResponse(ctx, ar, session)
	if err != nil {
		s.logger.Error(logging.DestinationHTTP, "Failed to create authorize response", "error", err)
		s.idpProvider.oauth2.WriteAuthorizeError(ctx, w, ar, err)
		return
	}

	// Write the response (redirects to client)
	s.idpProvider.oauth2.WriteAuthorizeResponse(ctx, w, ar, response)
}

// handleIDPToken handles OAuth2 token requests for IDP
func (s *Server) handleIDPToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Create a new session
	session := DefaultIDPSession("")

	// Create access request
	ar, err := s.idpProvider.oauth2.NewAccessRequest(ctx, r, session)
	if err != nil {
		s.logger.Error(logging.DestinationHTTP, "Failed to create access request", "error", err)
		s.idpProvider.oauth2.WriteAccessError(ctx, w, ar, err)
		return
	}

	// If this is a refresh token grant, we already have the session
	// If this is an authorization code grant, session is populated from the stored auth code

	// Create the access response
	response, err := s.idpProvider.oauth2.NewAccessResponse(ctx, ar)
	if err != nil {
		s.logger.Error(logging.DestinationHTTP, "Failed to create access response", "error", err)
		s.idpProvider.oauth2.WriteAccessError(ctx, w, ar, err)
		return
	}

	// Write the response
	s.idpProvider.oauth2.WriteAccessResponse(ctx, w, ar, response)
}

// handleIDPMetadata handles OIDC discovery metadata for IDP
func (s *Server) handleIDPMetadata(w http.ResponseWriter, _ *http.Request) {
	// Get the issuer URL from the IDP provider config
	issuer := s.idpProvider.config.AccessTokenIssuer

	metadata := map[string]interface{}{
		"issuer":                 issuer,
		"authorization_endpoint": issuer + "/idp/authorize",
		"token_endpoint":         issuer + "/idp/token",
		"userinfo_endpoint":      issuer + "/idp/userinfo",
		"jwks_uri":               issuer + "/idp/.well-known/jwks.json",
		"scopes_supported": []string{
			"openid",
			"profile",
			"email",
		},
		"response_types_supported": []string{
			"code",
			"token",
			"id_token",
			"code token",
			"code id_token",
			"token id_token",
			"code token id_token",
		},
		"response_modes_supported": []string{
			"query",
			"fragment",
		},
		"grant_types_supported": []string{
			"authorization_code",
			"refresh_token",
		},
		"subject_types_supported": []string{
			"public",
		},
		"id_token_signing_alg_values_supported": []string{
			"RS256",
		},
		"token_endpoint_auth_methods_supported": []string{
			"client_secret_basic",
			"client_secret_post",
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(metadata); err != nil {
		s.logger.Error(logging.DestinationHTTP, "Failed to encode IDP metadata", "error", err)
	}
}

// handleIDPUserInfo handles userinfo endpoint for IDP
func (s *Server) handleIDPUserInfo(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Extract access token from Authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		s.writeError(w, http.StatusUnauthorized, "Missing authorization header")
		return
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		s.writeError(w, http.StatusUnauthorized, "Invalid authorization header")
		return
	}

	token := parts[1]

	// Validate the access token
	tokenType, ar, err := s.idpProvider.oauth2.IntrospectToken(ctx, token, fosite.AccessToken, DefaultIDPSession(""))
	if err != nil {
		s.logger.Error(logging.DestinationHTTP, "Token introspection failed", "error", err)
		s.writeError(w, http.StatusUnauthorized, "Invalid token")
		return
	}

	if tokenType != fosite.AccessToken {
		s.writeError(w, http.StatusUnauthorized, "Invalid token type")
		return
	}

	// Get user information from the session
	username := ar.GetSession().GetSubject()

	userInfo := map[string]interface{}{
		"sub":  username,
		"name": username,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(userInfo); err != nil {
		s.logger.Error(logging.DestinationHTTP, "Failed to encode userinfo", "error", err)
	}
}

// handleIDPJWKS handles JWKS endpoint for IDP
func (s *Server) handleIDPJWKS(w http.ResponseWriter, _ *http.Request) {
	// Extract public key from the RSA private key
	publicKey := &s.idpProvider.privateKey.PublicKey

	// Convert to JWK format (JSON Web Key)
	// We use "idp-key-1" as the key ID
	jwk := map[string]interface{}{
		"kty": "RSA",
		"use": "sig",
		"alg": "RS256",
		"kid": "idp-key-1",
		"n":   base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(publicKey.E)).Bytes()),
	}

	jwks := map[string]interface{}{
		"keys": []interface{}{jwk},
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(jwks); err != nil {
		s.logger.Error(logging.DestinationHTTP, "Failed to encode JWKS", "error", err)
	}
}

// generateRandomPassword generates a random password for the admin user
func generateRandomPassword(length int) (string, error) {
	// Generate enough random bytes to ensure we have at least 'length' valid base64 characters
	// Base64 encoding produces 4 characters for every 3 bytes, so we need at least (length * 3) / 4 bytes
	numBytes := ((length * 3) + 3) / 4 // Round up
	bytes := make([]byte, numBytes)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	// Encode to URL-safe base64 and take the first 'length' characters
	encoded := base64.URLEncoding.EncodeToString(bytes)
	if len(encoded) < length {
		return encoded, nil
	}
	return encoded[:length], nil
}

// initializeIDPUsers initializes default users if needed
func (s *Server) initializeIDPUsers(ctx context.Context) error {
	// Check if admin user exists
	exists, err := s.idpProvider.storage.UserExists(ctx, "admin")
	if err != nil {
		return fmt.Errorf("failed to check if admin user exists: %w", err)
	}

	if !exists {
		// Generate random password
		password, err := generateRandomPassword(16)
		if err != nil {
			return fmt.Errorf("failed to generate admin password: %w", err)
		}

		// Create admin user with "admin" state
		if err := s.idpProvider.storage.CreateUser(ctx, "admin", password, "admin"); err != nil {
			return fmt.Errorf("failed to create admin user: %w", err)
		}

		// Print credentials to terminal
		fmt.Printf("\n")
		fmt.Printf("========================================\n")
		fmt.Printf("IDP Admin Credentials\n")
		fmt.Printf("========================================\n")
		fmt.Printf("Username: admin\n")
		fmt.Printf("Password: %s\n", password)
		fmt.Printf("========================================\n")
		fmt.Printf("\n")

		s.logger.Info(logging.DestinationHTTP, "Created IDP admin user", "username", "admin")
	}

	return nil
}

// initializeIDPClient creates an auto-generated OAuth2 client for the server
func (s *Server) initializeIDPClient(ctx context.Context, redirectURI string) error {
	clientID := "htcondor-server"

	// Check if client already exists
	_, err := s.idpProvider.storage.GetClient(ctx, clientID)
	if err == nil {
		// Client already exists, update redirect URI if needed
		// For simplicity, we'll just return
		s.logger.Info(logging.DestinationHTTP, "IDP client already exists", "client_id", clientID)
		return nil
	}

	if !errors.Is(err, fosite.ErrNotFound) {
		return fmt.Errorf("failed to check for existing client: %w", err)
	}

	// Generate client secret
	secret, err := generateRandomPassword(32)
	if err != nil {
		return fmt.Errorf("failed to generate client secret: %w", err)
	}

	// Create the client
	client := &fosite.DefaultClient{
		ID:     clientID,
		Secret: []byte(secret),
		RedirectURIs: []string{
			redirectURI,
		},
		GrantTypes: []string{
			"authorization_code",
			"refresh_token",
		},
		ResponseTypes: []string{
			"code",
		},
		Scopes: []string{
			"openid",
			"profile",
			"email",
		},
		Public: false,
	}

	if err := s.idpProvider.storage.CreateClient(ctx, client); err != nil {
		return fmt.Errorf("failed to create IDP client: %w", err)
	}

	s.logger.Info(logging.DestinationHTTP, "Created IDP client", "client_id", clientID, "redirect_uri", redirectURI)

	return nil
}
