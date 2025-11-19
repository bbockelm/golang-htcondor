// Package main provides token management functionality for the htcondor-api client
package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// TokenInfo stores OAuth2 token information for a trust domain
type TokenInfo struct {
	TrustDomain  string    `json:"trust_domain"`
	ClientID     string    `json:"client_id"`
	ClientSecret string    `json:"client_secret"`
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	TokenType    string    `json:"token_type"`
	ExpiresAt    time.Time `json:"expires_at"`
	Scopes       []string  `json:"scopes"`
	IssuerURL    string    `json:"issuer_url"`
}

// TokenInfoStore manages multiple token infos keyed by trust domain
type TokenInfoStore struct {
	Tokens map[string]*TokenInfo `json:"tokens"`
}

// TokenFetchConfig holds configuration for fetching tokens
type TokenFetchConfig struct {
	IssuerURL    string
	TrustDomain  string
	Scopes       []string
	ClientID     string
	ClientSecret string
}

// runTokenFetch implements the "token fetch" subcommand
func runTokenFetch(args []string) error {
	// Parse flags for token fetch
	if len(args) < 1 {
		return fmt.Errorf("usage: htcondor-api token fetch <issuer-url> [--trust-domain DOMAIN] [--scopes SCOPES]")
	}

	issuerURL := args[0]
	trustDomain := ""
	scopes := []string{"openid", "mcp:read", "mcp:write", "condor:/READ", "condor:/WRITE"}

	// Simple flag parsing
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--trust-domain":
			if i+1 < len(args) {
				trustDomain = args[i+1]
				i++
			}
		case "--scopes":
			if i+1 < len(args) {
				scopes = strings.Split(args[i+1], ",")
				i++
			}
		}
	}

	// Default trust domain from issuer URL
	if trustDomain == "" {
		u, err := url.Parse(issuerURL)
		if err != nil {
			return fmt.Errorf("invalid issuer URL: %w", err)
		}
		trustDomain = u.Host
	}

	config := &TokenFetchConfig{
		IssuerURL:   issuerURL,
		TrustDomain: trustDomain,
		Scopes:      scopes,
	}

	// Load existing token info
	tokenInfoPath := getTokenInfoPath()
	store, err := loadTokenInfoStore(tokenInfoPath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to load token info: %w", err)
	}
	if store == nil {
		store = &TokenInfoStore{Tokens: make(map[string]*TokenInfo)}
	}

	// Check if we have an existing valid token in tokens.d
	existingToken, err := checkExistingToken(trustDomain)
	if err == nil && existingToken != "" {
		fmt.Println("Found existing valid token in tokens.d")
		fmt.Printf("Token is valid for at least 5 more minutes\n")
		fmt.Printf("Token location: %s\n", getAccessTokenPath(trustDomain))
		return nil
	}

	// Check if we have a valid token for this trust domain
	tokenInfo, exists := store.Tokens[trustDomain]
	if exists && tokenInfo.RefreshToken != "" {
		// Try to refresh the token
		fmt.Println("Found existing refresh token, attempting to refresh...")
		newTokenInfo, err := refreshToken(tokenInfo, config)
		if err == nil {
			fmt.Println("Successfully refreshed access token!")
			store.Tokens[trustDomain] = newTokenInfo
			if err := saveTokenInfoStore(store, tokenInfoPath); err != nil {
				return fmt.Errorf("failed to save token info: %w", err)
			}
			if err := saveAccessToken(newTokenInfo); err != nil {
				return fmt.Errorf("failed to save access token: %w", err)
			}
			fmt.Printf("Access token saved to: %s\n", getAccessTokenPath(trustDomain))
			return nil
		}
		fmt.Printf("Refresh failed: %v, falling back to device code flow\n", err)
	}

	// No valid refresh token, use device code flow
	fmt.Println("Initiating device code flow...")

	// Register client if needed
	if !exists || tokenInfo.ClientID == "" {
		fmt.Println("Registering new OAuth2 client...")
		clientID, clientSecret, err := registerClient(config)
		if err != nil {
			return fmt.Errorf("failed to register client: %w", err)
		}
		config.ClientID = clientID
		config.ClientSecret = clientSecret
		fmt.Printf("Client registered: %s\n", clientID)
	} else {
		config.ClientID = tokenInfo.ClientID
		config.ClientSecret = tokenInfo.ClientSecret
	}

	// Perform device code flow
	newTokenInfo, err := performDeviceCodeFlow(config)
	if err != nil {
		return fmt.Errorf("device code flow failed: %w", err)
	}

	// Save token info
	store.Tokens[trustDomain] = newTokenInfo
	if err := saveTokenInfoStore(store, tokenInfoPath); err != nil {
		return fmt.Errorf("failed to save token info: %w", err)
	}

	// Save access token to tokens.d
	if err := saveAccessToken(newTokenInfo); err != nil {
		return fmt.Errorf("failed to save access token: %w", err)
	}

	fmt.Println("Successfully obtained tokens!")
	fmt.Printf("Token info saved to: %s\n", tokenInfoPath)
	fmt.Printf("Access token saved to: %s\n", getAccessTokenPath(trustDomain))

	return nil
}

// registerClient registers a new OAuth2 client with the server
func registerClient(config *TokenFetchConfig) (string, string, error) {
	registerURL := config.IssuerURL + "/mcp/oauth2/register"

	reqBody := map[string]interface{}{
		"client_name": "HTCondor API CLI",
		"grant_types": []string{"urn:ietf:params:oauth:grant-type:device_code", "refresh_token"},
		"scope":       config.Scopes,
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return "", "", err
	}

	ctx := context.Background()
	req, err := http.NewRequestWithContext(ctx, "POST", registerURL, bytes.NewBuffer(bodyBytes))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to close response body: %v\n", err)
		}
	}()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return "", "", fmt.Errorf("registration failed: %s (status: %d)", string(body), resp.StatusCode)
	}

	var result struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", "", err
	}

	return result.ClientID, result.ClientSecret, nil
}

// performDeviceCodeFlow executes the OAuth2 device code flow
func performDeviceCodeFlow(config *TokenFetchConfig) (*TokenInfo, error) {
	// Step 1: Request device code
	deviceAuthURL := config.IssuerURL + "/mcp/oauth2/device/authorize"

	data := url.Values{}
	data.Set("client_id", config.ClientID)
	data.Set("scope", strings.Join(config.Scopes, " "))

	ctx := context.Background()
	req, err := http.NewRequestWithContext(ctx, "POST", deviceAuthURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to close response body: %v\n", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("device authorization failed: %s", string(body))
	}

	var deviceResp struct {
		DeviceCode              string `json:"device_code"`
		UserCode                string `json:"user_code"`
		VerificationURI         string `json:"verification_uri"`
		VerificationURIComplete string `json:"verification_uri_complete"`
		ExpiresIn               int    `json:"expires_in"`
		Interval                int    `json:"interval"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&deviceResp); err != nil {
		return nil, err
	}

	// Display instructions to user
	verificationURL := fmt.Sprintf("%s?user_code=%s", deviceResp.VerificationURI, deviceResp.UserCode)
	fmt.Println("\n==================================================")
	fmt.Printf("Please visit: %s\n", verificationURL)
	fmt.Printf("(Code: %s)\n", deviceResp.UserCode)
	fmt.Println("==================================================")
	fmt.Println()

	// Step 2: Poll for token
	tokenURL := config.IssuerURL + "/mcp/oauth2/token"
	pollInterval := time.Duration(deviceResp.Interval) * time.Second
	if pollInterval < 5*time.Second {
		pollInterval = 5 * time.Second
	}

	timeout := time.After(time.Duration(deviceResp.ExpiresIn) * time.Second)
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	fmt.Println("Waiting for authorization...")

	for {
		select {
		case <-timeout:
			return nil, fmt.Errorf("device code expired")
		case <-ticker.C:
			tokenData := url.Values{}
			tokenData.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
			tokenData.Set("device_code", deviceResp.DeviceCode)
			tokenData.Set("client_id", config.ClientID)

			tokenReq, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(tokenData.Encode()))
			if err != nil {
				return nil, err
			}
			tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			tokenResp, err := client.Do(tokenReq)
			if err != nil {
				return nil, err
			}

			body, _ := io.ReadAll(tokenResp.Body)
			if err := tokenResp.Body.Close(); err != nil {
				fmt.Fprintf(os.Stderr, "Warning: failed to close response body: %v\n", err)
			}

			if tokenResp.StatusCode == http.StatusOK {
				var tokenResult struct {
					AccessToken  string `json:"access_token"`
					RefreshToken string `json:"refresh_token"`
					TokenType    string `json:"token_type"`
					ExpiresIn    int    `json:"expires_in"`
					Scope        string `json:"scope"`
				}

				if err := json.Unmarshal(body, &tokenResult); err != nil {
					return nil, err
				}

				scopes := strings.Split(tokenResult.Scope, " ")
				expiresAt := time.Now().Add(time.Duration(tokenResult.ExpiresIn) * time.Second)

				return &TokenInfo{
					TrustDomain:  config.TrustDomain,
					ClientID:     config.ClientID,
					ClientSecret: config.ClientSecret,
					AccessToken:  tokenResult.AccessToken,
					RefreshToken: tokenResult.RefreshToken,
					TokenType:    tokenResult.TokenType,
					ExpiresAt:    expiresAt,
					Scopes:       scopes,
					IssuerURL:    config.IssuerURL,
				}, nil
			}

			var errorResp struct {
				Error            string `json:"error"`
				ErrorDescription string `json:"error_description"`
			}

			if err := json.Unmarshal(body, &errorResp); err == nil {
				if errorResp.Error == "authorization_pending" {
					fmt.Print(".")
					continue
				}
				return nil, fmt.Errorf("token error: %s - %s", errorResp.Error, errorResp.ErrorDescription)
			}

			return nil, fmt.Errorf("unexpected response: %s", string(body))
		}
	}
}

// refreshToken refreshes an access token using a refresh token
func refreshToken(tokenInfo *TokenInfo, _ *TokenFetchConfig) (*TokenInfo, error) {
	tokenURL := tokenInfo.IssuerURL + "/mcp/oauth2/token"

	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", tokenInfo.RefreshToken)
	data.Set("client_id", tokenInfo.ClientID)
	data.Set("client_secret", tokenInfo.ClientSecret)

	ctx := context.Background()
	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to close response body: %v\n", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("refresh failed: %s", string(body))
	}

	var tokenResult struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
		Scope        string `json:"scope"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&tokenResult); err != nil {
		return nil, err
	}

	scopes := strings.Split(tokenResult.Scope, " ")
	expiresAt := time.Now().Add(time.Duration(tokenResult.ExpiresIn) * time.Second)

	// Use new refresh token if provided, otherwise keep the old one
	refreshToken := tokenResult.RefreshToken
	if refreshToken == "" {
		refreshToken = tokenInfo.RefreshToken
	}

	return &TokenInfo{
		TrustDomain:  tokenInfo.TrustDomain,
		ClientID:     tokenInfo.ClientID,
		ClientSecret: tokenInfo.ClientSecret,
		AccessToken:  tokenResult.AccessToken,
		RefreshToken: refreshToken,
		TokenType:    tokenResult.TokenType,
		ExpiresAt:    expiresAt,
		Scopes:       scopes,
		IssuerURL:    tokenInfo.IssuerURL,
	}, nil
}

// getTokenInfoPath returns the path to the token info file
func getTokenInfoPath() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		homeDir = "/tmp"
	}
	condorDir := filepath.Join(homeDir, ".condor")
	return filepath.Join(condorDir, "token_info")
}

// getAccessTokenPath returns the path where access token should be saved
func getAccessTokenPath(trustDomain string) string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		homeDir = "/tmp"
	}
	tokensDir := filepath.Join(homeDir, ".condor", "tokens.d")
	// Sanitize trust domain for filename
	safeDomain := strings.ReplaceAll(trustDomain, ":", "_")
	safeDomain = strings.ReplaceAll(safeDomain, "/", "_")
	return filepath.Join(tokensDir, safeDomain)
}

// loadTokenInfoStore loads token info from disk
func loadTokenInfoStore(path string) (*TokenInfoStore, error) {
	//nolint:gosec // Path is from user config directory
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var store TokenInfoStore
	if err := json.Unmarshal(data, &store); err != nil {
		return nil, err
	}

	return &store, nil
}

// saveTokenInfoStore saves token info to disk
func saveTokenInfoStore(store *TokenInfoStore, path string) error {
	// Ensure directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	data, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0600)
}

// saveAccessToken saves the access token to tokens.d directory
func saveAccessToken(tokenInfo *TokenInfo) error {
	tokensDir := filepath.Dir(getAccessTokenPath(tokenInfo.TrustDomain))
	if err := os.MkdirAll(tokensDir, 0700); err != nil {
		return err
	}

	tokenPath := getAccessTokenPath(tokenInfo.TrustDomain)
	return os.WriteFile(tokenPath, []byte(tokenInfo.AccessToken), 0600)
}

// checkExistingToken checks if there's a valid token in tokens.d that won't expire for at least 5 minutes
func checkExistingToken(_ string) (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		homeDir = "/tmp"
	}
	tokensDir := filepath.Join(homeDir, ".condor", "tokens.d")

	// Check if tokens.d directory exists
	entries, err := os.ReadDir(tokensDir)
	if err != nil {
		return "", fmt.Errorf("failed to read tokens.d directory: %w", err)
	}

	// Scan all files in tokens.d directory
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		tokenPath := filepath.Join(tokensDir, entry.Name())
		//nolint:gosec // G304: Token path is constructed from user's .condor directory
		tokenData, err := os.ReadFile(tokenPath)
		if err != nil {
			continue // Skip files we can't read
		}

		// Parse file line by line
		lines := strings.Split(string(tokenData), "\n")
		for _, line := range lines {
			// Trim whitespace
			line = strings.TrimSpace(line)

			// Skip empty lines and comments
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}

			// Try to parse and validate this token
			if isValidToken(line) {
				return line, nil
			}
		}
	}

	return "", fmt.Errorf("no valid token found in tokens.d")
}

// isValidToken checks if a token is valid JWT and won't expire for at least 5 minutes
func isValidToken(token string) bool {
	// Parse JWT to check expiration
	// JWT format: header.payload.signature
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false
	}

	// Decode payload (base64url)
	payloadData, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		// Try with standard base64
		payloadData, err = base64.RawStdEncoding.DecodeString(parts[1])
		if err != nil {
			return false
		}
	}

	// Parse JSON payload
	var payload struct {
		Exp int64 `json:"exp"`
	}
	if err := json.Unmarshal(payloadData, &payload); err != nil {
		return false
	}

	// Check if token expires in more than 5 minutes
	expiresAt := time.Unix(payload.Exp, 0)
	fiveMinutesFromNow := time.Now().Add(5 * time.Minute)

	return expiresAt.After(fiveMinutesFromNow)
}
