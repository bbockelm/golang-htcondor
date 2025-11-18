// Package main provides token management functionality for the htcondor-api client
package main

import (
	"bytes"
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
	TrustDomain   string    `json:"trust_domain"`
	ClientID      string    `json:"client_id"`
	ClientSecret  string    `json:"client_secret"`
	AccessToken   string    `json:"access_token"`
	RefreshToken  string    `json:"refresh_token"`
	TokenType     string    `json:"token_type"`
	ExpiresAt     time.Time `json:"expires_at"`
	Scopes        []string  `json:"scopes"`
	IssuerURL     string    `json:"issuer_url"`
}

// TokenInfoStore manages multiple token infos keyed by trust domain
type TokenInfoStore struct {
	Tokens map[string]*TokenInfo `json:"tokens"`
}

// TokenFetchConfig holds configuration for fetching tokens
type TokenFetchConfig struct {
	IssuerURL   string
	TrustDomain string
	Scopes      []string
	ClientID    string
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
	scopes := []string{"openid", "mcp:read", "mcp:write"}

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

	resp, err := http.Post(registerURL, "application/json", bytes.NewBuffer(bodyBytes))
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

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

	resp, err := http.PostForm(deviceAuthURL, data)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

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
	fmt.Println("\n==================================================")
	fmt.Printf("Please visit: %s\n", deviceResp.VerificationURI)
	fmt.Printf("And enter code: %s\n", deviceResp.UserCode)
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

			tokenResp, err := http.PostForm(tokenURL, tokenData)
			if err != nil {
				return nil, err
			}

			body, _ := io.ReadAll(tokenResp.Body)
			tokenResp.Body.Close()

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
func refreshToken(tokenInfo *TokenInfo, config *TokenFetchConfig) (*TokenInfo, error) {
	tokenURL := tokenInfo.IssuerURL + "/mcp/oauth2/token"

	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", tokenInfo.RefreshToken)
	data.Set("client_id", tokenInfo.ClientID)
	data.Set("client_secret", tokenInfo.ClientSecret)

	resp, err := http.PostForm(tokenURL, data)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

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
