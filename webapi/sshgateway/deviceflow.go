// Copyright 2026 Morgridge Institute for Research
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package sshgateway authenticates an ordinary SSH client against this
// server's OAuth2 identity, so a user can reach an HTCondor job with a
// terminal without holding a login on the access point.
//
// The hook is RFC 4256 keyboard-interactive. The server may send an
// instruction with no questions, which the client prints -- so the
// device code and the URL to approve it reach the user's terminal
// through a standard mechanism, with no client-side tooling.
package sshgateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Device-flow poll outcomes, as RFC 8628 section 3.5 defines them.
var (
	// ErrAuthorizationPending means the user has not finished yet.
	ErrAuthorizationPending = errors.New("sshgateway: authorization pending")
	// ErrSlowDown means the same, and asks for a longer interval.
	ErrSlowDown = errors.New("sshgateway: polling too fast")
	// ErrExpired means the device code aged out before approval.
	ErrExpired = errors.New("sshgateway: device code expired")
	// ErrDenied means the user refused.
	ErrDenied = errors.New("sshgateway: authorization denied")
)

// DeviceAuth is a started device authorization.
//
// There is deliberately no field for the verification_uri_complete the
// server also returns. That URI carries the user code in its query
// string, so following it approves the request with one click -- which
// is exactly the shape of the device-flow phishing attack, where an
// attacker starts a flow and gets the victim to click the link. Making
// the user transcribe the code is the mitigation, and the way to keep
// that mitigation is to not carry the convenient URI to where a prompt
// could print it.
type DeviceAuth struct {
	DeviceCode      string
	UserCode        string
	VerificationURI string
	ExpiresIn       time.Duration
	Interval        time.Duration
}

// Grant is a completed authorization.
type Grant struct {
	AccessToken  string
	RefreshToken string
	Scopes       []string
	ExpiresAt    time.Time
}

// DeviceFlow is the slice of an OAuth2 server this package needs.
//
// An interface because the gateway may run in the same process as the
// server it authenticates against or in a different one, and because
// the retry policy in Wait is worth testing without a network.
type DeviceFlow interface {
	// Authorize starts a flow and returns the code to show the user.
	Authorize(ctx context.Context) (*DeviceAuth, error)
	// Poll reports the state of a started flow. A flow still waiting
	// on the user returns ErrAuthorizationPending or ErrSlowDown.
	Poll(ctx context.Context, deviceCode string) (*Grant, error)
}

// slowDownPenalty is what RFC 8628 section 3.5 adds to the polling
// interval on each slow_down. A variable only so a test can shorten
// it; TestSlowDownPenaltyMatchesTheRFC pins the real value.
var slowDownPenalty = 5 * time.Second

// Wait polls until the user approves, refuses, or runs out of time.
//
// The interval comes from the server and grows by slowDownPenalty on
// every slow_down. Growing it permanently rather than for one
// iteration matters: a server that is rate-limiting says so once and
// expects the client to stay slower, and a client that speeds back up
// gets throttled for the rest of the flow.
func Wait(ctx context.Context, flow DeviceFlow, auth *DeviceAuth) (*Grant, error) {
	interval := auth.Interval
	if interval <= 0 {
		interval = 5 * time.Second
	}

	deadline := time.Now().Add(auth.ExpiresIn)
	if auth.ExpiresIn <= 0 {
		deadline = time.Now().Add(10 * time.Minute)
	}

	timer := time.NewTimer(interval)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timer.C:
		}

		if time.Now().After(deadline) {
			return nil, ErrExpired
		}

		grant, err := flow.Poll(ctx, auth.DeviceCode)
		switch {
		case err == nil:
			return grant, nil
		case errors.Is(err, ErrSlowDown):
			interval += slowDownPenalty
		case errors.Is(err, ErrAuthorizationPending):
			// Keep the current interval.
		default:
			// Expired, denied, or anything unexpected. Polling past
			// a decision the server has already made is pointless
			// and looks like abuse.
			return nil, err
		}
		timer.Reset(interval)
	}
}

// HTTPFlow drives the device grant over HTTP against an OAuth2 issuer.
//
// It works whether the issuer is this same process on loopback or a
// different host, so the choice of topology is a wiring decision rather
// than a protocol one.
type HTTPFlow struct {
	// Issuer is the base URL, e.g. https://ap.example.edu.
	Issuer string
	// ClientID is a public client -- the device-authorize endpoint
	// performs no client authentication, so there is no secret here
	// and none is needed.
	ClientID string
	// Scopes requested at authorization. condor:/WRITE covers shell
	// access, because the schedd registers GET_JOB_CONNECT_INFO at
	// WRITE; offline_access is what lets a terminal outlive its
	// access token.
	Scopes []string
	// HTTP is optional; http.DefaultClient is used when nil.
	HTTP *http.Client
}

const deviceGrantType = "urn:ietf:params:oauth:grant-type:device_code"

func (f *HTTPFlow) httpClient() *http.Client {
	if f.HTTP != nil {
		return f.HTTP
	}
	return http.DefaultClient
}

func (f *HTTPFlow) endpoint(path string) string {
	return strings.TrimSuffix(f.Issuer, "/") + path
}

// Authorize implements DeviceFlow.
func (f *HTTPFlow) Authorize(ctx context.Context) (*DeviceAuth, error) {
	form := url.Values{}
	form.Set("client_id", f.ClientID)
	if len(f.Scopes) > 0 {
		form.Set("scope", strings.Join(f.Scopes, " "))
	}

	body, status, err := f.post(ctx, f.endpoint("/mcp/oauth2/device/authorize"), form)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("sshgateway: device authorization failed: %s", describeOAuthError(body, status))
	}

	var resp struct {
		DeviceCode      string `json:"device_code"`
		UserCode        string `json:"user_code"`
		VerificationURI string `json:"verification_uri"`
		ExpiresIn       int    `json:"expires_in"`
		Interval        int    `json:"interval"`
		// verification_uri_complete is deliberately not decoded; see
		// the DeviceAuth doc comment.
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("sshgateway: device authorization response: %w", err)
	}
	if resp.DeviceCode == "" || resp.UserCode == "" {
		return nil, errors.New("sshgateway: device authorization response carried no code")
	}
	return &DeviceAuth{
		DeviceCode:      resp.DeviceCode,
		UserCode:        resp.UserCode,
		VerificationURI: resp.VerificationURI,
		ExpiresIn:       time.Duration(resp.ExpiresIn) * time.Second,
		Interval:        time.Duration(resp.Interval) * time.Second,
	}, nil
}

// Poll implements DeviceFlow.
func (f *HTTPFlow) Poll(ctx context.Context, deviceCode string) (*Grant, error) {
	form := url.Values{}
	form.Set("grant_type", deviceGrantType)
	form.Set("device_code", deviceCode)
	form.Set("client_id", f.ClientID)

	body, status, err := f.post(ctx, f.endpoint("/mcp/oauth2/token"), form)
	if err != nil {
		return nil, err
	}

	if status != http.StatusOK {
		var oe struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(body, &oe)
		switch oe.Error {
		case "authorization_pending":
			return nil, ErrAuthorizationPending
		case "slow_down":
			return nil, ErrSlowDown
		case "expired_token":
			return nil, ErrExpired
		case "access_denied":
			return nil, ErrDenied
		}
		return nil, fmt.Errorf("sshgateway: device token request failed: %s", describeOAuthError(body, status))
	}

	var resp struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
		Scope        string `json:"scope"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("sshgateway: device token response: %w", err)
	}
	if resp.AccessToken == "" {
		return nil, errors.New("sshgateway: device token response carried no access token")
	}
	return &Grant{
		AccessToken:  resp.AccessToken,
		RefreshToken: resp.RefreshToken,
		Scopes:       strings.Fields(resp.Scope),
		ExpiresAt:    time.Now().Add(time.Duration(resp.ExpiresIn) * time.Second),
	}, nil
}

// post sends a form and returns the body and status. The body is read
// in full and bounded: this talks to a trusted issuer, but an error
// page from something in between should not be able to exhaust memory.
func (f *HTTPFlow) post(ctx context.Context, endpoint string, form url.Values) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, 0, fmt.Errorf("sshgateway: building a request for %s: %w", endpoint, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := f.httpClient().Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("sshgateway: %s: %w", endpoint, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("sshgateway: reading the response from %s: %w", endpoint, err)
	}
	return body, resp.StatusCode, nil
}

// describeOAuthError turns an error body into one line for a log.
//
// Never shown to the SSH client: an issuer's error text is written for
// an operator reading a log, not for somebody sitting at a terminal
// who asked for a shell.
func describeOAuthError(body []byte, status int) string {
	var oe struct {
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	if err := json.Unmarshal(body, &oe); err == nil && oe.Error != "" {
		if oe.Description != "" {
			return fmt.Sprintf("%s: %s (HTTP %d)", oe.Error, oe.Description, status)
		}
		return fmt.Sprintf("%s (HTTP %d)", oe.Error, status)
	}
	return fmt.Sprintf("HTTP %d", status)
}
