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
// VerificationURIComplete carries the user code in its query string, so
// following it reaches the approval page with the code already filled
// in. An earlier version of this package deliberately dropped it, on
// the grounds that making the user transcribe the code defends against
// device-flow phishing. That reasoning does not survive contact with
// the threat model:
//
//   - The device-authorize endpoint performs no client authentication,
//     so an attacker can start their own flow and build the same URL.
//     Whether we print it changes nothing about what they can send.
//   - RFC 8628 section 3.3.1 offers the complete URI precisely for
//     delivery on the same device, out of band -- which is what
//     printing it on the terminal the user just typed `ssh` into is.
//     The section 5.4 phishing warning is about a code arriving over a
//     channel an attacker controls.
//   - The check that actually catches a phished victim is the approval
//     page displaying the code and asking whether it matches the one on
//     their device. That page already does this. A victim who followed
//     an attacker's link sees a code matching nothing they have.
//
// So the prompt shows the link AND the code, and tells the user to
// compare them. See loginInstruction.
type DeviceAuth struct {
	DeviceCode              string
	UserCode                string
	VerificationURI         string
	VerificationURIComplete string
	ExpiresIn               time.Duration
	Interval                time.Duration
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
	//
	// target is what the SSH username asked to reach. It is carried
	// into the authorization so the approval page can show the person
	// the workspace they are about to be let into -- and offer to
	// create it when they have none by that name -- rather than a
	// generic consent form that says only "a device wants in". It is
	// a hint for the page and nothing more: nothing downstream trusts
	// it, because the device-authorize endpoint authenticates no
	// client and anybody can put any name in one.
	Authorize(ctx context.Context, target Target) (*DeviceAuth, error)
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

// SessionFormField is the device-authorize parameter carrying the
// interactive session the caller asked for.
//
// RFC 8628's request carries client_id and scope and nothing else that
// fits; a custom parameter is the extension point the RFC leaves open.
// It is named here rather than in the server so the two ends cannot
// drift apart silently.
const SessionFormField = "ssh_session"

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
func (f *HTTPFlow) Authorize(ctx context.Context, target Target) (*DeviceAuth, error) {
	form := url.Values{}
	form.Set("client_id", f.ClientID)
	if len(f.Scopes) > 0 {
		form.Set("scope", strings.Join(f.Scopes, " "))
	}
	// Only a session name travels. A job id needs no workspace screen
	// -- the job either exists or it does not, and there is nothing to
	// configure -- so sending one would add an attacker-supplied
	// integer to the device code record for no gain.
	if !target.IsJob() && target.Name != "" {
		form.Set(SessionFormField, target.Name)
	}

	body, status, err := f.post(ctx, f.endpoint("/mcp/oauth2/device/authorize"), form)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("sshgateway: device authorization failed: %s", describeOAuthError(body, status))
	}

	var resp struct {
		DeviceCode              string `json:"device_code"`
		UserCode                string `json:"user_code"`
		VerificationURI         string `json:"verification_uri"`
		ExpiresIn               int    `json:"expires_in"`
		Interval                int    `json:"interval"`
		VerificationURIComplete string `json:"verification_uri_complete"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("sshgateway: device authorization response: %w", err)
	}
	if resp.DeviceCode == "" || resp.UserCode == "" {
		return nil, errors.New("sshgateway: device authorization response carried no code")
	}
	return &DeviceAuth{
		DeviceCode:              resp.DeviceCode,
		UserCode:                resp.UserCode,
		VerificationURI:         resp.VerificationURI,
		VerificationURIComplete: resp.VerificationURIComplete,
		ExpiresIn:               time.Duration(resp.ExpiresIn) * time.Second,
		Interval:                time.Duration(resp.Interval) * time.Second,
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
