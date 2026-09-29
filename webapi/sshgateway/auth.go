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

package sshgateway

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/bbockelm/golang-htcondor/logging"
)

// Permission extension keys. The SSH connection handler reads these
// off ServerConn.Permissions to learn who connected; they are server
// state and are never sent to the client.
const (
	// ExtAccount is the local account the caller's OAuth2 identity
	// mapped to. This, not the SSH username, is who the caller is.
	ExtAccount = "htcondor-account"
	// ExtScopes is the space-separated granted scope list.
	ExtScopes = "htcondor-scopes"
	// ExtAccessToken is the OAuth2 access token the grant produced,
	// which later becomes the HTCondor credential for this session.
	ExtAccessToken = "htcondor-access-token"
	// ExtRequestedTarget is the username the client asked for,
	// VERBATIM AND UNTRUSTED. The gateway uses it to choose which job
	// to attach to; it asserts nothing about identity, because
	// anybody can type anything there.
	ExtRequestedTarget = "htcondor-requested-target"
)

// IdentityFunc resolves the local account for a completed grant.
//
// Returning an empty name with a nil error is a programming mistake
// and is treated as a refusal: an unnamed caller must never reach a
// job, and failing closed here is what makes that true even if a
// future implementation forgets to return an error.
type IdentityFunc func(ctx context.Context, g *Grant) (string, error)

// Options configures an Authenticator.
type Options struct {
	// Flow and Identity are required.
	Flow     DeviceFlow
	Identity IdentityFunc

	Logger *logging.Logger

	// Prompt names the service in the text the user sees, e.g.
	// "ap2001.chtc.wisc.edu". Optional.
	Prompt string

	// Timeout bounds one login attempt. It also bounds how long an
	// abandoned connection holds a goroutine: nothing notices that a
	// client hung up while we are polling, because polling does not
	// touch the connection. Keep it at or below the issuer's device
	// code lifetime.
	Timeout time.Duration

	// MaxConcurrent caps logins in flight. Every connection that
	// reaches the prompt starts a device authorization and then waits
	// minutes for a human, so without a cap an attacker opening
	// connections mints unbounded device codes and goroutines for the
	// price of a TCP handshake.
	MaxConcurrent int
}

// Defaults applied to a zero Options.
const (
	DefaultTimeout       = 5 * time.Minute
	DefaultMaxConcurrent = 64
)

// Authenticator turns an SSH keyboard-interactive exchange into an
// OAuth2 device authorization.
type Authenticator struct {
	opts  Options
	slots chan struct{}
}

// NewAuthenticator validates opts and returns an Authenticator.
func NewAuthenticator(opts Options) (*Authenticator, error) {
	if opts.Flow == nil {
		return nil, errors.New("sshgateway: a DeviceFlow is required")
	}
	if opts.Identity == nil {
		// Not defaulted to "trust the token subject". A token's
		// subject is not an identity here -- the schedd is the trust
		// root -- so there is no safe default to fall back on.
		return nil, errors.New("sshgateway: an IdentityFunc is required")
	}
	if opts.Timeout <= 0 {
		opts.Timeout = DefaultTimeout
	}
	if opts.MaxConcurrent <= 0 {
		opts.MaxConcurrent = DefaultMaxConcurrent
	}
	return &Authenticator{
		opts:  opts,
		slots: make(chan struct{}, opts.MaxConcurrent),
	}, nil
}

// KeyboardInteractive is the ssh.ServerConfig callback.
//
// It is the only method the server should advertise. Setting it alone
// means an OpenSSH client never attempts publickey, so a user with a
// full agent does not spend the server's MaxAuthTries before reaching
// the prompt they were going to use anyway.
//
// ctx bounds every login this Authenticator runs; per-login timeouts
// come from Options.Timeout. The callback signature has no context of
// its own, which is why one is supplied here.
func (a *Authenticator) KeyboardInteractive(ctx context.Context) func(ssh.ConnMetadata, ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
	return func(conn ssh.ConnMetadata, challenge ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
		return a.authenticate(ctx, conn, challenge)
	}
}

func (a *Authenticator) authenticate(ctx context.Context, conn ssh.ConnMetadata, challenge ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
	select {
	case a.slots <- struct{}{}:
		defer func() { <-a.slots }()
	default:
		a.tell(challenge, "Too many logins are in progress. Please try again in a moment.")
		return nil, errors.New("sshgateway: too many concurrent logins")
	}

	ctx, cancel := context.WithTimeout(ctx, a.opts.Timeout)
	defer cancel()

	auth, err := a.opts.Flow.Authorize(ctx)
	if err != nil {
		a.logf("Could not start a device authorization", "remote", conn.RemoteAddr().String(), "error", err)
		// The issuer's own words are for the log. What the user needs
		// is to know it was not their fault and to try again.
		a.tell(challenge, "Could not start the login flow. Please try again, and tell your administrator if it keeps happening.")
		return nil, fmt.Errorf("sshgateway: starting the device authorization: %w", err)
	}

	// One challenge with no questions: RFC 4256 lets the server send
	// an instruction the client prints and answers immediately. So the
	// user sees the code and the URL without having to press anything,
	// and the session continues by itself once they approve.
	if _, err := challenge("", loginInstruction(a.opts.Prompt, auth), nil, nil); err != nil {
		return nil, fmt.Errorf("sshgateway: presenting the login prompt: %w", err)
	}

	grant, err := Wait(ctx, a.opts.Flow, auth)
	if err != nil {
		a.tell(challenge, waitFailureText(err))
		a.logf("Device authorization did not complete",
			"remote", conn.RemoteAddr().String(), "requested_target", conn.User(), "error", err)
		return nil, fmt.Errorf("sshgateway: waiting for approval: %w", err)
	}

	account, err := a.opts.Identity(ctx, grant)
	if err != nil {
		a.tell(challenge, "You signed in, but your account could not be resolved on this system. Ask your administrator to check the identity mapping.")
		a.logf("Could not resolve an account for an approved grant",
			"remote", conn.RemoteAddr().String(), "error", err)
		return nil, fmt.Errorf("sshgateway: resolving the account: %w", err)
	}
	if strings.TrimSpace(account) == "" {
		// Fail closed on an unnamed caller. See IdentityFunc.
		a.tell(challenge, "You signed in, but your account could not be resolved on this system. Ask your administrator to check the identity mapping.")
		a.logf("Identity mapping returned no account for an approved grant",
			"remote", conn.RemoteAddr().String())
		return nil, errors.New("sshgateway: the identity mapping produced no account")
	}

	a.logf("SSH gateway login",
		"account", account,
		"remote", conn.RemoteAddr().String(),
		"requested_target", conn.User(),
		"scopes", strings.Join(grant.Scopes, " "))

	return &ssh.Permissions{
		Extensions: map[string]string{
			ExtAccount:         account,
			ExtScopes:          strings.Join(grant.Scopes, " "),
			ExtAccessToken:     grant.AccessToken,
			ExtRequestedTarget: conn.User(),
		},
	}, nil
}

// loginInstruction is what the user reads in their terminal.
//
// The one-click link is shown when the server offers one, because this
// text reaches the user on the very terminal they typed `ssh` into --
// the same-device, out-of-band delivery RFC 8628 section 3.3.1 offers
// it for. The code is printed beside it so the user can check it
// against what the approval page displays, which is the step that
// catches somebody who followed a link they were sent rather than one
// they were shown. See the DeviceAuth doc comment.
func loginInstruction(service string, auth *DeviceAuth) string {
	var b strings.Builder
	if service != "" {
		fmt.Fprintf(&b, "Sign in to %s\r\n\r\n", service)
	} else {
		b.WriteString("Sign in to continue\r\n\r\n")
	}

	if auth.VerificationURIComplete != "" {
		fmt.Fprintf(&b, "  Open  %s\r\n\r\n", auth.VerificationURIComplete)
		fmt.Fprintf(&b, "  The page will show the code  %s  -- check it matches this one.\r\n\r\n", auth.UserCode)
	} else {
		fmt.Fprintf(&b, "  1. Open  %s\r\n", auth.VerificationURI)
		fmt.Fprintf(&b, "  2. Enter the code  %s\r\n\r\n", auth.UserCode)
	}

	b.WriteString("This session continues by itself once you approve it.\r\n")
	return b.String()
}

// waitFailureText explains a failed wait in the terminal, in terms of
// what the person can do about it.
func waitFailureText(err error) string {
	switch {
	case errors.Is(err, ErrDenied):
		return "The login was refused in the browser. Nothing was changed."
	case errors.Is(err, ErrExpired), errors.Is(err, context.DeadlineExceeded):
		return "The login code expired before it was approved. Reconnect to get a new one."
	case errors.Is(err, context.Canceled):
		return "The login was cancelled."
	default:
		return "The login could not be completed. Please try again, and tell your administrator if it keeps happening."
	}
}

// tell sends a message with no questions, purely to put text on the
// user's terminal before the connection fails.
//
// Without it the client prints only "Permission denied
// (keyboard-interactive)", which is the same thing it says for every
// other reason a login can fail. Any error here is dropped: the
// connection is already on its way out, and the caller's own error is
// the one worth returning.
func (a *Authenticator) tell(challenge ssh.KeyboardInteractiveChallenge, msg string) {
	if challenge == nil {
		return
	}
	_, _ = challenge("", msg+"\r\n", nil, nil)
}

func (a *Authenticator) logf(msg string, args ...any) {
	if a.opts.Logger == nil {
		return
	}
	a.opts.Logger.Info(logging.DestinationHTTP, msg, args...)
}
