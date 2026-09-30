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
	"net"
	"strings"
	"sync"
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
	// Deliberately absent: the caller's OAuth2 access token, and the
	// username they asked for.
	//
	// Nothing read either. The username is conn.User(), which the
	// connection already carries, and the HTCondor credential is
	// minted locally from the account and scopes -- so holding a live
	// bearer token here for the life of a session bought nothing and
	// put it in every heap dump.
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

	// MaxPerSource caps logins in flight from ONE address.
	//
	// The global cap alone is a denial-of-service primitive rather
	// than a defence: sixty-four sockets from one host that answer the
	// prompt and then go silent hold every slot for the full timeout,
	// and nobody else can log in. Zero means DefaultMaxPerSource.
	MaxPerSource int

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
	DefaultMaxPerSource  = 4
)

// Authenticator turns an SSH keyboard-interactive exchange into an
// OAuth2 device authorization.
type Authenticator struct {
	opts  Options
	slots chan struct{}

	// inFlight counts logins per source address, so one host cannot
	// take every global slot.
	mu       sync.Mutex
	inFlight map[string]int
}

// takeSource claims a per-source slot.
func (a *Authenticator) takeSource(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.inFlight[host] >= a.opts.MaxPerSource {
		return false
	}
	a.inFlight[host]++
	return true
}

func (a *Authenticator) releaseSource(addr string) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.inFlight[host] <= 1 {
		delete(a.inFlight, host)
		return
	}
	a.inFlight[host]--
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
	if opts.MaxPerSource <= 0 {
		opts.MaxPerSource = DefaultMaxPerSource
	}
	return &Authenticator{
		opts:     opts,
		slots:    make(chan struct{}, opts.MaxConcurrent),
		inFlight: make(map[string]int),
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
	remote := conn.RemoteAddr().String()
	if !a.takeSource(remote) {
		a.tell(challenge, "Too many logins are already in progress from your address.")
		return nil, fmt.Errorf("sshgateway: too many concurrent logins from %s", remote)
	}
	defer a.releaseSource(remote)

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

	// The code goes in a PROMPT, not only in the instruction.
	//
	// A zero-question challenge looked ideal -- the client prints the
	// instruction and answers immediately, so the session continues by
	// itself. OpenSSH 10.x on macOS does exactly that. OpenSSH 9.9 on
	// Linux prints NOTHING and authenticates anyway, which is every
	// HTCondor user seeing a blank screen. A prompt is displayed by
	// every client because displaying it is what a prompt is for.
	//
	// The cost is one keypress. That is the whole trade: correctness on
	// the platform the users are on, against elegance on the one this
	// was developed on.
	if _, err := challenge("", loginInstruction(a.opts.Prompt),
		[]string{loginPromptLine(auth)}, []bool{true}); err != nil {
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
			ExtAccount: account,
			ExtScopes:  strings.Join(grant.Scopes, " "),
		},
	}, nil
}

// loginInstruction is the one line of context above the prompt.
//
// Deliberately says nothing actionable. Everything a person has to DO
// is in the prompt instead, because OpenSSH on Linux renders the
// prompt and ignores the instruction -- so anything that lives only
// here is invisible to most of the people who will use this. Saying it
// in both places is what made the old splash screen repeat the URL and
// the code three times over.
func loginInstruction(service string) string {
	if service == "" {
		return "Sign in to continue.\r\n"
	}
	return fmt.Sprintf("Sign in to %s\r\n", service)
}

// loginPromptLine is what the client actually renders.
//
// Laid out over several lines on purpose. ssh prefixes the prompt with
// "(user@host) ", so a single long line carrying a URL and a code
// wraps in the middle of the URL on any normal terminal. Starting with
// a newline leaves that prefix alone on its own line and puts the URL
// and the code on lines of their own, where they can be
// double-clicked and copied.
func loginPromptLine(auth *DeviceAuth) string {
	where := auth.VerificationURIComplete
	if where == "" {
		where = auth.VerificationURI
	}
	var b strings.Builder
	b.WriteString("\r\n")
	fmt.Fprintf(&b, "  Approve:  %s\r\n", where)
	fmt.Fprintf(&b, "  Code:     %s   (the page should show this)\r\n", auth.UserCode)
	b.WriteString("\r\n")
	b.WriteString("Press Enter once approved: ")
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
