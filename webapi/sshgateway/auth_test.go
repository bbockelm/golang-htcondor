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
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func testSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	return signer
}

// server runs an SSH server whose only auth method is the
// Authenticator under test. It records the Permissions of the last
// connection that got in, and answers a session channel with an
// immediate clean exit so a real ssh client has something to finish
// against.
type server struct {
	addr string

	mu    sync.Mutex
	perms *ssh.Permissions
}

func (s *server) lastPermissions() *ssh.Permissions {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.perms
}

func startServer(t *testing.T, a *Authenticator) *server {
	t.Helper()

	cfg := &ssh.ServerConfig{
		KeyboardInteractiveCallback: a.KeyboardInteractive(context.Background()),
	}
	cfg.AddHostKey(testSigner(t))

	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	srv := &server{addr: ln.Addr().String()}
	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			go srv.handle(nc, cfg)
		}
	}()
	return srv
}

func (s *server) handle(nc net.Conn, cfg *ssh.ServerConfig) {
	conn, chans, reqs, err := ssh.NewServerConn(nc, cfg)
	if err != nil {
		_ = nc.Close()
		return
	}
	defer func() { _ = conn.Close() }()

	s.mu.Lock()
	s.perms = conn.Permissions
	s.mu.Unlock()

	go ssh.DiscardRequests(reqs)
	for nch := range chans {
		if nch.ChannelType() != "session" {
			_ = nch.Reject(ssh.UnknownChannelType, "only sessions here")
			continue
		}
		ch, creqs, err := nch.Accept()
		if err != nil {
			return
		}
		go func() {
			for req := range creqs {
				if req.WantReply {
					_ = req.Reply(req.Type == "shell" || req.Type == "exec" || req.Type == "pty-req", nil)
				}
				if req.Type == "shell" || req.Type == "exec" {
					_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
					_ = ch.Close()
				}
			}
		}()
	}
}

// grantingAuthenticator approves on the first poll and maps every
// grant to account.
func grantingAuthenticator(t *testing.T, account string, opts Options) *Authenticator {
	t.Helper()
	auth := testAuth()
	auth.Interval = time.Millisecond
	if opts.Flow == nil {
		opts.Flow = &fakeFlow{auth: auth, grant: &Grant{AccessToken: "at", Scopes: []string{"openid", "condor:/WRITE"}}}
	}
	if opts.Identity == nil {
		opts.Identity = func(context.Context, *Grant) (string, error) { return account, nil }
	}
	a, err := NewAuthenticator(opts)
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	return a
}

// dial connects with x/crypto's client and returns everything the
// keyboard-interactive callback was shown.
func dial(t *testing.T, addr, user string) ([]string, error) {
	t.Helper()
	var shown []string
	cfg := &ssh.ClientConfig{
		User:            user,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // test server, key generated per run
		Timeout:         10 * time.Second,
		Auth: []ssh.AuthMethod{
			ssh.KeyboardInteractive(func(_, instruction string, questions []string, _ []bool) ([]string, error) {
				shown = append(shown, instruction)
				return make([]string, len(questions)), nil
			}),
		},
	}
	client, err := ssh.Dial("tcp", addr, cfg)
	if err != nil {
		return shown, err
	}
	_ = client.Close()
	return shown, nil
}

func TestApprovedLoginCarriesTheIdentityForward(t *testing.T) {
	a := grantingAuthenticator(t, "bbockelm", Options{Prompt: "ap.example.edu"})
	srv := startServer(t, a)

	shown, err := dial(t, srv.addr, "12345.0")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if len(shown) == 0 || !strings.Contains(shown[0], "WDJB-MJHT") {
		t.Fatalf("the client was never shown the code: %q", shown)
	}
	if !strings.Contains(shown[0], "ap.example.edu") {
		t.Errorf("the prompt does not name the service: %q", shown[0])
	}

	perms := srv.lastPermissions()
	if perms == nil {
		t.Fatal("no permissions recorded")
	}
	if got := perms.Extensions[ExtAccount]; got != "bbockelm" {
		t.Errorf("account = %q, want the mapped account", got)
	}
	if got := perms.Extensions[ExtScopes]; got != "openid condor:/WRITE" {
		t.Errorf("scopes = %q", got)
	}
	if got := perms.Extensions[ExtAccessToken]; got != "at" {
		t.Errorf("access token = %q", got)
	}
	// The SSH username is routing input, not identity: it is carried
	// verbatim and separately from the account that was resolved.
	if got := perms.Extensions[ExtRequestedTarget]; got != "12345.0" {
		t.Errorf("requested target = %q, want the username verbatim", got)
	}
}

// An identity mapping that returns no account must not authenticate
// anybody. An unnamed caller reaching a job is the failure this is
// guarding, and it has to hold even when the mapping returns a nil
// error -- which is the shape a future implementation is most likely
// to get wrong.
func TestUnresolvedAccountIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name     string
		identity IdentityFunc
	}{
		{"empty name, no error", func(context.Context, *Grant) (string, error) { return "", nil }},
		{"whitespace only", func(context.Context, *Grant) (string, error) { return "   ", nil }},
		{"an error", func(context.Context, *Grant) (string, error) { return "", errors.New("no such user") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := grantingAuthenticator(t, "", Options{Identity: tc.identity})
			srv := startServer(t, a)

			shown, err := dial(t, srv.addr, "someone")
			if err == nil {
				t.Fatal("the login succeeded with no resolved account")
			}
			if srv.lastPermissions() != nil {
				t.Error("a connection was admitted")
			}
			// The user is told why, rather than getting the same
			// "permission denied" every other failure produces.
			if len(shown) < 2 || !strings.Contains(strings.ToLower(shown[len(shown)-1]), "account") {
				t.Errorf("the failure was not explained in the terminal: %q", shown)
			}
		})
	}
}

func TestRefusedAuthorizationIsExplained(t *testing.T) {
	auth := testAuth()
	auth.Interval = time.Millisecond
	flow := &fakeFlow{auth: auth, replies: []error{ErrDenied}}
	a := grantingAuthenticator(t, "bbockelm", Options{Flow: flow})
	srv := startServer(t, a)

	shown, err := dial(t, srv.addr, "someone")
	if err == nil {
		t.Fatal("a refused authorization logged in")
	}
	last := shown[len(shown)-1]
	if !strings.Contains(strings.ToLower(last), "refused") {
		t.Errorf("a refusal was not explained: %q", last)
	}
}

// Every connection that reaches the prompt starts a device
// authorization and then waits minutes for a human. Without a cap,
// opening connections is a way to mint unbounded device codes and
// goroutines for the price of a TCP handshake.
func TestConcurrentLoginsAreCapped(t *testing.T) {
	blocking := newBlockingFlow(testAuth())

	a := grantingAuthenticator(t, "bbockelm", Options{Flow: blocking, MaxConcurrent: 1})
	srv := startServer(t, a)

	// Hold the single slot.
	held := make(chan struct{})
	go func() {
		defer close(held)
		_, _ = dial(t, srv.addr, "first")
	}()
	blocking.waitStarted(t)

	shown, err := dial(t, srv.addr, "second")
	if err == nil {
		t.Fatal("a second login got in past the cap of 1")
	}
	if len(shown) == 0 || !strings.Contains(strings.ToLower(shown[0]), "too many") {
		t.Errorf("the cap was not explained in the terminal: %q", shown)
	}

	close(blocking.release)
	<-held
}

// blockingFlow holds Authorize until released, so a test can occupy a
// concurrency slot deterministically rather than by sleeping.
type blockingFlow struct {
	auth    *DeviceAuth
	release chan struct{}
	started chan struct{}
	once    sync.Once
}

func newBlockingFlow(auth *DeviceAuth) *blockingFlow {
	return &blockingFlow{
		auth:    auth,
		release: make(chan struct{}),
		started: make(chan struct{}),
	}
}

func (b *blockingFlow) waitStarted(t *testing.T) {
	t.Helper()
	select {
	case <-b.started:
	case <-time.After(5 * time.Second):
		t.Fatal("the first login never reached the flow")
	}
}

func (b *blockingFlow) Authorize(ctx context.Context) (*DeviceAuth, error) {
	b.once.Do(func() { close(b.started) })
	select {
	case <-b.release:
		return nil, errors.New("released")
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (b *blockingFlow) Poll(context.Context, string) (*Grant, error) {
	return nil, ErrAuthorizationPending
}

// baseSSHArgs are the flags every invocation needs.
//
// -F /dev/null so the developer's own ~/.ssh/config cannot reach these
// tests. ControlMaster in particular is not a stylistic difference: the
// mux layer swallows the reason a channel was refused and reports
// "Session open refused by peer", which is exactly the diagnostic
// these tests exist for.
func baseSSHArgs(portFlag, port string) []string {
	return []string{
		"-F", "/dev/null",
		portFlag, port,
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "IdentitiesOnly=yes",
		"-o", "LogLevel=ERROR",
	}
}

// askpass stages a helper that records the prompt ssh would have shown
// a user, and answers it with an empty line.
//
// Needed because `go test` gives ssh no controlling terminal, and
// without one OpenSSH has nowhere to write a prompt -- so a test that
// merely runs ssh cannot see what a person would see. That gap is not
// hypothetical: the zero-question challenge this package started with
// printed nothing at all on Linux, and every test passed anyway
// because none of them could observe a prompt in the first place.
//
// SSH_ASKPASS_REQUIRE=force is what makes ssh prefer the helper over a
// terminal; DISPLAY is set because older clients check for it.
func askpass(t *testing.T) (env []string, shown func() string) {
	t.Helper()
	dir := t.TempDir()
	log := filepath.Join(dir, "prompts.txt")
	script := filepath.Join(dir, "askpass.sh")
	body := "#!/bin/sh\nprintf '%s\\n' \"$1\" >> \"" + log + "\"\necho\n"
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil { //nolint:gosec // must be executable
		t.Fatalf("write askpass: %v", err)
	}
	return []string{
			"SSH_ASKPASS=" + script,
			"SSH_ASKPASS_REQUIRE=force",
			"DISPLAY=:0",
			"PATH=" + os.Getenv("PATH"),
			"HOME=" + dir,
		}, func() string {
			b, _ := os.ReadFile(log) //nolint:gosec // a path this function just built under t.TempDir()
			return string(b)
		}
}

// runSSH is the one place a client is actually launched.
func runSSH(t *testing.T, bin, addr string, env, flags []string, tail ...string) ([]byte, error) {
	t.Helper()
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	portFlag := "-p"
	if strings.HasSuffix(bin, "scp") {
		portFlag = "-P"
	}
	args := append(baseSSHArgs(portFlag, port), flags...)
	for i, a := range tail {
		tail[i] = strings.ReplaceAll(a, "HOST", host)
	}
	args = append(args, tail...)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	//nolint:gosec // fixed argv; the binary is resolved by LookPath in the caller
	cmd := exec.CommandContext(ctx, bin, args...)
	if len(env) > 0 {
		cmd.Env = env
	}
	return cmd.CombinedOutput()
}

// realSSHRaw leaves the authentication method to the caller, which is
// what the certificate tests need: realSSH's device-flow defaults come
// first in argv and OpenSSH takes the first occurrence of an option.
func realSSHRaw(t *testing.T, bin, addr string, extra []string, tail ...string) ([]byte, error) {
	t.Helper()
	return runSSH(t, bin, addr, nil, extra, tail...)
}

// realSSH runs a client with the device-flow defaults.
func realSSH(t *testing.T, bin, addr string, extra []string, tail ...string) ([]byte, error) {
	t.Helper()
	return realSSHEnv(t, bin, addr, nil, extra, tail...)
}

// realSSHEnv is realSSH with an environment, for the askpass helper.
func realSSHEnv(t *testing.T, bin, addr string, env, extra []string, tail ...string) ([]byte, error) {
	t.Helper()
	flags := append([]string{
		"-o", "PubkeyAuthentication=no",
		"-o", "PreferredAuthentications=keyboard-interactive",
	}, extra...)
	return runSSH(t, bin, addr, env, flags, tail...)
}

// The experiment this whole approach rests on: a REAL OpenSSH client,
// given a keyboard-interactive challenge with no questions, must print
// the instruction and then authenticate. Everything else here is
// tested against x/crypto's own client, which is not what users run.
//
// The matrix is the second finding. A challenge with no questions
// reads no input, so the client needs no terminal -- which an earlier
// draft of the design got wrong, having assumed keyboard-interactive
// implies a TTY. Verified against OpenSSH 10.3p1.
//
// Only BatchMode=yes is refused, and deliberately not asserted here:
// it is the client declining to attempt the method at all, which is
// its policy to change, and a test pinning somebody else's refusal
// breaks the day they relax it.
func TestRealOpenSSHClientAuthenticates(t *testing.T) {
	sshBin, err := exec.LookPath("ssh")
	if err != nil {
		t.Skip("no ssh binary to test against")
	}

	for _, tc := range []struct {
		name  string
		extra []string
	}{
		{"default", nil},
		{"no tty", []string{"-T"}},
		{"forced tty", []string{"-tt"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := grantingAuthenticator(t, "bbockelm", Options{Prompt: "ap.example.edu"})
			srv := startServer(t, a)
			env, shown := askpass(t)

			out, err := realSSHEnv(t, sshBin, srv.addr, env, tc.extra, "12345.0@HOST", "true")
			t.Logf("ssh exit=%v output:\n%s\nprompted:\n%s", err, out, shown())

			// What the USER would see, which is the prompt -- not the
			// combined output, which is empty when ssh has no terminal.
			if !strings.Contains(shown(), "WDJB-MJHT") {
				t.Fatalf("a real ssh client never showed the device code. prompted:\n%q\noutput:\n%s",
					shown(), out)
			}
			perms := srv.lastPermissions()
			if perms == nil || perms.Extensions[ExtAccount] != "bbockelm" {
				t.Fatalf("the real client did not authenticate: perms=%+v", perms)
			}
		})
	}
}

// scp authenticates through the same prompt. It matters because it
// narrows what the certificate path is for: not "keyboard-interactive
// cannot work without a terminal" -- it can -- but automation that
// sets BatchMode, and not making a human approve every single
// connection.
//
// Only the authentication is asserted. This test server answers no
// sftp subsystem, so the transfer itself fails here for a reason that
// has nothing to do with the gateway.
func TestRealSCPAuthenticates(t *testing.T) {
	scpBin, err := exec.LookPath("scp")
	if err != nil {
		t.Skip("no scp binary to test against")
	}

	a := grantingAuthenticator(t, "bbockelm", Options{Prompt: "ap.example.edu"})
	srv := startServer(t, a)
	env, shown := askpass(t)

	src := filepath.Join(t.TempDir(), "payload")
	if err := os.WriteFile(src, []byte("hi\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	out, _ := realSSHEnv(t, scpBin, srv.addr, env, nil, src, "12345.0@HOST:/tmp/payload")
	t.Logf("scp output:\n%s\nprompted:\n%s", out, shown())

	if !strings.Contains(shown(), "WDJB-MJHT") {
		t.Errorf("scp never showed the device code. prompted:\n%q", shown())
	}
	perms := srv.lastPermissions()
	if perms == nil || perms.Extensions[ExtAccount] != "bbockelm" {
		t.Errorf("scp did not authenticate: perms=%+v", perms)
	}
}

// A client that offers a public key first must still reach the
// prompt. The server advertises keyboard-interactive alone, so the
// key is refused and the client moves on -- which is the behaviour
// that lets a user with a loaded agent log in without configuring
// anything.
//
// Tested here rather than against the system ssh because driving that
// with publickey enabled makes the client touch the agent, and an
// agent process inheriting the output pipe leaves CombinedOutput
// blocked after the client itself has exited. That is a harness
// hazard, not a gateway one, and it is why the real-client tests pass
// PubkeyAuthentication=no.
func TestClientOfferingAKeyStillReachesThePrompt(t *testing.T) {
	a := grantingAuthenticator(t, "bbockelm", Options{Prompt: "ap.example.edu"})
	srv := startServer(t, a)

	var shown []string
	cfg := &ssh.ClientConfig{
		User:            "12345.0",
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // test server, key generated per run
		Timeout:         10 * time.Second,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(testSigner(t)),
			ssh.KeyboardInteractive(func(_, instruction string, questions []string, _ []bool) ([]string, error) {
				shown = append(shown, instruction)
				return make([]string, len(questions)), nil
			}),
		},
	}
	client, err := ssh.Dial("tcp", srv.addr, cfg)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_ = client.Close()

	if len(shown) == 0 || !strings.Contains(shown[0], "WDJB-MJHT") {
		t.Fatalf("the prompt was never reached: %q", shown)
	}
	if perms := srv.lastPermissions(); perms == nil || perms.Extensions[ExtAccount] != "bbockelm" {
		t.Errorf("the client did not authenticate: perms=%+v", perms)
	}
}
