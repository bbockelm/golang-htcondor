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
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeFlow answers Poll from a scripted list, recording the gap
// between calls so the retry policy can be observed.
type fakeFlow struct {
	mu      sync.Mutex
	auth    *DeviceAuth
	authErr error
	replies []error // consumed in order; nil means "granted"
	grant   *Grant
	calls   []time.Time
}

func (f *fakeFlow) Authorize(context.Context) (*DeviceAuth, error) {
	if f.authErr != nil {
		return nil, f.authErr
	}
	return f.auth, nil
}

func (f *fakeFlow) Poll(context.Context, string) (*Grant, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, time.Now())
	if len(f.replies) == 0 {
		return f.grant, nil
	}
	err := f.replies[0]
	f.replies = f.replies[1:]
	if err == nil {
		return f.grant, nil
	}
	return nil, err
}

func (f *fakeFlow) gaps() []time.Duration {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []time.Duration
	for i := 1; i < len(f.calls); i++ {
		out = append(out, f.calls[i].Sub(f.calls[i-1]))
	}
	return out
}

func testAuth() *DeviceAuth {
	return &DeviceAuth{
		DeviceCode: "dev-code",
		UserCode:   "WDJB-MJHT",
		// The real server's shape, complete URI included. A fixture
		// that omits it renders the fallback branch, which looks
		// exactly like the one-click link having been lost.
		VerificationURI:         "https://ap.example.edu/mcp/oauth2/device/verify",
		VerificationURIComplete: "https://ap.example.edu/mcp/oauth2/device/verify?user_code=WDJB-MJHT",
		ExpiresIn:               10 * time.Second,
		Interval:                10 * time.Millisecond,
	}
}

func TestWaitReturnsTheGrant(t *testing.T) {
	want := &Grant{AccessToken: "at", Scopes: []string{"condor:/WRITE"}}
	f := &fakeFlow{
		auth:    testAuth(),
		grant:   want,
		replies: []error{ErrAuthorizationPending, ErrAuthorizationPending, nil},
	}
	got, err := Wait(context.Background(), f, f.auth)
	if err != nil {
		t.Fatalf("wait: %v", err)
	}
	if got.AccessToken != want.AccessToken {
		t.Errorf("token = %q, want %q", got.AccessToken, want.AccessToken)
	}
}

// slow_down must lengthen the interval for the REST of the flow, not
// for one iteration. A server that is throttling says so once; a
// client that speeds back up gets throttled again for the rest of the
// flow and the user waits longer, not less.
// The RFC fixes the penalty at five seconds; Wait's variable exists
// only so the test above does not spend it.
func TestSlowDownPenaltyMatchesTheRFC(t *testing.T) {
	if slowDownPenalty != 5*time.Second {
		t.Errorf("slowDownPenalty = %v, want the RFC 8628 value of 5s", slowDownPenalty)
	}
}

func TestWaitSlowDownIsPermanent(t *testing.T) {
	// Shortened so the test does not spend three real penalties; the
	// property under test is that the penalty PERSISTS, not its size.
	restore := slowDownPenalty
	slowDownPenalty = 50 * time.Millisecond
	t.Cleanup(func() { slowDownPenalty = restore })

	auth := testAuth()
	auth.Interval = 10 * time.Millisecond
	f := &fakeFlow{
		auth:  auth,
		grant: &Grant{AccessToken: "at"},
		// pending, slow_down, pending, granted
		replies: []error{ErrAuthorizationPending, ErrSlowDown, ErrAuthorizationPending, nil},
	}
	if _, err := Wait(context.Background(), f, auth); err != nil {
		t.Fatalf("wait: %v", err)
	}

	gaps := f.gaps()
	if len(gaps) < 3 {
		t.Fatalf("got %d gaps, want at least 3", len(gaps))
	}
	// The gap AFTER the slow_down, and every one after that, carries
	// the five-second penalty. Compared against the original interval
	// rather than an absolute number so the test says what it means.
	want := auth.Interval + slowDownPenalty
	if gaps[1] < want {
		t.Errorf("gap after slow_down = %v, want at least %v", gaps[1], want)
	}
	if gaps[2] < want {
		t.Errorf("gap two polls after slow_down = %v, want at least %v; the penalty was dropped again", gaps[2], want)
	}
}

func TestWaitStopsOnADecision(t *testing.T) {
	for _, tc := range []struct {
		name string
		give error
	}{
		{"denied", ErrDenied},
		{"expired", ErrExpired},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeFlow{auth: testAuth(), replies: []error{tc.give}}
			_, err := Wait(context.Background(), f, f.auth)
			if !errors.Is(err, tc.give) {
				t.Fatalf("err = %v, want %v", err, tc.give)
			}
			// One poll, then stop. Polling past a decision the server
			// has already made looks like abuse.
			if n := len(f.gaps()) + 1; n != 1 {
				t.Errorf("polled %d times, want 1", n)
			}
		})
	}
}

func TestWaitExpiresOnItsOwnDeadline(t *testing.T) {
	auth := testAuth()
	auth.ExpiresIn = 20 * time.Millisecond
	auth.Interval = 10 * time.Millisecond
	f := &fakeFlow{auth: auth, replies: []error{ErrAuthorizationPending, ErrAuthorizationPending, ErrAuthorizationPending}}

	_, err := Wait(context.Background(), f, auth)
	if !errors.Is(err, ErrExpired) {
		t.Fatalf("err = %v, want ErrExpired", err)
	}
}

func TestWaitHonoursContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	f := &fakeFlow{auth: testAuth(), replies: []error{ErrAuthorizationPending, ErrAuthorizationPending}}
	go func() {
		time.Sleep(15 * time.Millisecond)
		cancel()
	}()
	_, err := Wait(ctx, f, f.auth)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

// The HTTP flow must translate every RFC 8628 poll outcome, because
// Wait's whole retry policy keys off these sentinels -- an
// unrecognised "authorization_pending" would abort the login the
// moment the user is reading the code.
func TestHTTPFlowTranslatesPollErrors(t *testing.T) {
	for _, tc := range []struct {
		body string
		want error
	}{
		{`{"error":"authorization_pending"}`, ErrAuthorizationPending},
		{`{"error":"slow_down"}`, ErrSlowDown},
		{`{"error":"expired_token"}`, ErrExpired},
		{`{"error":"access_denied"}`, ErrDenied},
	} {
		t.Run(tc.body, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()

			f := &HTTPFlow{Issuer: srv.URL, ClientID: "gateway"}
			_, err := f.Poll(context.Background(), "dev-code")
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestHTTPFlowAuthorizeAndPoll(t *testing.T) {
	var sawScope, sawGrantType string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/mcp/oauth2/device/authorize":
			sawScope = r.Form.Get("scope")
			_, _ = w.Write([]byte(`{"device_code":"dc","user_code":"WDJB-MJHT",
				"verification_uri":"https://ap.example.edu/device",
				"verification_uri_complete":"https://ap.example.edu/device?user_code=WDJB-MJHT",
				"expires_in":600,"interval":5}`))
		case "/mcp/oauth2/token":
			sawGrantType = r.Form.Get("grant_type")
			_, _ = w.Write([]byte(`{"access_token":"at","refresh_token":"rt","expires_in":3600,
				"scope":"openid condor:/WRITE"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	f := &HTTPFlow{Issuer: srv.URL, ClientID: "gateway", Scopes: []string{"openid", "condor:/WRITE"}}

	auth, err := f.Authorize(context.Background())
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if auth.UserCode != "WDJB-MJHT" {
		t.Errorf("user code = %q", auth.UserCode)
	}
	if auth.Interval != 5*time.Second || auth.ExpiresIn != 600*time.Second {
		t.Errorf("interval/expiry = %v/%v", auth.Interval, auth.ExpiresIn)
	}
	if sawScope != "openid condor:/WRITE" {
		t.Errorf("scope sent = %q", sawScope)
	}

	grant, err := f.Poll(context.Background(), auth.DeviceCode)
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	if grant.AccessToken != "at" || grant.RefreshToken != "rt" {
		t.Errorf("grant = %+v", grant)
	}
	if len(grant.Scopes) != 2 {
		t.Errorf("scopes = %v", grant.Scopes)
	}
	if sawGrantType != deviceGrantType {
		t.Errorf("grant_type = %q", sawGrantType)
	}
}

// The one-click link and the code are offered where the client will
// actually render them: the PROMPT.
//
// Not the instruction. OpenSSH on Linux prints the prompt and ignores
// a keyboard-interactive instruction entirely, so anything actionable
// that lives only in the instruction is invisible to most users. The
// instruction now carries no instructions -- which is why the splash
// screen stopped repeating the URL and the code three times.
func TestOneClickLinkIsOfferedInThePrompt(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"device_code":"dc","user_code":"WDJB-MJHT",
			"verification_uri":"https://ap.example.edu/device",
			"verification_uri_complete":"https://ap.example.edu/device?user_code=WDJB-MJHT",
			"expires_in":600,"interval":5}`))
	}))
	defer srv.Close()

	f := &HTTPFlow{Issuer: srv.URL, ClientID: "gateway"}
	auth, err := f.Authorize(context.Background())
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if auth.VerificationURIComplete == "" {
		t.Fatal("the complete URI was dropped")
	}

	prompt := loginPromptLine(auth)
	if !strings.Contains(prompt, auth.VerificationURIComplete) {
		t.Errorf("the prompt does not offer the link:\n%s", prompt)
	}
	if !strings.Contains(prompt, "WDJB-MJHT") {
		t.Errorf("the prompt does not show the code:\n%s", prompt)
	}

	// The URL and the code each get a line of their own. ssh prefixes
	// the prompt with "(user@host) ", so one long line wraps in the
	// middle of the URL.
	for _, line := range strings.Split(prompt, "\r\n") {
		if len(line) > 100 {
			t.Errorf("a prompt line is %d characters and will wrap: %q", len(line), line)
		}
	}
	if !strings.HasPrefix(prompt, "\r\n") {
		t.Errorf("the prompt does not start on its own line, so ssh's (user@host) prefix runs into it")
	}
}

// Everything actionable is in the prompt, so the instruction must not
// repeat it. Repeating it is what put the URL and the code on screen
// three times.
func TestInstructionCarriesNothingActionable(t *testing.T) {
	auth := &DeviceAuth{
		UserCode:                "WDJB-MJHT",
		VerificationURI:         "https://ap.example.edu/device",
		VerificationURIComplete: "https://ap.example.edu/device?user_code=WDJB-MJHT",
	}
	instr := loginInstruction("ap.example.edu")

	if strings.Contains(instr, auth.UserCode) {
		t.Errorf("the instruction repeats the code:\n%s", instr)
	}
	if strings.Contains(instr, "ap.example.edu/device") {
		t.Errorf("the instruction repeats the URL:\n%s", instr)
	}
	if !strings.Contains(instr, "ap.example.edu") {
		t.Errorf("the instruction does not name the service:\n%s", instr)
	}
}

// A server that offers no complete URI still gets a usable prompt.
func TestPromptFallsBackToThePlainURL(t *testing.T) {
	auth := &DeviceAuth{
		UserCode:        "WDJB-MJHT",
		VerificationURI: "https://ap.example.edu/device",
	}
	prompt := loginPromptLine(auth)
	if !strings.Contains(prompt, "https://ap.example.edu/device") {
		t.Errorf("the verification URL is missing:\n%s", prompt)
	}
	if !strings.Contains(prompt, "WDJB-MJHT") {
		t.Errorf("the code is missing:\n%s", prompt)
	}
}
