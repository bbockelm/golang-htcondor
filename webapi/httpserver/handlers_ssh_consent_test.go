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

package httpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ory/fosite"

	"github.com/bbockelm/golang-htcondor/webapi/sshgateway"
)

// sshConsentFixture is a Handler with just enough wired up to run the
// two consent endpoints: an OAuth2 storage to hold device codes, and
// the user-header identity path so a request can be "a signed-in
// browser" without a cookie jar.
type sshConsentFixture struct {
	h       *Handler
	storage *OAuth2Storage
	client  *fosite.DefaultClient
}

func newSSHConsentFixture(t *testing.T) *sshConsentFixture {
	t.Helper()
	storage := NewOAuth2Storage(newTestDB(t, filepath.Join(t.TempDir(), "consent.db")))
	client := &fosite.DefaultClient{
		ID:         sshGatewayClientID,
		GrantTypes: []string{"urn:ietf:params:oauth:grant-type:device_code"},
		Scopes:     sshGatewayScopes,
		Public:     true,
	}
	if err := storage.CreateClient(context.Background(), client); err != nil {
		t.Fatalf("create client: %v", err)
	}
	return &sshConsentFixture{
		h: &Handler{
			logger: testLogger(t),
			// config is not optional: writeError reaches for the
			// issuer to build a WWW-Authenticate header on a 401.
			oauth2Provider: &OAuth2Provider{
				storage: storage,
				config:  &fosite.Config{AccessTokenIssuer: "https://ap.example.edu"}, //nolint:gosec // G101: test issuer URL
			},
			userHeader:               "X-Remote-User",
			userHeaderUnsafeAllowAll: true,
		},
		storage: storage,
		client:  client,
	}
}

// startLogin mints a device code the way the SSH gateway would.
func (f *sshConsentFixture) startLogin(t *testing.T, session string) string {
	t.Helper()
	dh := NewDeviceCodeHandler(f.storage,
		&fosite.Config{AccessTokenIssuer: "https://ap.example.edu"}) //nolint:gosec // G101: test issuer URL
	resp, err := dh.HandleDeviceAuthorizationRequest(
		context.Background(), f.client, sshGatewayScopes, session)
	if err != nil {
		t.Fatalf("device authorization: %v", err)
	}
	return resp.UserCode
}

func (f *sshConsentFixture) get(t *testing.T, user, userCode string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, sshConsentReadPath+"?user_code="+userCode, nil)
	if user != "" {
		r.Header.Set("X-Remote-User", user)
	}
	rec := httptest.NewRecorder()
	f.h.handleSSHConsentRead(rec, r)
	return rec
}

func (f *sshConsentFixture) post(t *testing.T, user string, body sshConsentDecision) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, sshConsentApprovePath, strings.NewReader(string(raw)))
	r.Header.Set("Content-Type", "application/json")
	if user != "" {
		r.Header.Set("X-Remote-User", user)
	}
	rec := httptest.NewRecorder()
	f.h.handleSSHConsentApprove(rec, r)
	return rec
}

func (f *sshConsentFixture) view(t *testing.T, user, userCode string) sshConsentView {
	t.Helper()
	rec := f.get(t, user, userCode)
	if rec.Code != http.StatusOK {
		t.Fatalf("read = %d: %s", rec.Code, rec.Body.String())
	}
	var v sshConsentView
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return v
}

// The redirect into the SPA has to be conditional on BOTH halves, and
// a test binary never has the frontend compiled in -- so the embedded
// flag is a parameter rather than a call to webui.IsEmbedded(). Read
// the inline version and both arms look identical from here: every
// case would return "" and the test could not fail.
func TestSSHConsentRedirectNeedsAnSSHLoginAndAnEmbeddedUI(t *testing.T) {
	for _, tc := range []struct {
		name     string
		session  string
		embedded bool
		want     string
	}{
		{"ssh login with a UI", "work", true, "/ssh/approve?user_code=ABCD-EFGH"},
		{"ssh login without a UI", "work", false, ""},
		{"not an ssh login", "", true, ""},
		{"neither", "", false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := sshConsentRedirect(tc.session, "ABCD-EFGH", tc.embedded); got != tc.want {
				t.Errorf("redirect = %q, want %q", got, tc.want)
			}
		})
	}
}

// The workspace name has to survive the whole round trip: into the
// device authorization, through the row, and back out by user code.
// It travelled on the request form, which the storage persisted and
// then threw away on the way back -- so the name reached the database
// and nothing could read it.
func TestTheRequestedWorkspaceSurvivesTheDeviceCodeRow(t *testing.T) {
	f := newSSHConsentFixture(t)
	userCode := f.startLogin(t, "work")

	_, request, err := f.storage.GetDeviceCodeSessionByUserCode(context.Background(), userCode)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if got := sshSessionFromRequester(request); got != "work" {
		t.Errorf("workspace = %q, want %q", got, "work")
	}
}

func TestADeviceCodeWithNoWorkspaceIsNotAnSSHLogin(t *testing.T) {
	f := newSSHConsentFixture(t)
	userCode := f.startLogin(t, "")

	_, request, err := f.storage.GetDeviceCodeSessionByUserCode(context.Background(), userCode)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if got := sshSessionFromRequester(request); got != "" {
		t.Errorf("workspace = %q, want none", got)
	}
	// And the endpoints refuse it, so this pair cannot be used to
	// approve the device codes the generic consent page owns.
	if rec := f.get(t, "alice", userCode); rec.Code != http.StatusNotFound {
		t.Errorf("read of a non-SSH code = %d, want 404", rec.Code)
	}
}

// A name that would not be accepted today must not be rendered or
// submitted today, whatever is in the row. The row is written by an
// endpoint that authenticates no client.
func TestAnUnusableWorkspaceNameIsNotHandedBack(t *testing.T) {
	for _, name := range []string{
		"../../etc/passwd",
		"has space",
		strings.Repeat("a", 65),
		"-leading",
	} {
		request := fosite.NewRequest()
		request.Form = map[string][]string{sshgateway.SessionFormField: {name}}
		if got := sshSessionFromRequester(request); got != "" {
			t.Errorf("%q was handed back as %q", name, got)
		}
	}
}

func TestSSHConsentNeedsABrowserIdentity(t *testing.T) {
	f := newSSHConsentFixture(t)
	userCode := f.startLogin(t, "work")

	if rec := f.get(t, "", userCode); rec.Code != http.StatusUnauthorized {
		t.Errorf("anonymous read = %d, want 401", rec.Code)
	}
	rec := f.post(t, "", sshConsentDecision{UserCode: userCode, Action: "approve"})
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("anonymous approve = %d, want 401", rec.Code)
	}
	// And the code is still waiting, so nothing was granted on the way
	// past the refusal.
	if !f.storage.DeviceCodeIsPending(context.Background(), userCode) {
		t.Error("an anonymous request decided the login")
	}
}

// The approval token is what stops a cross-site page from approving a
// login with a cookie it cannot read. It is handed out only in the
// body of the read endpoint, so an approval without one means the
// caller never loaded the screen.
func TestApprovingNeedsTheTokenFromTheScreen(t *testing.T) {
	f := newSSHConsentFixture(t)
	userCode := f.startLogin(t, "work")

	rec := f.post(t, "alice", sshConsentDecision{UserCode: userCode, Action: "approve"})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("approve with no token = %d, want 403: %s", rec.Code, rec.Body.String())
	}

	// The device code must still be waiting: a refused approval that
	// nonetheless flipped the row would be worse than useless.
	if !f.storage.DeviceCodeIsPending(context.Background(), userCode) {
		t.Fatal("a refused approval decided the login anyway")
	}

	v := f.view(t, "alice", userCode)
	if v.ApprovalToken == "" {
		t.Fatal("the screen was given no approval token")
	}
	rec = f.post(t, "alice", sshConsentDecision{
		UserCode: userCode, Action: "approve", ApprovalToken: v.ApprovalToken,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("approve with the token = %d: %s", rec.Code, rec.Body.String())
	}
}

// One user's token must not approve from another user's browser. The
// grant is issued to whoever approved, so a token that travelled would
// let a shared screenshot of a URL become somebody else's shell.
func TestAnApprovalTokenIsBoundToTheUserItWasIssuedTo(t *testing.T) {
	f := newSSHConsentFixture(t)
	userCode := f.startLogin(t, "work")

	alice := f.view(t, "alice", userCode)
	bob := f.view(t, "bob", userCode)
	if alice.ApprovalToken == bob.ApprovalToken {
		t.Fatal("two users were shown the same approval token")
	}

	rec := f.post(t, "bob", sshConsentDecision{
		UserCode: userCode, Action: "approve", ApprovalToken: alice.ApprovalToken,
	})
	if rec.Code != http.StatusForbidden {
		t.Errorf("bob approving with alice's token = %d, want 403", rec.Code)
	}
}

// And not to another code of the same user's, which is what a
// concatenated (rather than length-prefixed) MAC input would allow.
func TestAnApprovalTokenIsBoundToItsCode(t *testing.T) {
	f := newSSHConsentFixture(t)
	first := f.startLogin(t, "work")
	second := f.startLogin(t, "work")

	v := f.view(t, "alice", first)
	rec := f.post(t, "alice", sshConsentDecision{
		UserCode: second, Action: "approve", ApprovalToken: v.ApprovalToken,
	})
	if rec.Code != http.StatusForbidden {
		t.Errorf("approving a different code = %d, want 403", rec.Code)
	}
}

// Every code that is not waiting for a decision gets the same answer.
// Distinguishing "expired" or "already approved" from "never existed"
// tells a guesser that a code existed, which is the only expensive
// half of finding one.
func TestACodeThatIsNotPendingIsIndistinguishableFromOneThatNeverWas(t *testing.T) {
	f := newSSHConsentFixture(t)

	approved := f.startLogin(t, "work")
	v := f.view(t, "alice", approved)
	if rec := f.post(t, "alice", sshConsentDecision{
		UserCode: approved, Action: "approve", ApprovalToken: v.ApprovalToken,
	}); rec.Code != http.StatusOK {
		t.Fatalf("approve: %d %s", rec.Code, rec.Body.String())
	}

	denied := f.startLogin(t, "work")
	dv := f.view(t, "alice", denied)
	if rec := f.post(t, "alice", sshConsentDecision{
		UserCode: denied, Action: "deny", ApprovalToken: dv.ApprovalToken,
	}); rec.Code != http.StatusOK {
		t.Fatalf("deny: %d %s", rec.Code, rec.Body.String())
	}

	want := f.get(t, "alice", "ZZZZ-ZZZZ")
	if want.Code != http.StatusNotFound || !strings.Contains(want.Body.String(), sshConsentNotFound) {
		t.Fatalf("absent code = %d %s", want.Code, want.Body.String())
	}
	for name, code := range map[string]string{"approved": approved, "denied": denied} {
		got := f.get(t, "alice", code)
		if got.Code != want.Code || got.Body.String() != want.Body.String() {
			t.Errorf("an %s code answers %d %q; an absent one answers %d %q -- that pair is an oracle",
				name, got.Code, got.Body.String(), want.Code, want.Body.String())
		}
	}
}

// Guessing is bounded. The code is eight characters a human types, so
// the only thing keeping the space out of reach at scale is that a
// caller cannot try quickly.
func TestUserCodeGuessingIsRateLimited(t *testing.T) {
	f := newSSHConsentFixture(t)

	var limited bool
	for i := 0; i < sshConsentBurst+5; i++ {
		rec := f.get(t, "alice", "ZZZZ-ZZZZ")
		if rec.Code == http.StatusTooManyRequests {
			limited = true
			break
		}
	}
	if !limited {
		t.Fatalf("%d failed lookups were all allowed", sshConsentBurst+5)
	}
}

// A different signed-in user must not get a fresh budget from the same
// address, or the per-user limit would be a formality.
func TestTheAddressBudgetIsSpentByEveryUser(t *testing.T) {
	f := newSSHConsentFixture(t)

	for i := 0; i < sshConsentBurst; i++ {
		f.get(t, "alice", "ZZZZ-ZZZZ")
	}
	if rec := f.get(t, "bob", "ZZZZ-ZZZZ"); rec.Code != http.StatusTooManyRequests {
		t.Errorf("a second user from the same address = %d, want 429", rec.Code)
	}
}

func TestApproveRefusesACrossSitePost(t *testing.T) {
	f := newSSHConsentFixture(t)
	userCode := f.startLogin(t, "work")
	v := f.view(t, "alice", userCode)

	body, _ := json.Marshal(sshConsentDecision{
		UserCode: userCode, Action: "approve", ApprovalToken: v.ApprovalToken,
	})
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, sshConsentApprovePath, strings.NewReader(string(body)))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Remote-User", "alice")
	r.Header.Set("Origin", "https://evil.example")
	rec := httptest.NewRecorder()
	f.h.handleSSHConsentApprove(rec, r)
	if rec.Code != http.StatusForbidden {
		t.Errorf("cross-site approve = %d, want 403", rec.Code)
	}
}

func TestApproveRefusesAFormContentType(t *testing.T) {
	f := newSSHConsentFixture(t)
	userCode := f.startLogin(t, "work")
	v := f.view(t, "alice", userCode)

	body, _ := json.Marshal(sshConsentDecision{
		UserCode: userCode, Action: "approve", ApprovalToken: v.ApprovalToken,
	})
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, sshConsentApprovePath, strings.NewReader(string(body)))
	// What a cross-site <form> can send without a preflight.
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("X-Remote-User", "alice")
	rec := httptest.NewRecorder()
	f.h.handleSSHConsentApprove(rec, r)
	if rec.Code != http.StatusUnsupportedMediaType {
		t.Errorf("form-encoded approve = %d, want 415", rec.Code)
	}
}

func TestDenyingLeavesNothingApproved(t *testing.T) {
	f := newSSHConsentFixture(t)
	userCode := f.startLogin(t, "work")
	v := f.view(t, "alice", userCode)

	rec := f.post(t, "alice", sshConsentDecision{
		UserCode: userCode, Action: "deny", ApprovalToken: v.ApprovalToken,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("deny = %d: %s", rec.Code, rec.Body.String())
	}
	var result sshConsentResult
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if result.Approved {
		t.Error("a refusal came back approved")
	}
	if f.storage.DeviceCodeIsPending(context.Background(), userCode) {
		t.Error("a refusal left the login waiting")
	}
}

// The screen opens on what the gateway would have submitted by itself,
// so the numbers shown are the ones about to be used.
func TestTheFormOpensOnTheOperatorsOwnDefaults(t *testing.T) {
	f := newSSHConsentFixture(t)
	f.h.sshGatewaySessionSpec = sshGatewaySessionSize{Cpus: 4, MemoryMB: 16384}
	userCode := f.startLogin(t, "work")

	v := f.view(t, "alice", userCode)
	if v.Defaults.Cpus != 4 || v.Defaults.MemoryMB != 16384 {
		t.Errorf("defaults = %+v, want the configured 4 cpus / 16384 MiB", v.Defaults)
	}
	// Disk was not configured, so the interactive package's own default
	// fills it rather than a zero the server would silently replace.
	if v.Defaults.DiskMB == 0 {
		t.Error("the form would open showing a disk request of zero")
	}
}

// Creating is refused where there is nothing to create with, rather
// than approving and leaving the terminal with nothing to attach to
// and no explanation.
func TestCreatingNeedsAnInteractiveManager(t *testing.T) {
	f := newSSHConsentFixture(t)
	_, _, err := f.h.sshConsentCreateSession(
		context.Background(), "alice", "work", InteractiveCreateTerminalRequest{})
	if err == nil {
		t.Fatal("a session was created with no manager")
	}
	if !strings.Contains(err.Error(), "interactive sessions") {
		t.Errorf("the refusal does not say what is missing: %v", err)
	}
}

func TestRequireSameOrigin(t *testing.T) {
	h := &Handler{httpBaseURL: "https://ap.example.edu"}
	for _, tc := range []struct {
		name, origin, host string
		ok                 bool
	}{
		{"absent", "", "ap.example.edu", true},
		{"same host", "http://ap.example.edu", "ap.example.edu", true},
		{"configured base", "https://ap.example.edu", "127.0.0.1:8080", true},
		{"elsewhere", "https://evil.example", "ap.example.edu", false},
		{"unparseable", "::", "ap.example.edu", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/x", nil)
			r.Host = tc.host
			if tc.origin != "" {
				r.Header.Set("Origin", tc.origin)
			}
			if err := h.requireSameOrigin(r); (err == nil) != tc.ok {
				t.Errorf("requireSameOrigin(%q, host %q) = %v, want ok=%v",
					tc.origin, tc.host, err, tc.ok)
			}
		})
	}
}

// Creation runs BEFORE the approval is recorded, and a creation that
// fails must leave the login waiting.
//
// The ordering is the whole design. The gateway's poll returns the
// instant the row flips to approved and it then looks for the
// workspace; approving first would hand it a grant for a session that
// does not exist, and it would make a second one. Approving anyway
// after a failed create would do the same thing with a worse story --
// the user consented to a configuration they did not get.
func TestAFailedCreateLeavesTheLoginWaiting(t *testing.T) {
	f := newSSHConsentFixture(t)
	userCode := f.startLogin(t, "work")
	v := f.view(t, "alice", userCode)

	rec := f.post(t, "alice", sshConsentDecision{
		UserCode:      userCode,
		Action:        "approve",
		ApprovalToken: v.ApprovalToken,
		// Past the validator's ceiling, so the request is refused
		// before anything is submitted or approved.
		Create: &InteractiveCreateTerminalRequest{Cpus: 10000},
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("approve with an impossible request = %d, want 400: %s", rec.Code, rec.Body.String())
	}
	// Named explicitly, so this cannot pass because the fixture has no
	// interactive manager -- which would make it a test of nothing.
	if !strings.Contains(rec.Body.String(), "cpus") {
		t.Fatalf("the refusal is not the validation one: %s", rec.Body.String())
	}
	if !f.storage.DeviceCodeIsPending(context.Background(), userCode) {
		t.Error("the login was approved even though the workspace was not created")
	}
}
