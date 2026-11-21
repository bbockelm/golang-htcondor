package mockgoogle

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// The mock is itself a thing that can be wrong, and a wrong mock makes
// every test above it green and meaningless. These tests hold it to the
// documented behaviours its package comment cites.

const (
	clientID     = "1234.apps.googleusercontent.com"
	clientSecret = "s3cret"
	redirectURI  = "https://ap.example.org/api/v1/connect/builtin:gdrive/callback"
)

// get and postForm build requests that carry the test's context, which
// is what noctx asks for and what makes a hung mock fail the test
// rather than the suite.
func get(t *testing.T, client *http.Client, rawURL string, hdr map[string]string) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, rawURL, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", rawURL, err)
	}
	return resp
}

func postForm(t *testing.T, rawURL string, form url.Values) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, rawURL,
		strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", rawURL, err)
	}
	return resp
}

func newMock(t *testing.T) *Server {
	t.Helper()
	return New(t, Config{ClientID: clientID, ClientSecret: clientSecret, RedirectURI: redirectURI})
}

// noRedirect keeps the client from following the authorization
// redirect, so a test can read the Location it was given.
func noRedirect() *http.Client {
	return &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func authorize(t *testing.T, s *Server, extra url.Values) *url.URL {
	t.Helper()
	q := url.Values{
		"client_id":     {clientID},
		"redirect_uri":  {redirectURI},
		"response_type": {"code"},
		"scope":         {"https://www.googleapis.com/auth/drive.file"},
		"state":         {"xyz"},
	}
	for k, vs := range extra {
		q[k] = vs
	}
	resp := get(t, noRedirect(), s.AuthorizationURL()+"?"+q.Encode(), nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("authorize: status %d, body %s", resp.StatusCode, body)
	}
	loc, err := resp.Location()
	if err != nil {
		t.Fatalf("no Location: %v", err)
	}
	return loc
}

func postToken(t *testing.T, s *Server, form url.Values) (int, map[string]any) {
	t.Helper()
	resp := postForm(t, s.TokenURL(), form)
	defer func() { _ = resp.Body.Close() }()
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	return resp.StatusCode, body
}

// --- the authorization endpoint ---------------------------------------

func TestAuthorizationReturnsStateUnchanged(t *testing.T) {
	s := newMock(t)
	loc := authorize(t, s, nil)
	if got := loc.Query().Get("state"); got != "xyz" {
		t.Errorf("state = %q, want it returned exactly as given", got)
	}
	if loc.Query().Get("code") == "" {
		t.Error("no code in the redirect")
	}
}

// A redirect_uri that does not match is refused WITHOUT redirecting.
// Bouncing an error to an unregistered URI would make this an open
// redirector, which is the bug the check exists to prevent.
func TestUnregisteredRedirectURIIsNotRedirectedTo(t *testing.T) {
	s := newMock(t)
	q := url.Values{
		"client_id":     {clientID},
		"redirect_uri":  {"https://evil.example.net/steal"},
		"response_type": {"code"},
		"scope":         {"x"},
	}
	resp := get(t, noRedirect(), s.AuthorizationURL()+"?"+q.Encode(), nil)
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusFound {
		loc, _ := resp.Location()
		t.Fatalf("redirected to %v; an unregistered redirect_uri must not be redirected to", loc)
	}
	var body map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if body["error"] != "redirect_uri_mismatch" {
		t.Errorf("error = %v, want redirect_uri_mismatch", body["error"])
	}
}

func TestUserCancellingGivesAccessDenied(t *testing.T) {
	s := newMock(t)
	s.DenyAuthorization(true)
	loc := authorize(t, s, nil)
	if got := loc.Query().Get("error"); got != "access_denied" {
		t.Errorf("error = %q, want access_denied", got)
	}
	if loc.Query().Get("code") != "" {
		t.Error("a code was issued despite the denial")
	}
}

// --- the code exchange ------------------------------------------------

func TestCodeExchangeReturnsTheDocumentedFields(t *testing.T) {
	s := newMock(t)
	loc := authorize(t, s, url.Values{"access_type": {"offline"}})

	status, body := postToken(t, s, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {loc.Query().Get("code")},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"redirect_uri":  {redirectURI},
	})
	if status != http.StatusOK {
		t.Fatalf("status %d: %v", status, body)
	}
	for _, field := range []string{"access_token", "expires_in", "token_type", "scope", "refresh_token"} {
		if _, ok := body[field]; !ok {
			t.Errorf("response is missing %q", field)
		}
	}
	if body["token_type"] != "Bearer" {
		t.Errorf("token_type = %v, want Bearer always", body["token_type"])
	}
}

// The refresh token comes back only when the authorization request
// asked for offline access. An application that forgets access_type
// gets a working access token and nothing that outlives it, which is a
// failure that shows up an hour later rather than at once.
func TestRefreshTokenOnlyWithOfflineAccess(t *testing.T) {
	s := newMock(t)

	loc := authorize(t, s, nil) // no access_type
	_, body := postToken(t, s, url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {loc.Query().Get("code")},
		"client_id":    {clientID},
		"redirect_uri": {redirectURI},
	})
	if _, ok := body["refresh_token"]; ok {
		t.Error("a refresh token came back without access_type=offline")
	}

	loc = authorize(t, s, url.Values{"access_type": {"offline"}})
	_, body = postToken(t, s, url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {loc.Query().Get("code")},
		"client_id":    {clientID},
		"redirect_uri": {redirectURI},
	})
	if _, ok := body["refresh_token"]; !ok {
		t.Error("no refresh token with access_type=offline")
	}
}

func TestAuthorizationCodeIsSingleUse(t *testing.T) {
	s := newMock(t)
	loc := authorize(t, s, url.Values{"access_type": {"offline"}})
	form := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {loc.Query().Get("code")},
		"client_id":    {clientID},
		"redirect_uri": {redirectURI},
	}

	if status, body := postToken(t, s, form); status != http.StatusOK {
		t.Fatalf("first exchange failed: %d %v", status, body)
	}
	status, body := postToken(t, s, form)
	if status == http.StatusOK {
		t.Fatal("the same authorization code was redeemed twice")
	}
	if body["error"] != "invalid_grant" {
		t.Errorf("error = %v, want invalid_grant", body["error"])
	}
}

func TestRedirectURIMustMatchAtTheExchange(t *testing.T) {
	s := newMock(t)
	loc := authorize(t, s, nil)
	status, body := postToken(t, s, url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {loc.Query().Get("code")},
		"client_id":    {clientID},
		"redirect_uri": {"https://ap.example.org/elsewhere"},
	})
	if status == http.StatusOK {
		t.Fatal("a mismatched redirect_uri was accepted")
	}
	if body["error"] != "redirect_uri_mismatch" {
		t.Errorf("error = %v", body["error"])
	}
}

func TestWrongClientSecretIsRefused(t *testing.T) {
	s := newMock(t)
	loc := authorize(t, s, nil)
	status, body := postToken(t, s, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {loc.Query().Get("code")},
		"client_id":     {clientID},
		"client_secret": {"wrong"},
		"redirect_uri":  {redirectURI},
	})
	if status == http.StatusOK {
		t.Fatal("a wrong client_secret was accepted")
	}
	if body["error"] != "invalid_client" {
		t.Errorf("error = %v, want invalid_client", body["error"])
	}
}

// PKCE is verified when the authorization request carried a challenge,
// and not required when it did not -- Google's web-server page documents
// no PKCE, so the mock must not insist on it.
func TestPKCEIsVerifiedWhenOfferedAndNotRequiredOtherwise(t *testing.T) {
	s := newMock(t)
	verifier := "a-verifier-long-enough-to-be-real"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	loc := authorize(t, s, url.Values{
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	})
	form := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {loc.Query().Get("code")},
		"client_id":    {clientID},
		"redirect_uri": {redirectURI},
	}

	bad := cloneValues(form)
	bad.Set("code_verifier", "not-the-verifier")
	if status, _ := postToken(t, s, bad); status == http.StatusOK {
		t.Fatal("a wrong code_verifier was accepted")
	}

	// The code is still unused: a failed PKCE check must not burn it,
	// or a retry with the right verifier could never succeed.
	good := cloneValues(form)
	good.Set("code_verifier", verifier)
	if status, body := postToken(t, s, good); status != http.StatusOK {
		t.Fatalf("the right verifier was refused: %d %v", status, body)
	}

	// And a flow with no challenge needs no verifier.
	loc2 := authorize(t, s, nil)
	if status, body := postToken(t, s, url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {loc2.Query().Get("code")},
		"client_id":    {clientID},
		"redirect_uri": {redirectURI},
	}); status != http.StatusOK {
		t.Fatalf("a flow without PKCE was refused: %d %v", status, body)
	}
}

func cloneValues(v url.Values) url.Values {
	out := url.Values{}
	for k, vs := range v {
		out[k] = append([]string(nil), vs...)
	}
	return out
}

// --- refresh ----------------------------------------------------------

func connect(t *testing.T, s *Server) (accessToken, refreshToken string) {
	t.Helper()
	loc := authorize(t, s, url.Values{"access_type": {"offline"}})
	_, body := postToken(t, s, url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {loc.Query().Get("code")},
		"client_id":    {clientID},
		"redirect_uri": {redirectURI},
	})
	at, _ := body["access_token"].(string)
	rt, _ := body["refresh_token"].(string)
	if at == "" || rt == "" {
		t.Fatalf("connect: got access=%q refresh=%q", at, rt)
	}
	return at, rt
}

// A refresh returns no refresh_token. Google's page does not say that
// one comes back and its example does not show one, so the mock does
// what the documentation shows. A connector depending on a new refresh
// token here is depending on something undocumented, and this is where
// it finds out.
func TestRefreshReturnsNoNewRefreshToken(t *testing.T) {
	s := newMock(t)
	_, rt := connect(t, s)

	status, body := postToken(t, s, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {rt},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
	})
	if status != http.StatusOK {
		t.Fatalf("refresh failed: %d %v", status, body)
	}
	if _, ok := body["refresh_token"]; ok {
		t.Error("a refresh returned a new refresh_token, which the documentation does not show")
	}
	if body["access_token"] == "" {
		t.Error("no new access token")
	}
}

func TestRevokedRefreshTokenGivesInvalidGrant(t *testing.T) {
	s := newMock(t)
	_, rt := connect(t, s)
	s.Revoke(rt)

	status, body := postToken(t, s, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {rt},
		"client_id":     {clientID},
	})
	if status == http.StatusOK {
		t.Fatal("a revoked refresh token still worked")
	}
	if body["error"] != "invalid_grant" {
		t.Errorf("error = %v, want invalid_grant", body["error"])
	}
}

func TestRevocationEndpointRevokes(t *testing.T) {
	s := newMock(t)
	_, rt := connect(t, s)

	resp := postForm(t, s.RevokeURL(), url.Values{"token": {rt}})
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("revoke: status %d, want 200", resp.StatusCode)
	}

	if status, _ := postToken(t, s, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {rt},
		"client_id":     {clientID},
	}); status == http.StatusOK {
		t.Error("the token still worked after revocation")
	}
}

// --- Drive ------------------------------------------------------------

func TestDriveReadsAPickedFile(t *testing.T) {
	s := newMock(t)
	at, _ := connect(t, s)
	s.PickFile("FILEID", "data.csv", []byte("a,b,c\n"))

	resp := get(t, http.DefaultClient, s.DriveBaseURL()+"/files/FILEID?alt=media",
		map[string]string{"Authorization": "Bearer " + at})
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
	if string(body) != "a,b,c\n" {
		t.Errorf("body = %q", body)
	}
}

// An unpicked file is 404, not 403: under drive.file a file the
// application was never granted does not exist as far as it is
// concerned. That distinction is what the plugin explains in a hold
// reason, so the mock has to make it.
func TestUnpickedFileIsNotFoundNotForbidden(t *testing.T) {
	s := newMock(t)
	at, _ := connect(t, s)

	resp := get(t, http.DefaultClient, s.DriveBaseURL()+"/files/NEVERPICKED?alt=media",
		map[string]string{"Authorization": "Bearer " + at})
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status %d, want 404", resp.StatusCode)
	}
	var body struct {
		Error struct {
			Message string `json:"message"`
			Errors  []struct {
				Reason string `json:"reason"`
			} `json:"errors"`
		} `json:"error"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if len(body.Error.Errors) == 0 || body.Error.Errors[0].Reason != "notFound" {
		t.Errorf("error body = %+v, want Drive's shape with reason notFound", body)
	}
}

func TestDriveRefusesAnUnknownBearer(t *testing.T) {
	s := newMock(t)
	s.PickFile("FILEID", "data.csv", []byte("x"))

	resp := get(t, http.DefaultClient, s.DriveBaseURL()+"/files/FILEID?alt=media",
		map[string]string{"Authorization": "Bearer not-a-token"})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status %d, want 401", resp.StatusCode)
	}
}

func TestFailNextDrivesRetryPaths(t *testing.T) {
	s := newMock(t)
	s.FailNext(http.StatusTooManyRequests)

	resp := postForm(t, s.TokenURL(), url.Values{"grant_type": {"refresh_token"}})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("status %d, want the rigged 429", resp.StatusCode)
	}
	if len(s.nextStatuses) != 0 {
		t.Error("the rigged status was not consumed")
	}
}

func TestListOnlyShowsPickedFiles(t *testing.T) {
	s := newMock(t)
	at, _ := connect(t, s)
	s.PickFile("A", "a.txt", []byte("a"))

	resp := get(t, http.DefaultClient,
		s.DriveBaseURL()+"/files?q="+url.QueryEscape("name = 'b.txt'"),
		map[string]string{"Authorization": "Bearer " + at})
	defer func() { _ = resp.Body.Close() }()

	var body struct {
		Files []struct{ ID, Name string } `json:"files"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if len(body.Files) != 1 || body.Files[0].Name != "a.txt" {
		t.Errorf("files = %+v; drive.file narrows a listing to what was picked", body.Files)
	}
}

// The package comment claims these endpoints stand in for Google's. If
// the paths drift from the documented ones the mock stops being a
// stand-in for anything.
func TestEndpointPathsMatchGoogles(t *testing.T) {
	s := newMock(t)
	for _, tc := range []struct{ got, wantSuffix string }{
		{s.AuthorizationURL(), "/o/oauth2/v2/auth"},
		{s.TokenURL(), "/token"},
		{s.RevokeURL(), "/revoke"},
		{s.DriveBaseURL(), "/drive/v3"},
	} {
		if !strings.HasSuffix(tc.got, tc.wantSuffix) {
			t.Errorf("%q does not end in %q", tc.got, tc.wantSuffix)
		}
	}
}
