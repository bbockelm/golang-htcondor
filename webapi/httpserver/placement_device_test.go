package httpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/golang-htcondor/webapi/httpserver/appdb/seal"
)

// The expected bodies and headers in this file are byte-for-byte what
// placement-webapp (Flask 3.1 + authlib 1.8.0, pdwebapp/auth/device.py)
// writes for the same requests; they were captured from that stack.
// placement-client and curl scripts parse exactly these.

const devicePollForm = "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code"

type deviceHarness struct {
	*onboardingServer
	now time.Time
}

func newDeviceHarness(t *testing.T) *deviceHarness {
	t.Helper()
	h := &deviceHarness{onboardingServer: newOnboardingServer(t, newOnboardFake()), now: time.Unix(1700000000, 0)}
	h.httpBaseURL = "https://ap.example"
	h.placementOnboard.devices.now = func() time.Time { return h.now }
	return h
}

func (h *deviceHarness) post(t *testing.T, form string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/auth/device_authorization", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func (h *deviceHarness) issue(t *testing.T) (deviceCode, userCode string) {
	t.Helper()
	rec := h.post(t, "client_id=placement_client")
	var got map[string]any
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &got) != nil {
		t.Fatalf("issue: %d %s", rec.Code, rec.Body.String())
	}
	return got["device_code"].(string), got["user_code"].(string)
}

func (h *deviceHarness) poll(t *testing.T, clientID, deviceCode string) *httptest.ResponseRecorder {
	t.Helper()
	return h.post(t, devicePollForm+"&client_id="+url.QueryEscape(clientID)+"&device_code="+url.QueryEscape(deviceCode))
}

func assertGolden(t *testing.T, name string, rec *httptest.ResponseRecorder, status int, body string) {
	t.Helper()
	if rec.Code != status || rec.Body.String() != body {
		t.Errorf("%s:\n got %d %q\nwant %d %q", name, rec.Code, rec.Body.String(), status, body)
	}
	for k, want := range map[string]string{"Content-Type": "application/json", "Cache-Control": "no-store", "Pragma": "no-cache"} {
		if got := rec.Header().Get(k); got != want {
			t.Errorf("%s: %s = %q, want %q", name, k, got, want)
		}
	}
}

func TestPlacementDeviceIssueGolden(t *testing.T) {
	h := newDeviceHarness(t)
	rec := h.post(t, "client_id=placement_client")
	var got map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	dc, _ := got["device_code"].(string)
	uc, _ := got["user_code"].(string)
	if len(dc) != 42 || strings.Trim(dc, placementDeviceCodeAlphabet) != "" {
		t.Errorf("device_code %q is not 42 characters of [A-Za-z0-9]", dc)
	}
	if !placementUserCodeRE.MatchString(uc) || strings.Trim(strings.ReplaceAll(uc, "-", ""), placementUserCodeAlphabet) != "" {
		t.Errorf("user_code %q is not XXXX-XXXX in authlib's alphabet", uc)
	}
	want := `{"device_code": "` + dc + `", "expires_in": 1800, "interval": 5, "user_code": "` + uc +
		`", "verification_uri": "https://ap.example/auth/code", "verification_uri_complete": "https://ap.example/auth/code?user_code=` + uc + `"}`
	assertGolden(t, "issue", rec, http.StatusOK, want)
}

func TestPlacementDevicePollingGolden(t *testing.T) {
	h := newDeviceHarness(t)
	dc, uc := h.issue(t)

	assertGolden(t, "first poll", h.poll(t, "placement_client", dc), 400, `{"error": "authorization_pending"}`)
	assertGolden(t, "immediate second poll", h.poll(t, "placement_client", dc), 400, `{"error": "slow_down"}`)
	h.now = h.now.Add(5 * time.Second)
	assertGolden(t, "poll after interval", h.poll(t, "placement_client", dc), 400, `{"error": "authorization_pending"}`)
	// Four seconds after the last poll is within the one second of slack.
	h.now = h.now.Add(4 * time.Second)
	assertGolden(t, "poll one second early", h.poll(t, "placement_client", dc), 400, `{"error": "authorization_pending"}`)

	assertGolden(t, "unknown device code", h.poll(t, "placement_client", "nope"), 400,
		`{"error": "invalid_request", "error_description": "Invalid 'device_code' in payload"}`)
	assertGolden(t, "another client's device code", h.poll(t, "curl", dc), 400, `{"error": "unauthorized_client"}`)

	// Approve through the user endpoint, as the confirmation page does.
	rec := h.do(t, h.placementCookie(t, aliceIdentity), http.MethodPost, "/api/v1/placement/me/token",
		`{"project":"ProjA","authorizations":["READ"],"user_code":"`+strings.ToLower(uc)+`"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("approve: %d %s", rec.Code, rec.Body.String())
	}
	var approved placementMeTokenResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &approved)
	if approved.Token != "" || approved.Device == nil || approved.Device.ClientName != "Placement Client" {
		t.Errorf("a device approval returned %+v; the token must go to the device only", approved)
	}

	token := testPlacementJWT(aliceIdentity, h.fake.tokenExp)
	expiresIn := h.fake.tokenExp.Unix() - h.now.Unix()
	assertGolden(t, "success", h.poll(t, "placement_client", dc), 200,
		`{"access_token": "`+token+`\n", "expires_in": "`+strconv.FormatInt(expiresIn, 10)+`", "token_type": "Placement"}`)
	// Delivered once, then forgotten.
	assertGolden(t, "after delivery", h.poll(t, "placement_client", dc), 400,
		`{"error": "invalid_request", "error_description": "Invalid 'device_code' in payload"}`)
}

func TestPlacementDeviceDeniedAndExpiredGolden(t *testing.T) {
	h := newDeviceHarness(t)
	dc, uc := h.issue(t)
	rec := h.do(t, h.placementCookie(t, aliceIdentity), http.MethodPost, "/api/v1/placement/me/device/"+uc+"/deny", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("deny: %d %s", rec.Code, rec.Body.String())
	}
	assertGolden(t, "denied", h.poll(t, "placement_client", dc), 400,
		`{"error": "access_denied", "error_description": "The resource owner or authorization server denied the request"}`)

	dc2, _ := h.issue(t)
	h.now = h.now.Add(1801 * time.Second)
	assertGolden(t, "expired", h.poll(t, "placement_client", dc2), 400, `{"error": "expired_token"}`)
}

func TestPlacementDeviceClientAuthGolden(t *testing.T) {
	h := newDeviceHarness(t)
	assertGolden(t, "unknown client", h.post(t, "client_id=evil"), 400,
		`{"error": "invalid_client", "error_description": "The client does not exist on this server."}`)
	rec := h.post(t, "")
	assertGolden(t, "no client", rec, 401,
		`{"error": "invalid_client", "error_description": "The client cannot authenticate with methods: ['client_secret_basic', 'client_secret_post', 'none']"}`)
	if got, want := rec.Header().Get("WWW-Authenticate"),
		`Basic error="invalid_client", error_description="The client cannot authenticate with methods: ['client_secret_basic', 'client_secret_post', 'none']"`; got != want {
		t.Errorf("WWW-Authenticate = %q, want %q", got, want)
	}
}

// pdwebapp's token body when the token carries no expiry omits expires_in.
func TestPlacementDeviceSuccessWithoutExpiryGolden(t *testing.T) {
	h := newDeviceHarness(t)
	dc, uc := h.issue(t)
	if err := h.placementOnboard.devices.approve(context.Background(), uc, aliceIdentity, "eyJ.payload.sig", 0); err != nil {
		t.Fatal(err)
	}
	assertGolden(t, "no exp", h.poll(t, "placement_client", dc), 200,
		`{"access_token": "eyJ.payload.sig\n", "token_type": "Placement"}`)
}

func TestPlacementDeviceCodeRedirects(t *testing.T) {
	h := newDeviceHarness(t)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/auth/code?user_code=BCDF-GHJK", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/placement/device?user_code=BCDF-GHJK" {
		t.Errorf("%d Location=%q", rec.Code, rec.Header().Get("Location"))
	}
}

func TestPlacementDeviceCancelForm(t *testing.T) {
	h := newDeviceHarness(t)
	dc, uc := h.issue(t)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/auth/cancel_device",
		strings.NewReader("user_code="+uc))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("cancel without a session: %d", rec.Code)
	}
	req = httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/auth/cancel_device",
		strings.NewReader("user_code="+uc))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(h.placementCookie(t, aliceIdentity))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("cancel: %d %s", rec.Code, rec.Body.String())
	}
	if got := h.poll(t, "placement_client", dc); !strings.Contains(got.Body.String(), "access_denied") {
		t.Errorf("poll after cancel: %s", got.Body.String())
	}
}

func TestPlacementDeviceTokenIsSealedAtRest(t *testing.T) {
	h := newDeviceHarness(t)
	sealer, err := seal.New(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	h.placementOnboard.devices.sealer = sealer
	dc, uc := h.issue(t)
	if err := h.placementOnboard.devices.approve(context.Background(), uc, aliceIdentity, "secret.token.value", 0); err != nil {
		t.Fatal(err)
	}
	var stored []byte
	if err := h.db.QueryRowContext(context.Background(),
		`SELECT token_sealed FROM placement_device_grants WHERE user_code = ?`, uc).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(stored), "secret.token.value") {
		t.Error("the device token is stored in the clear")
	}
	assertGolden(t, "sealed delivery", h.poll(t, "placement_client", dc), 200,
		`{"access_token": "secret.token.value\n", "token_type": "Placement"}`)
}

func TestPyJSONMatchesPythonEscaping(t *testing.T) {
	got := string(pyJSON(map[string]any{"b": "é\"\\\n\x01😀/", "a": 5}))
	// json.dumps({"b": "é\"\\\n\x01😀/", "a": 5}, sort_keys=True)
	want := `{"a": 5, "b": "\u00e9\"\\\n\u0001\ud83d\ude00/"}`
	if got != want {
		t.Errorf("pyJSON = %s, want %s", got, want)
	}
}
