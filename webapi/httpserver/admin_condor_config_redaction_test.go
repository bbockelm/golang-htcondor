package httpserver

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/golang-htcondor/config"
)

// The admin config readout hides secrets by the knob's name and by the
// look of its value, shows everything else, and hides none of
// HTCondor's own defaults for the look of them.
func TestAdminCondorConfigRedactsKeyMaterial(t *testing.T) {
	const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.c2lnbmF0dXJlLWJ5dGVz"
	cfg, err := config.NewFromReader(strings.NewReader(strings.Join([]string{
		"APP_DB_KEK = shown-only-by-its-name",
		"SESSION_SALT = shown-only-by-its-name",
		"ODD_KNOB_HEX = 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
		"ODD_KNOB_B64 = q83vEjRWeJq8m3o9YzF6dGhpc2lzbm90YXJlYWxrZXlidXRsb29rc2xpa2VvbmU",
		"ODD_KNOB_JWT = " + jwt,
		"ODD_KNOB_PEM = -----BEGIN PRIVATE KEY----- MIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7",
		"PLAIN_PATH = /etc/condor/passwords.d/POOL",
		"PLAIN_EXPR = (TARGET.Memory > 1024) && (MY.Owner =!= \"nobody\")",
	}, "\n")))
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	tc := newTestConfig(t)
	tc.HTCondorConfig = cfg
	s, err := NewServer(tc)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	s.webuiAdminGroups = newGroupSet("condor-admins")
	// Routes are registered in Start.
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	if err := s.Handler.Start(t.Context(), ln, "http"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.Shutdown(ctx)
	})
	sid, _, err := s.sessionStore.Create("operator", []string{"condor-admins"})
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/admin/condor-config", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sid}) //nolint:gosec // test cookie
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET condor-config: %d %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "shown-only-by-its-name") || strings.Contains(w.Body.String(), jwt) {
		t.Errorf("a secret value reached the readout")
	}

	var resp AdminCondorConfigResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	got := make(map[string]AdminCondorConfigEntry, len(resp.Entries))
	defaults := 0
	for _, e := range resp.Entries {
		got[strings.ToUpper(e.Key)] = e
		if e.IsDefault {
			defaults++
		}
		if e.IsDefault && e.Redacted && !sensitiveCondorKeyPattern.MatchString(e.Key) {
			t.Errorf("default %s was redacted for the look of its value", e.Key)
		}
	}
	if defaults < 500 {
		t.Fatalf("precondition: only %d default entries, so the defaults were not checked", defaults)
	}
	for _, k := range []string{"APP_DB_KEK", "SESSION_SALT", "ODD_KNOB_HEX", "ODD_KNOB_B64", "ODD_KNOB_JWT", "ODD_KNOB_PEM"} {
		if e, ok := got[k]; !ok || !e.Redacted || e.Value != "" {
			t.Errorf("%s: %+v, want redacted", k, e)
		}
	}
	for _, k := range []string{"PLAIN_PATH", "PLAIN_EXPR"} {
		if e, ok := got[k]; !ok || e.Redacted || e.Value == "" {
			t.Errorf("%s: %+v, want shown", k, e)
		}
	}
}
