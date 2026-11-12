package httpserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

func noSSHHandler(t *testing.T) *Handler {
	t.Helper()
	h := &Handler{logger: newTestLogger(t)}
	h.sshToJobOff.Store(true)
	// The job routes authenticate before they dispatch, so an
	// unauthenticated request never reaches the gate under test. The
	// signing key is what mints the per-request token the header path
	// hands back.
	h.userHeader = "X-Remote-User"
	h.userHeaderUnsafeAllowAll = true
	h.signingKeyPath = writeTestSigningKey(t)
	h.trustDomain = "test.domain"
	h.uidDomain = "d"
	return h
}

func asAlice(method, path string) *http.Request {
	r := httptest.NewRequest(method, path, nil)
	r.Header.Set("X-Remote-User", "alice")
	return r
}

// Every way into a running job is refused, and each refusal names the
// setting -- the operator reading a user's screenshot is the one who
// can change it.
func TestReachingIntoAJobIsRefusedWhereTheSiteForbidsIt(t *testing.T) {
	for _, tc := range []struct {
		name   string
		method string
		path   string
	}{
		{"terminal", http.MethodGet, "/api/v1/jobs/12.0/ssh"},
		{"warm", http.MethodPost, "/api/v1/jobs/12.0/warm"},
		{"proxy", http.MethodGet, "/api/v1/jobs/12.0/proxy/8080/"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := noSSHHandler(t)
			w := httptest.NewRecorder()
			h.handleJobByID(w, asAlice(tc.method, tc.path))

			if w.Code != http.StatusServiceUnavailable {
				t.Errorf("status = %d, want %d", w.Code, http.StatusServiceUnavailable)
			}
			if !strings.Contains(w.Body.String(), "HTTP_API_SSH_TO_JOB") {
				t.Errorf("the refusal does not name the setting: %s", w.Body.String())
			}
		})
	}
}

// The certificate and consent endpoints serve a gateway that does not
// run, so they go with it.
func TestTheGatewaysOwnEndpointsRefuseToo(t *testing.T) {
	for _, tc := range []struct {
		name   string
		method string
		path   string
		fn     func(*Handler, http.ResponseWriter, *http.Request)
	}{
		{"ca", http.MethodGet, "/api/v1/ssh/ca", (*Handler).handleSSHCA},
		{"certificate", http.MethodPost, "/api/v1/ssh/certificate", (*Handler).handleSSHCertificate},
		{"consent read", http.MethodGet, sshConsentReadPath, (*Handler).handleSSHConsentRead},
		{"consent approve", http.MethodPost, sshConsentApprovePath, (*Handler).handleSSHConsentApprove},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := noSSHHandler(t)
			w := httptest.NewRecorder()
			tc.fn(h, w, httptest.NewRequest(tc.method, tc.path, nil))
			if w.Code != http.StatusServiceUnavailable {
				t.Errorf("status = %d, want %d", w.Code, http.StatusServiceUnavailable)
			}
		})
	}
}

// The two applications that work by reaching into a job go with it,
// and the one that does not stays. A site cannot be expected to find
// and set three settings to express one policy.
func TestForbiddingSSHWithdrawsTheApplicationsBuiltOnIt(t *testing.T) {
	h, err := NewHandler(HandlerConfig{
		SSHToJobDisabled: true,
		ScheddAddr:       "127.0.0.1:9618",
		OAuth2DBPath:     migratedAppDB(t),
		Logger:           newTestLogger(t),
	})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	if got := h.interactive.offered(); !slices.Equal(got, []string{"jupyter"}) {
		t.Errorf("offered = %v, want only jupyter: VS Code is served through the job proxy and a terminal IS an ssh session, "+
			"while JupyterLab's tunnel is dialled out of the sandbox", got)
	}
	if h.sshToJobEnabled() {
		t.Error("the handler still allows reaching into a job")
	}
}

// The gateway's listener is not started: one that accepts connections
// only to refuse them answers on the port, so it looks configured.
func TestTheGatewayDoesNotStart(t *testing.T) {
	h := &Handler{logger: newTestLogger(t), sshGatewayAddress: ":2222"}
	h.sshToJobOff.Store(true)

	if err := h.startSSHGateway(context.Background(), "https://ap.example.edu"); err != nil {
		t.Fatalf("startSSHGateway: %v", err)
	}
	if h.sshGateway != nil {
		t.Error("a gateway was started although nothing may reach into a job")
	}
}

// Allowed unless the site says otherwise: a Handler built as a literal,
// and an installation that has never heard of the setting, keep what
// they had.
func TestReachingIntoAJobIsAllowedByDefault(t *testing.T) {
	var h Handler
	if !h.sshToJobEnabled() {
		t.Error("a handler nobody configured forbids reaching into a job")
	}
}
