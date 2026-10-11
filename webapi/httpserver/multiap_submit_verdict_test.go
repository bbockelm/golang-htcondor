package httpserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ory/fosite"

	"github.com/bbockelm/golang-htcondor/webapi/apassign"
	"github.com/bbockelm/golang-htcondor/webapi/apregistry"
	"github.com/bbockelm/golang-htcondor/webapi/multiap"
)

// refuseOn is an AP verdict refusing everyone on ap.
func refuseOn(ap string) func(context.Context, apregistry.Member, string) error {
	return func(_ context.Context, m apregistry.Member, user string) error {
		if strings.EqualFold(m.Name, ap) {
			return &multiap.Error{Status: http.StatusForbidden, Reason: multiap.ReasonDenied,
				Msg: "access point " + m.Name + " refuses " + user}
		}
		return nil
	}
}

// The target AP's own verdict on the caller -- its user records (Admit)
// and the identity it reports for the credential (VerifyCaller) -- is
// asked before anything is submitted there, and a refusal submits
// nothing.
func TestMultiAPSubmitAsksTheAPsVerdict(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(*multiap.Service)
	}{
		{"user record (Admit)", func(svc *multiap.Service) { svc.Admit = refuseOn(ap2) }},
		// Admit off: the user-record check asks the AP itself, and this
		// case counts connections to see that nothing was submitted.
		{"identity (VerifyCaller)", func(svc *multiap.Service) { svc.Admit, svc.VerifyCaller = nil, refuseOn(ap2) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newSubmitServer(t, "USER alice@d "+ap2+" "+ap3+"\n", "scitokens")
			tc.setup(s.svc)
			before := s.aps.counts()
			rec := doAlice(t, s.srv, http.MethodPost, "/api/v1/jobs", submitJSON)
			reachedNone(t, "a refused submission", before, s.aps.counts())
			if rec.Code != http.StatusForbidden || errorReason(t, rec) != multiap.ReasonDenied {
				t.Errorf("submit = %d %s, want 403 %s", rec.Code, rec.Body.String(), multiap.ReasonDenied)
			}
			if s.credds[ap2].checkCount() != 0 {
				t.Error("the refusing AP's credd was asked for credentials")
			}
			// The alternate, which does not refuse, still takes work.
			before = s.aps.counts()
			_ = doAlice(t, s.srv, http.MethodPost, "/api/v1/jobs?schedd="+ap3, submitJSON)
			reachedOnlyAP(t, "submit to the alternate", before, s.aps.counts(), ap3)
		})
	}
}

// A credential endpoint asks the AP's verdict too.
func TestMultiAPCredentialsAskTheAPsVerdict(t *testing.T) {
	s := newSubmitServer(t, "USER alice@d "+ap2+"\n")
	s.svc.Admit = refuseOn(ap2)
	rec := doAlice(t, s.srv, http.MethodGet, "/api/v1/creds/service", "")
	if rec.Code != http.StatusForbidden || errorReason(t, rec) != multiap.ReasonDenied {
		t.Errorf("credentials on a refusing AP = %d %s, want 403 %s", rec.Code, rec.Body.String(), multiap.ReasonDenied)
	}
	if st, _ := s.credds[ap2].counts(); st != 0 {
		t.Error("the refusing AP's credd was asked")
	}
}

// A submission is a write: a bulk action must not skip the AP on the
// hub's word until the hub has seen it.
func TestMultiAPSubmitNotesTheWrite(t *testing.T) {
	s := newSubmitServer(t, "USER alice@d "+ap2+"\n")
	_ = doAlice(t, s.srv, http.MethodPost, "/api/v1/jobs", submitJSON)
	if !s.svc.WroteSince(ap2, time.Minute) {
		t.Error("a submission to ap2 was not noted as a write on ap2")
	}
	if s.svc.WroteSince(ap1, time.Minute) || s.svc.WroteSince(ap3, time.Minute) {
		t.Error("a submission to ap2 was noted on another AP")
	}
}

// An explicit alternate that cannot take work now is a 503 naming why,
// and is not contacted.
func TestMultiAPSubmitUnusableAlternateIs503(t *testing.T) {
	for _, tc := range []struct {
		name string
		mod  func(*apregistry.Member)
	}{
		{"absent", func(m *apregistry.Member) { m.Present = false }},
		{"untrusted", func(m *apregistry.Member) {
			m.Trust = apregistry.Trust{State: apregistry.TrustUntrusted, Reason: "refused the probe"}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newSubmitServer(t, "USER alice@d "+ap2+" "+ap3+"\n")
			s.aps.reg.Update(ap3, tc.mod)
			before := s.aps.counts()
			rec := doAlice(t, s.srv, http.MethodPost, "/api/v1/jobs?schedd="+ap3, submitJSON)
			reachedNone(t, "a submission to an unusable alternate", before, s.aps.counts())
			if rec.Code != http.StatusServiceUnavailable || errorReason(t, rec) != apassign.ReasonTargetUnusable {
				t.Errorf("= %d %s, want 503 %s", rec.Code, rec.Body.String(), apassign.ReasonTargetUnusable)
			}
		})
	}
}

// An AP that turns untrusted between the identity check and the submit
// is reported as that, with its reason -- not as a failed submission.
func TestMultiAPSubmitAPTurnsUntrustedMidway(t *testing.T) {
	s := newSubmitServer(t, "USER alice@d "+ap2+"\n")
	s.svc.Admit = nil // it asks the AP itself; this test counts connections
	s.svc.VerifyCaller = func(context.Context, apregistry.Member, string) error {
		s.aps.reg.Update(ap2, func(m *apregistry.Member) {
			m.Trust = apregistry.Trust{State: apregistry.TrustUntrusted, Reason: "refused the probe"}
		})
		return nil
	}
	before := s.aps.counts()
	rec := doAlice(t, s.srv, http.MethodPost, "/api/v1/jobs", submitJSON)
	reachedNone(t, "a submission to an AP that became untrusted", before, s.aps.counts())
	if rec.Code != http.StatusServiceUnavailable || errorReason(t, rec) != multiap.ReasonAPUntrusted {
		t.Errorf("= %d %s, want 503 %s", rec.Code, rec.Body.String(), multiap.ReasonAPUntrusted)
	}
}

// A GROUP rule places a browser session by the groups its login
// recorded.
func TestMultiAPSubmitBySessionGroups(t *testing.T) {
	s := newSubmitServer(t, "GROUP physics "+ap3+"\nUSER alice@d "+ap2+"\n")
	sessID, _, err := s.srv.sessionStore.Create("alice", []string{"physics"})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/jobs", strings.NewReader(submitJSON))
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessID, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	req.Header.Set("Origin", "http://example.com")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	before := s.aps.counts()
	s.srv.ServeHTTP(rec, req)
	reachedOnlyAP(t, "a session submission", before, s.aps.counts(), ap3)
	if rec.Code == http.StatusForbidden || rec.Code == http.StatusUnauthorized {
		t.Errorf("session submit = %d %s", rec.Code, rec.Body.String())
	}
}

// A GROUP rule places an MCP call by the groups its OAuth2 grant carries.
func TestMultiAPMCPSubmitByGrantGroups(t *testing.T) {
	s := newSubmitServer(t, "GROUP physics "+ap3+"\nUSER alice@d "+ap2+"\n")
	tok := mintGroupAccessToken(t, s.srv, "alice", []string{"physics"}, []string{"mcp:read", "mcp:write"})
	// The schedd-verified identity of this bearer, as the first call
	// would have resolved it.
	s.srv.mcpActors.put(tok, "alice@d", time.Minute)
	before := s.aps.counts()
	code, body := mcpRPC(t, s.srv, tok, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"submit_job",`+
		`"arguments":{"submit_file":"executable = /bin/true\ntransfer_executable = false\nqueue\n"}}}`)
	reachedOnlyAP(t, "an MCP submission", before, s.aps.counts(), ap3)
	if code != http.StatusOK {
		t.Errorf("MCP submit = %d %s", code, body)
	}
}

// mintGroupAccessToken is mintMCPAccessToken for a subject and groups.
func mintGroupAccessToken(t *testing.T, s *Server, subject string, groups, scopes []string) string {
	t.Helper()
	ctx := context.Background()
	if _, err := s.oauth2Provider.GetStorage().GetDB().ExecContext(ctx,
		`INSERT OR IGNORE INTO oauth2_clients (id, client_secret, redirect_uris, grant_types, response_types, scopes, public)
		 VALUES ('group-client', '', '[]', '["authorization_code"]', '["code"]', '[]', 1)`); err != nil {
		t.Fatalf("seed client: %v", err)
	}
	session := DefaultOpenIDConnectSession(subject).WithGroups(groups)
	ar := fosite.NewAccessRequest(session)
	ar.Client = &fosite.DefaultClient{ID: "group-client"}
	ar.GrantedScope = fosite.Arguments(scopes)
	setStandardTokenExpiries(ctx, s.oauth2Provider.config, session)
	strategy := s.oauth2Provider.GetStrategy()
	tok, _, err := strategy.GenerateAccessToken(ctx, ar)
	if err != nil {
		t.Fatalf("GenerateAccessToken: %v", err)
	}
	if err := s.oauth2Provider.GetStorage().CreateAccessTokenSession(ctx,
		strategy.AccessTokenSignature(ctx, tok), ar); err != nil {
		t.Fatalf("CreateAccessTokenSession: %v", err)
	}
	return tok
}

// The per-AP credd follows the address the AP's schedd advertises.
func TestAPCreddsFollowTheAdvertisedAddress(t *testing.T) {
	c := &apCredds{}
	m := apregistry.Member{Name: ap1, CreddAddress: "<10.0.0.1:9620>"}
	first, scope1 := c.forMember(m)
	again, _ := c.forMember(m)
	if first == nil || first != again || scope1 != "<10.0.0.1:9620>" {
		t.Fatalf("first=%v again=%v scope=%q", first, again, scope1)
	}
	m.CreddAddress = "<10.0.0.9:9620>"
	moved, scope2 := c.forMember(m)
	if moved == first || scope2 != "<10.0.0.9:9620>" {
		t.Errorf("after the credd moved: same client %v, scope %q", moved == first, scope2)
	}
	if cl, scope := c.forMember(apregistry.Member{Name: ap2}); cl != nil || scope != "" {
		t.Errorf("an AP with no credd: %v %q", cl, scope)
	}
}
