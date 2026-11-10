package httpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/jobid"
	"github.com/bbockelm/golang-htcondor/webapi/apregistry"
	"github.com/bbockelm/golang-htcondor/webapi/multiap"
	"github.com/bbockelm/golang-htcondor/webapi/shareurl"
)

// disabledOn is a user-record oracle whose verdict depends on the AP:
// the user is disabled on the named APs only.
func disabledOn(aps ...string) *multiAPOracle {
	return &multiAPOracle{name: OracleScheddUserRec, judgesUser: true,
		members: func() []apregistry.Member { return nil },
		perMember: func(m apregistry.Member) RevocationOracle {
			for _, ap := range aps {
				if strings.EqualFold(ap, m.Name) {
					return fixedOracle{d: ReauthDecision{Status: UserStatusRevoked, Reason: "disabled by the admin"}}
				}
			}
			return fixedOracle{d: ReauthDecision{Status: UserStatusActive}}
		}}
}

// An AP whose own records disable the caller refuses everything routed
// to it for them -- single-job actions, sandbox reads, share URLs and
// bulk legs -- while the other AP keeps serving them.
func TestMultiAPDisabledUserIsRefusedPerAP(t *testing.T) {
	aps := newActionAPs(t, ap1, ap2)
	srv := newActionServer(t, aps, nil)
	srv.revocationOracles = []RevocationOracle{disabledOn(ap2)}

	before := aps.counts()
	for _, path := range []string{"/hold", "/stdout"} {
		method := http.MethodPost
		if path == "/stdout" {
			method = http.MethodGet
		}
		rec := doAlice(t, srv, method, "/api/v1/jobs/1.0@"+ap2+path, "")
		var body struct {
			Reason string `json:"reason"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		if rec.Code != http.StatusForbidden || body.Reason != multiap.ReasonDenied {
			t.Errorf("%s on ap2 for a user disabled there = %d %s, want 403 %s", path, rec.Code, rec.Body.String(), multiap.ReasonDenied)
		}
	}
	if after := aps.counts(); after[ap2] != before[ap2] {
		t.Errorf("a refused request reached ap2: %v -> %v", before, after)
	}
	doAlice(t, srv, http.MethodPost, "/api/v1/jobs/1.0@"+ap1+"/hold", "")
	if aps.counts()[ap1] == before[ap1] {
		t.Error("ap1, which does not disable alice, was not reached")
	}

	// A share URL for ap2 is refused for its owner there, without detail.
	rec := redeem(t, srv, http.MethodGet, "/api/v1/share/output", shareToken(t, srv, shareurl.Payload{Schedd: ap2, Cluster: 1}))
	if rec.Code != http.StatusForbidden || strings.Contains(rec.Body.String(), "disabled by the admin") {
		t.Errorf("share URL for a disabled owner = %d %s", rec.Code, rec.Body.String())
	}

	// A bulk action reports ap2 as refused and still runs on ap1.
	rec = doAlice(t, srv, http.MethodPost, "/api/v1/jobs/hold", `{"constraint":"true"}`)
	var rep MultiAPBulkResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &rep); err != nil {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	for _, a := range rep.APs {
		if a.Schedd == ap2 && (a.Status != multiap.BulkFailed || !strings.Contains(a.Error, "refuses")) {
			t.Errorf("ap2 in a bulk action = %+v, want refused", a)
		}
	}
	if after := aps.counts(); after[ap2] != before[ap2] {
		t.Errorf("a bulk action reached ap2 for a user disabled there")
	}
}

// Nothing about an AP is looked at, or recorded, for an unauthenticated
// request.
func TestMultiAPActionsAuthenticateFirst(t *testing.T) {
	aps := newActionAPs(t, ap1, ap2, "ap3.example.org")
	aps.reg.Update("ap3.example.org", func(m *apregistry.Member) {
		m.Trust = apregistry.Trust{State: apregistry.TrustUntrusted, Reason: "trust domain secret.example"}
	})
	srv := newActionServer(t, aps, nil)
	for _, ap := range []string{ap1, "ap3.example.org", "ap9.example.org"} {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodDelete, "/api/v1/jobs/1.0@"+ap, nil)
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized || strings.Contains(rec.Body.String(), "secret.example") ||
			strings.Contains(rec.Body.String(), "access point") {
			t.Errorf("unauthenticated DELETE on %s = %d %s, want a bare 401", ap, rec.Code, rec.Body.String())
		}
	}
	if aps.counts()[ap1] != 0 || srv.multi.svc.WroteSince(ap1, time.Hour) {
		t.Error("an unauthenticated request reached ap1 or was recorded as a write there")
	}
}

// Only members that passed the trust probe identify callers; a request
// routed to an AP is identified by that AP alone.
func TestMultiAPIdentityComesFromTrustedOrRoutedAPs(t *testing.T) {
	aps := newActionAPs(t, ap1, ap2, "ap3.example.org")
	aps.reg.Update(ap2, func(m *apregistry.Member) { m.Trust = apregistry.Trust{State: apregistry.TrustTrusted} })
	aps.reg.Update("ap3.example.org", func(m *apregistry.Member) { m.Trust = apregistry.Trust{State: apregistry.TrustTrusted} })
	srv := newActionServer(t, aps, nil)
	got := srv.identitySchedds()
	for _, s := range got {
		if s.Name() == ap1 {
			t.Errorf("ap1, never probed, is used to identify callers")
		}
	}
	if len(got) != 2 {
		t.Errorf("identity schedds = %d, want the two trusted members", len(got))
	}

	sec, err := htcondor.NewClientSecurityConfigWithConfig(context.Background(), nil, "e30.e30.c2ln", "", 0, "CLIENT", nil)
	if err != nil {
		t.Fatal(err)
	}
	m, _ := aps.reg.Get(ap1)
	ctx := multiap.WithTarget(htcondor.WithSecurityConfig(context.Background(), sec),
		multiap.Target{Member: m, ID: jobid.ID{Schedd: ap1, Cluster: 1}})
	before := aps.counts()
	_, _ = srv.pingAsCaller(ctx)
	after := aps.counts()
	if after[ap1] == before[ap1] || after[ap2] != before[ap2] || after["ap3.example.org"] != before["ap3.example.org"] {
		t.Errorf("a ping routed to ap1 went %v -> %v, want ap1 only", before, after)
	}
}
