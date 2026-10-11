package httpserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/golang-htcondor/webapi/shareurl"
)

func shareToken(t *testing.T, srv *Server, p shareurl.Payload) string {
	t.Helper()
	if p.Exp == 0 {
		p.Exp = time.Now().Add(time.Hour).Unix()
	}
	if p.Owner == "" {
		p.Owner = "alice"
	}
	if p.Authz == nil {
		p.Authz = []string{"READ", "WRITE"}
	}
	tok, err := srv.signShareToken(p)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func redeem(t *testing.T, srv *Server, method, path, tok string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), method, path+"?t="+url.QueryEscape(tok), strings.NewReader("x"))
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	return rec
}

// A redeemed share URL acts on the AP it names, and only there; one that
// names none is refused before any schedd is contacted.
func TestMultiAPShareURLRoutesToItsAP(t *testing.T) {
	aps := newActionAPs(t, ap1, ap2)
	srv := newActionServer(t, aps, nil)

	for _, c := range []struct {
		method, path string
		kind         shareurl.Kind
	}{
		{http.MethodGet, "/api/v1/share/output", shareurl.KindOutput},
		{http.MethodPut, "/api/v1/share/input", shareurl.KindInput},
	} {
		before := aps.counts()
		rec := redeem(t, srv, c.method, c.path, shareToken(t, srv, shareurl.Payload{Schedd: ap2, Cluster: 1, Kind: c.kind}))
		after := aps.counts()
		if after[ap2] == before[ap2] || after[ap1] != before[ap1] {
			t.Errorf("%s %s for 1.0@ap2 = %d %s; connections %v -> %v, want ap2 only",
				c.method, c.path, rec.Code, clip(rec.Body.String(), 200), before, after)
		}

		before = aps.counts()
		rec = redeem(t, srv, c.method, c.path, shareToken(t, srv, shareurl.Payload{Cluster: 1, Kind: c.kind}))
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "does not name an access point") {
			t.Errorf("%s %s without s = %d %s, want 403", c.method, c.path, rec.Code, rec.Body.String())
		}
		rec = redeem(t, srv, c.method, c.path, shareToken(t, srv, shareurl.Payload{Schedd: "ap9.example.org", Cluster: 1, Kind: c.kind}))
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s %s for an unknown AP = %d %s, want 404", c.method, c.path, rec.Code, rec.Body.String())
		}
		if after := aps.counts(); after[ap1] != before[ap1] || after[ap2] != before[ap2] {
			t.Errorf("a refused share URL reached a schedd: %v -> %v", before, after)
		}
	}

	// Watch share URLs are not served in multi-AP mode yet.
	rec := redeem(t, srv, http.MethodGet, "/api/v1/share/watch", shareToken(t, srv, shareurl.Payload{Kind: shareurl.KindWatch, Watch: "w1"}))
	if rec.Code != http.StatusNotImplemented {
		t.Errorf("watch share in multi-AP mode = %d %s, want 501", rec.Code, rec.Body.String())
	}
}

// Single-AP mode: a URL without s is redeemed as it always was; one
// naming another schedd is refused.
func TestSingleAPShareURLSchedd(t *testing.T) {
	addr, accepted := fakeScheddListener(t)
	cfg := newTestConfig(t)
	cfg.ScheddAddr = "<" + addr + ">"
	cfg.SigningKeyPath = writeTestSigningKey(t)
	cfg.TrustDomain = "test.domain"
	cfg.UIDDomain = "d"
	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	srv.setupRoutes()

	before := accepted.Load()
	redeem(t, srv, http.MethodGet, "/api/v1/share/output", shareToken(t, srv, shareurl.Payload{Cluster: 1}))
	if accepted.Load() == before {
		t.Error("a URL without s no longer reaches the schedd in single-AP mode")
	}
	before = accepted.Load()
	rec := redeem(t, srv, http.MethodGet, "/api/v1/share/output", shareToken(t, srv, shareurl.Payload{Schedd: "elsewhere", Cluster: 1}))
	if rec.Code != http.StatusForbidden || accepted.Load() != before {
		t.Errorf("a URL for another schedd = %d %s (connections +%d), want 403 and none", rec.Code, rec.Body.String(), accepted.Load()-before)
	}
	redeem(t, srv, http.MethodGet, "/api/v1/share/output", shareToken(t, srv, shareurl.Payload{Schedd: "TEST-SCHEDD", Cluster: 1}))
	if accepted.Load() == before {
		t.Error("a URL naming this server's own schedd was refused")
	}
}
