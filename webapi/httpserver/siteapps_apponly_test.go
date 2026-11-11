package httpserver

import (
	"net/http"
	"testing"
)

func TestIsRedirectableUIPath(t *testing.T) {
	// Pages a browser navigates to.
	for _, p := range []string{"/", "/jobs", "/pool/slots/abc", "/submit", "/jobs.html"} {
		if !isRedirectableUIPath(p) {
			t.Errorf("isRedirectableUIPath(%q) = false, want true", p)
		}
	}
	// Everything that would break if it were redirected. The assets in
	// particular: the app we are sending people to is served by the
	// same catch-all as the pages, so redirecting its JavaScript would
	// break the destination.
	for _, p := range []string{
		"/api/v1/jobs", "/site/cryoem/", "/login", "/logout", "/idp/login",
		"/mcp", "/.well-known/openid-configuration", "/_next/static/chunk.js",
		"/healthz", "/readyz", "/metrics",
		"/assets/app.js", "/favicon.ico", "/styles.css",
	} {
		if isRedirectableUIPath(p) {
			t.Errorf("isRedirectableUIPath(%q) = true, want false", p)
		}
	}
}

func TestIsAppOnlyRequiresEveryGroup(t *testing.T) {
	h := &Handler{webuiAppOnlyGroups: newGroupSet("smith_lab, jones_lab")}

	cases := []struct {
		name   string
		groups []string
		want   bool
	}{
		{"only an app-only group", []string{"smith_lab"}, true},
		{"two app-only groups", []string{"smith_lab", "jones_lab"}, true},
		// Somebody who is also staff has a reason to see the console.
		// Taking it away because of one of their memberships would be
		// the wrong way round.
		{"also in a staff group", []string{"smith_lab", "chtc_staff"}, false},
		{"no app-only groups", []string{"chtc_staff"}, false},
		{"no groups at all", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := h.isAppOnly(tc.groups); got != tc.want {
				t.Errorf("isAppOnly(%v) = %v, want %v", tc.groups, got, tc.want)
			}
		})
	}
}

// Unconfigured means the feature is off for everyone, whatever groups
// a caller holds.
func TestIsAppOnlyOffWhenUnconfigured(t *testing.T) {
	h := &Handler{webuiAppOnlyGroups: newGroupSet("")}
	if h.isAppOnly([]string{"smith_lab"}) {
		t.Error("app-only applied with no groups configured")
	}
}

func TestExpertModeArmedReadsTheCookie(t *testing.T) {
	r, _ := http.NewRequest(http.MethodGet, "/", nil)
	if expertModeArmed(r) {
		t.Error("armed with no cookie")
	}
	r.AddCookie(&http.Cookie{Name: expertCookieName, Value: "1"})
	if !expertModeArmed(r) {
		t.Error("not armed with the cookie set")
	}

	// An empty value is not armed: that is what clearing it looks like
	// on a client that keeps the name around.
	r2, _ := http.NewRequest(http.MethodGet, "/", nil)
	r2.AddCookie(&http.Cookie{Name: expertCookieName, Value: ""})
	if expertModeArmed(r2) {
		t.Error("an empty cookie counted as armed")
	}
}

// One home goes straight there; more than one goes to the switcher,
// because picking one arbitrarily sends half those people to the wrong
// place every time.
func TestAppOnlyDestination(t *testing.T) {
	dir := t.TempDir()
	siteAppBundle(t, dir, "cryoem", "CryoEM", "smith_lab")
	siteAppBundle(t, dir, "seqqc", "SeqQC", "jones_lab")
	h := siteAppServer(t, dir)
	// Both are homes.
	for _, id := range []string{"cryoem", "seqqc"} {
		e, ok := h.siteApps.Get(id)
		if !ok {
			t.Fatalf("%s not published", id)
		}
		e.App.Home = true
	}

	if got := h.appOnlyDestination([]string{"smith_lab"}); got != "/site/cryoem/" {
		t.Errorf("one home -> %q, want /site/cryoem/", got)
	}
	if got := h.appOnlyDestination([]string{"smith_lab", "jones_lab"}); got != "/site/" {
		t.Errorf("two homes -> %q, want the switcher", got)
	}
	if got := h.appOnlyDestination([]string{"nobody"}); got != "/site/" {
		t.Errorf("no homes -> %q, want the switcher", got)
	}
}

func TestAppOnlyDestinationWithoutALibrary(t *testing.T) {
	h := &Handler{}
	if got := h.appOnlyDestination([]string{"anyone"}); got != "/site/" {
		t.Errorf("got %q, want /site/", got)
	}
}

// THE property of this feature, asserted directly: app-only is
// presentation. The wrapper passes everything through when nothing is
// configured, and it never touches the API.
func TestAppOnlyRedirectIsNotAuthorization(t *testing.T) {
	reached := false
	inner := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true })

	// Unconfigured: every path goes straight through.
	h := &Handler{webuiAppOnlyGroups: newGroupSet("")}
	wrapped := h.appOnlyRedirect(inner)
	for _, p := range []string{"/", "/jobs", "/api/v1/jobs"} {
		reached = false
		req, _ := http.NewRequest(http.MethodGet, p, nil)
		wrapped.ServeHTTP(discardWriter{}, req)
		if !reached {
			t.Errorf("GET %q was intercepted with no app-only groups configured", p)
		}
	}

	// Configured, but the API is never redirected whatever the session.
	h2 := &Handler{webuiAppOnlyGroups: newGroupSet("smith_lab")}
	wrapped2 := h2.appOnlyRedirect(inner)
	reached = false
	req, _ := http.NewRequest(http.MethodGet, "/api/v1/jobs", nil)
	wrapped2.ServeHTTP(discardWriter{}, req)
	if !reached {
		t.Error("an API request was intercepted by the app-only wrapper")
	}
}

// discardWriter is an http.ResponseWriter that keeps nothing.
type discardWriter struct{}

func (discardWriter) Header() http.Header         { return http.Header{} }
func (discardWriter) Write(b []byte) (int, error) { return len(b), nil }
func (discardWriter) WriteHeader(int)             {}
