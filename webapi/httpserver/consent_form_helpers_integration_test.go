//go:build integration

package httpserver

import (
	"html"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"testing"
)

// consentPageCSRF fetches a consent or device-verification page and
// returns the CSRF token it rendered.
//
// The form is bound to the person and to the request it is about, so a
// test cannot build an approval by hand any more -- it has to submit
// what the page said. That is a better test anyway: this file already
// carries a note about a bug that passed because approveDevice omitted
// fields the real page emits, and every omission of that kind is a
// chance for the test to exercise a path no browser reaches.
// baseURL is needed because a redirect's Location header is relative --
// "/mcp/oauth2/consent?state=..." -- and a bare one has no scheme to
// fetch with.
func consentPageCSRF(t *testing.T, client *http.Client, baseURL, pageURL, username string) string {
	t.Helper()
	pageURL = resolveAgainst(t, baseURL, pageURL)
	req, err := http.NewRequest(http.MethodGet, pageURL, nil)
	if err != nil {
		t.Fatalf("building a request for %s: %v", pageURL, err)
	}
	if username != "" {
		req.Header.Set("X-Test-User", username)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("loading %s: %v", pageURL, err)
	}
	body, readErr := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if readErr != nil {
		t.Fatalf("reading %s: %v", pageURL, readErr)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("%s returned %d: %s", pageURL, resp.StatusCode, body)
	}
	token := hiddenInputValue(string(body), "csrf_token")
	if token == "" {
		t.Fatalf("%s carried no csrf_token: %s", pageURL, body)
	}
	return token
}

// hiddenInputValue pulls one hidden input's value out of rendered HTML.
//
// A regexp rather than an HTML parser because the markup is this
// server's own and fixed; the point is to submit what the page says,
// not to be a browser.
func hiddenInputValue(body, name string) string {
	re := regexp.MustCompile(`<input[^>]*type="hidden"[^>]*name="` + regexp.QuoteMeta(name) + `"[^>]*value="([^"]*)"`)
	m := re.FindStringSubmatch(body)
	if len(m) < 2 {
		return ""
	}
	return html.UnescapeString(m[1])
}

// resolveAgainst turns a possibly-relative URL into an absolute one.
func resolveAgainst(t *testing.T, baseURL, ref string) string {
	t.Helper()
	parsed, err := url.Parse(ref)
	if err != nil {
		t.Fatalf("parsing %q: %v", ref, err)
	}
	if parsed.IsAbs() {
		return ref
	}
	base, err := url.Parse(baseURL)
	if err != nil {
		t.Fatalf("parsing base %q: %v", baseURL, err)
	}
	return base.ResolveReference(parsed).String()
}
