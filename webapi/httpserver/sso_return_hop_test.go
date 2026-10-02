package httpserver

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// The last hop is performed by the browser, not by a 302.
//
// A 302 here arrives at the destination as part of a chain the identity
// provider started, so the SameSite=Strict session cookie we just set is
// withheld and the destination sends the user back to the IdP -- the
// loop reported from production. A page served from this origin makes
// the next navigation same-site, which Strict permits.
func TestBrowserFinishesTheLoginHopItself(t *testing.T) {
	h := &Handler{}
	w := httptest.NewRecorder()
	h.finishBrowserLogin(w, "/oauth2/device/verify?user_code=WDJB-MJHT")

	if loc := w.Header().Get("Location"); loc != "" {
		t.Fatalf("answered with a redirect to %q; a 302 is what loses the cookie", loc)
	}
	if w.Code != 200 {
		t.Fatalf("status %d, want 200", w.Code)
	}
	body := w.Body.String()
	// Three ways out, in case JavaScript is off: the script, the meta
	// refresh, and a link. Each performs or offers a same-site
	// navigation.
	for _, want := range []string{"location.replace(", "http-equiv=\"refresh\"", "<a href="} {
		if !strings.Contains(body, want) {
			t.Errorf("the page offers no %s: %s", want, body)
		}
	}
	if !strings.Contains(body, "user_code=WDJB-MJHT") {
		t.Errorf("the destination was lost: %s", body)
	}
	if got := w.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store: the page names where somebody was going", got)
	}
}

// The destination is escaped for both places it lands in -- an HTML
// attribute and a JavaScript string -- which are different escapes.
func TestTheDestinationCannotBreakOutOfThePage(t *testing.T) {
	h := &Handler{}
	for _, nasty := range []string{
		`/x"><script>alert(1)</script>`,
		`/x</script><script>alert(1)</script>`,
		"/x\"+alert(1)+\"",
	} {
		w := httptest.NewRecorder()
		h.finishBrowserLogin(w, nasty)
		body := w.Body.String()
		// The only <script> in the page is the one we wrote. Any
		// second opening tag means the value escaped its context.
		if strings.Count(strings.ToLower(body), "<script") != 1 {
			t.Errorf("%q produced %d script tags:\n%s", nasty,
				strings.Count(strings.ToLower(body), "<script"), body)
		}
		if strings.Contains(body, "alert(1)</script>") {
			t.Errorf("%q closed the script block:\n%s", nasty, body)
		}
	}
}

func TestJSStringLiteralEscapesTagBoundaries(t *testing.T) {
	got := jsStringLiteral(`</script>`)
	if strings.Contains(got, "<") || strings.Contains(got, ">") {
		t.Fatalf("tag characters survived into the literal: %s", got)
	}
	if !strings.HasPrefix(got, `"`) || !strings.HasSuffix(got, `"`) {
		t.Fatalf("not a quoted literal: %s", got)
	}
	// A quote must not end the literal early.
	if q := jsStringLiteral(`a"b`); q != `"a\"b"` {
		t.Fatalf("quote not escaped: %s", q)
	}
}
