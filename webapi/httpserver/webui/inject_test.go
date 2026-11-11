package webui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

const headBlock = `<base href="/site/cryoem/"><script>window.__X__=1</script>`

func TestInjectHeadPlacement(t *testing.T) {
	cases := []struct {
		name   string
		page   string
		before string // the injected block must appear before this
	}{
		{
			name:   "before </head>",
			page:   "<!doctype html><html><head><title>t</title></head><body>b</body></html>",
			before: "</head>",
		},
		{
			// A hand-written index.html with no head still has to learn
			// its base path, or the app is simply broken.
			name:   "after <body> when there is no head",
			page:   "<!doctype html><html><body>b</body></html>",
			before: "b</body>",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := string(injectHead([]byte(tc.page), []byte(headBlock)))
			i := strings.Index(got, headBlock)
			if i < 0 {
				t.Fatalf("block not injected: %s", got)
			}
			if j := strings.Index(got, tc.before); j < 0 || i > j {
				t.Errorf("block at %d is not before %q at %d: %s", i, tc.before, j, got)
			}
		})
	}
}

func TestInjectHeadFragmentIsPrepended(t *testing.T) {
	got := string(injectHead([]byte("just text"), []byte(headBlock)))
	if !strings.HasPrefix(got, headBlock) {
		t.Errorf("block was not prepended: %s", got)
	}
}

func TestInjectHeadEmptyIsNoOp(t *testing.T) {
	page := "<html><head></head></html>"
	if got := string(injectHead([]byte(page), nil)); got != page {
		t.Errorf("page changed: %s", got)
	}
}

func TestLooksLikeHTML(t *testing.T) {
	for _, yes := range []string{"<!DOCTYPE html>", "<html>", "<head>", "  <body>", "<HTML>"} {
		if !looksLikeHTML([]byte(yes)) {
			t.Errorf("looksLikeHTML(%q) = false", yes)
		}
	}
	for _, no := range []string{"", "{\"a\":1}", "plain text", "<svg></svg>"} {
		if looksLikeHTML([]byte(no)) {
			t.Errorf("looksLikeHTML(%q) = true", no)
		}
	}
}

func TestNewSPAHandlerFSServesAndInjects(t *testing.T) {
	fsys := fstest.MapFS{
		"index.html":    {Data: []byte("<html><head></head><body>home</body></html>")},
		"assets/app.js": {Data: []byte("console.log(1)")},
		"jobs.html":     {Data: []byte("<html><head></head><body>jobs</body></html>")},
	}
	h := NewSPAHandlerFS(fsys, WithHeadHTML([]byte(headBlock)))

	t.Run("root gets the block", func(t *testing.T) {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d", rec.Code)
		}
		if !strings.Contains(rec.Body.String(), headBlock) {
			t.Errorf("index.html was not injected: %s", rec.Body.String())
		}
	})

	t.Run("extensionless route resolves and gets the block", func(t *testing.T) {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/jobs", nil))
		if !strings.Contains(rec.Body.String(), "jobs") ||
			!strings.Contains(rec.Body.String(), headBlock) {
			t.Errorf("jobs page wrong: %s", rec.Body.String())
		}
	})

	t.Run("unknown route falls back to index, injected", func(t *testing.T) {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/deep/client/route", nil))
		if !strings.Contains(rec.Body.String(), headBlock) {
			t.Errorf("SPA fallback was not injected: %s", rec.Body.String())
		}
	})

	t.Run("assets are untouched", func(t *testing.T) {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/assets/app.js", nil))
		if body := rec.Body.String(); body != "console.log(1)" {
			t.Errorf("asset was modified: %q", body)
		}
	})
}

// Without the option the bytes must go out of the filesystem untouched,
// so a Range request is answered by the file rather than a rendered
// copy. Site apps rely on that for everything that is not a page.
func TestNewSPAHandlerFSWithoutInjectionIsByteExact(t *testing.T) {
	page := "<html><head></head><body>home</body></html>"
	h := NewSPAHandlerFS(fstest.MapFS{"index.html": {Data: []byte(page)}})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil))
	if rec.Body.String() != page {
		t.Errorf("body = %q, want the file unchanged", rec.Body.String())
	}
}

// Path escapes must be refused by the handler, whatever the filesystem
// underneath would have done.
func TestNewSPAHandlerFSRefusesEscapes(t *testing.T) {
	fsys := fstest.MapFS{
		"index.html": {Data: []byte("<html><head></head><body>home</body></html>")},
	}
	h := NewSPAHandlerFS(fsys)
	for _, bad := range []string{"/../secret", "/..%2fsecret", "//etc/passwd"} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.com"+bad, nil)
		h.ServeHTTP(rec, req)
		if body := rec.Body.String(); strings.Contains(body, "secret") || strings.Contains(body, "root:") {
			t.Errorf("%q escaped the filesystem: %s", bad, body)
		}
	}
}
