package httpserver

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// fakeScheddListener accepts and drops connections at the schedd's address,
// counting them, so a test can tell whether a request got as far as the
// schedd.
func fakeScheddListener(t *testing.T) (string, *atomic.Int64) {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	var accepted atomic.Int64
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			_ = conn.Close()
		}
	}()
	return ln.Addr().String(), &accepted
}

// submitBody is a JSON submit request whose submit file is padded to n
// bytes.
func submitBody(n int) string {
	return `{"submit_file":"executable = /bin/true\n` + strings.Repeat("#", n) + `\nqueue\n"}`
}

// A request body past the default limit is refused with 413 before the
// handler does anything with it -- in particular before it submits to the
// schedd. The caller here is identified (by the trusted user header) so
// that the request reaches the decode: the limit is what stands between
// an authenticated client and the server's memory.
func TestOversizedJSONBodyIsRefusedBeforeTheSchedd(t *testing.T) {
	addr, accepted := fakeScheddListener(t)
	cfg := newTestConfig(t)
	cfg.ScheddAddr = addr
	cfg.UserHeader = "X-Test-User"
	cfg.UserHeaderTrustAnyUnsafe = true // single-host test, no proxy in front
	cfg.SigningKeyPath = writeTestSigningKey(t)
	cfg.TrustDomain = "test.domain"
	cfg.UIDDomain = "test.domain"
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	s.setupRoutes()

	post := func(body string, header func(*http.Request)) *httptest.ResponseRecorder {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
			"/api/v1/jobs", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		header(req)
		w := httptest.NewRecorder()
		s.ServeHTTP(w, req)
		return w
	}
	asAlice := func(r *http.Request) { r.Header.Set("X-Test-User", "alice") }

	before := accepted.Load()
	w := post(submitBody(2<<20), asAlice)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("a 2 MiB submit was answered %d, want 413: %s", w.Code, w.Body.String())
	}
	var e ErrorResponse
	if err := json.Unmarshal(w.Body.Bytes(), &e); err != nil {
		t.Fatalf("error body is not JSON: %v (%s)", err, w.Body.String())
	}
	if e.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("error body says code %d, status says 413", e.Code)
	}
	if n := accepted.Load() - before; n != 0 {
		t.Errorf("an oversized submit reached the schedd (%d connection(s))", n)
	}

	// The same request under the limit does reach the schedd, so the
	// listener above would have seen the oversized one if it had.
	w = post(submitBody(1024), asAlice)
	if w.Code == http.StatusRequestEntityTooLarge {
		t.Fatalf("a 1 KiB submit was refused as too large: %s", w.Body.String())
	}
	if accepted.Load() == before {
		t.Errorf("a small submit never reached the schedd (status %d: %s); "+
			"the oversized case above proves nothing", w.Code, w.Body.String())
	}

	// A token nobody signed is refused, oversized body or not.
	token := forgedToken(t, "alice@test.domain")
	w = post(submitBody(2<<20), func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+token) })
	if w.Code != http.StatusUnauthorized && w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("a 2 MiB submit with an unsigned bearer was answered %d: %s", w.Code, w.Body.String())
	}
}

// Routes that legitimately take more than the default can raise it, and
// the raised limit is the one that applies -- not the smaller of the two,
// which is what wrapping the body a second time would give.
//
// Saved templates carry input files inline, so 2 MiB is an ordinary
// request there.
func TestRaisedBodyLimitTakesEffect(t *testing.T) {
	cfg := newTestConfig(t)
	cfg.UserHeader = "X-Test-User"
	cfg.UserHeaderTrustAnyUnsafe = true // single-host test, no proxy in front
	cfg.SigningKeyPath = writeTestSigningKey(t)
	cfg.TrustDomain = "test.domain"
	cfg.UIDDomain = "test.domain"
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if s.templateLibrary == nil {
		t.Fatal("no template store: this test cannot exercise the templates route")
	}
	s.setupRoutes()

	save := func(fileBytes, files int) *httptest.ResponseRecorder {
		type inputFile struct {
			Name    string `json:"name"`
			Content []byte `json:"content"`
		}
		in := make([]inputFile, files)
		for i := range in {
			in[i] = inputFile{Name: "in" + string(rune('a'+i)) + ".txt", Content: make([]byte, fileBytes)}
		}
		body, err := json.Marshal(map[string]any{
			"name":        "large",
			"contents":    "executable = /bin/true\nqueue\n",
			"input_files": in,
		})
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
			"/api/v1/templates", strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Test-User", "alice")
		w := httptest.NewRecorder()
		s.ServeHTTP(w, req)
		return w
	}

	// Four 512 KiB files, base64 in the JSON: about 2.7 MiB, over the
	// default and under the route's own limit.
	if w := save(512<<10, 4); w.Code != http.StatusCreated {
		t.Fatalf("a 2.7 MiB template save was answered %d, want 201: %s", w.Code, w.Body.String())
	}
	// And the route's own limit still holds: about 12 MiB.
	if w := save(3<<20, 3); w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("a 12 MiB template save was answered %d, want 413: %s", w.Code, w.Body.String())
	}
}

// Dynamic client registration is unauthenticated, so it gets less than the
// default.
func TestClientRegistrationBodyIsBounded(t *testing.T) {
	srv := startDeviceVerifyServer(t)

	register := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
			"/mcp/oauth2/register", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)
		return w
	}

	uris := make([]string, 0, 200000)
	for i := 0; len(uris) < cap(uris); i++ {
		uris = append(uris, "http://127.0.0.1/callback/padding-padding-padding")
	}
	big, err := json.Marshal(map[string]any{"client_name": "big", "redirect_uris": uris})
	if err != nil {
		t.Fatal(err)
	}
	if len(big) < 10_000_000 {
		t.Fatalf("test body is only %d bytes", len(big))
	}
	if w := register(string(big)); w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("a %d-byte registration was answered %d, want 413: %.200s", len(big), w.Code, w.Body.String())
	}
	// Past the route's 64 KiB but well under the 1 MiB default: the
	// route's own limit is the one in force.
	mid, err := json.Marshal(map[string]any{"client_name": "mid", "redirect_uris": uris[:2000]})
	if err != nil {
		t.Fatal(err)
	}
	if w := register(string(mid)); w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("a %d-byte registration was answered %d, want 413: %.200s", len(mid), w.Code, w.Body.String())
	}
	// An ordinary registration still succeeds.
	if id := registerDeviceVerifyClient(t, srv); id == "" {
		t.Fatal("no client id")
	}
}

// The limit mechanics, below the routes: the default applies, a route can
// raise or lower it, and a proxy can lift it.
func TestSetBodyLimitReplacesTheDefault(t *testing.T) {
	read := func(r *http.Request) (int, error) {
		n, err := io.Copy(io.Discard, r.Body)
		return int(n), err
	}
	newReq := func(n int) (*http.Request, *requestBodyLimit) {
		r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/",
			strings.NewReader(strings.Repeat("x", n)))
		state := &requestBodyLimit{}
		limitRequestBody(httptest.NewRecorder(), r, state)
		return r, state
	}

	r, state := newReq(defaultMaxRequestBody + 1)
	if _, err := read(r); !errors.As(err, new(*http.MaxBytesError)) {
		t.Errorf("default: err = %v, want MaxBytesError", err)
	}
	if state.Exceeded() != defaultMaxRequestBody {
		t.Errorf("default: Exceeded() = %d, want %d", state.Exceeded(), defaultMaxRequestBody)
	}

	r, state = newReq(4 << 20)
	setBodyLimit(httptest.NewRecorder(), r, 8<<20)
	if n, err := read(r); err != nil || n != 4<<20 {
		t.Errorf("raised: read %d, %v; want all 4 MiB", n, err)
	}
	if state.Exceeded() != 0 {
		t.Errorf("raised: Exceeded() = %d after a body within the limit", state.Exceeded())
	}

	r, state = newReq(100)
	setBodyLimit(httptest.NewRecorder(), r, 10)
	if _, err := read(r); err == nil {
		t.Error("lowered: a 100-byte body passed a 10-byte limit")
	}
	if state.Exceeded() != 10 {
		t.Errorf("lowered: Exceeded() = %d, want 10", state.Exceeded())
	}

	r, _ = newReq(defaultMaxRequestBody + 1)
	removeBodyLimit(r)
	if n, err := read(r); err != nil || n != defaultMaxRequestBody+1 {
		t.Errorf("removed: read %d, %v; want the whole body", n, err)
	}
}

// Handlers change the limit through setBodyLimit, never by wrapping the
// body in http.MaxBytesReader themselves. A second MaxBytesReader can only
// lower the limit -- a route that asked for more would silently get the
// default -- and an overflow it reports surfaces as 400 or 500 rather than
// 413.
func TestHandlersDoNotWrapTheBodyThemselves(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") || f == "request_body.go" {
			continue
		}
		src, err := os.ReadFile(filepath.Clean(f))
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(src), "\n") {
			if strings.Contains(line, "http.MaxBytesReader(") {
				t.Errorf("%s:%d calls http.MaxBytesReader; use setBodyLimit", f, i+1)
			}
		}
	}
}
