package apassign

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// A 404 or 403 means "no answer" or "denied" only when the service says
// so in the contract's body. A proxy's 404 page, a typo'd path, or a 403
// for a bad bearer is an error: it must not send everyone to the default,
// or deny everyone.
func TestRESTStatusNeedsTheContractBody(t *testing.T) {
	var body atomic.Value
	var status atomic.Int64
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(int(status.Load()))
		_, _ = w.Write([]byte(body.Load().(string)))
	}))
	t.Cleanup(ts.Close)
	r, err := NewREST(ts.URL, "", RESTOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		status int
		body   string
		want   error // nil: some other error
	}{
		{404, `{"result":"no_assignment"}`, ErrNoAnswer},
		{404, `<html>Not Found</html>`, nil},
		{404, ``, nil},
		{404, `{"result":"denied"}`, nil},
		{403, `{"result":"denied"}`, ErrDenied},
		{403, `{"error":"invalid bearer token"}`, nil},
		{403, ``, nil},
		{401, `{"result":"denied"}`, nil},
	} {
		status.Store(int64(tc.status))
		body.Store(tc.body)
		_, err := r.Assign(context.Background(), Request{User: "alice@example.org"})
		switch {
		case tc.want != nil && !errors.Is(err, tc.want):
			t.Errorf("%d %s: %v, want %v", tc.status, tc.body, err, tc.want)
		case tc.want == nil && (err == nil || errors.Is(err, ErrNoAnswer) || errors.Is(err, ErrDenied)):
			t.Errorf("%d %s: %v, want a backend error", tc.status, tc.body, err)
		}
	}

	// Through a chain with a default: a bare 404 is a 503, not the default.
	ch, err := Build(Config{Backends: []string{BackendREST}, RESTURL: ts.URL, Default: "ap1"}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	status.Store(404)
	body.Store("404 page not found")
	_, err = ch.Resolve(context.Background(), alice)
	wantErr(t, err, http.StatusServiceUnavailable, ReasonUnavailable)
}

// A reconfigure re-reads the backends, but a user's last known good answer
// survives it: a backend that breaks right after a reconfigure is covered
// like one that breaks at any other time.
func TestReloadKeepsLastKnownGood(t *testing.T) {
	clk := newClock()
	var broken atomic.Bool
	b := &fakeBackend{fn: func(Request) (Assignment, error) {
		if broken.Load() {
			return Assignment{}, errors.New("down")
		}
		return Assignment{Schedd: "ap2", TTL: time.Minute}, nil
	}}
	ch := newTestChain(t, []Backend{{Name: "rest", Assigner: b}}, Options{Now: clk.now})
	if _, err := ch.Resolve(context.Background(), alice); err != nil {
		t.Fatal(err)
	}
	if err := ch.Reload(); err != nil {
		t.Fatal(err)
	}
	// Reload made the answer stale: the backend is asked again.
	before := b.calls.Load()
	broken.Store(true)
	a, err := ch.Resolve(context.Background(), alice)
	if b.calls.Load() == before {
		t.Error("the backend was not asked again after a reload")
	}
	if err != nil || a.Schedd != "ap2" || !a.Stale {
		t.Errorf("after a reload with the backend down: %+v %v, want the last known good ap2", a, err)
	}
}

// REST.Reload with a token file that cannot be read keeps the token it has.
func TestRESTReloadKeepsTokenOnFailure(t *testing.T) {
	r, svc, tokFile := newREST(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"schedd":"ap1"}`))
	})
	if err := os.Remove(tokFile); err != nil {
		t.Fatal(err)
	}
	if err := r.Reload(); err == nil {
		t.Error("Reload of a missing token file reported no error")
	}
	// The file is gone; the request goes out with the token read before.
	_, _ = r.Assign(context.Background(), Request{User: "a@b"})
	if _, auth := svc.last(); auth != "Bearer s3cret" {
		t.Errorf("after a failed reload the header was %q, want the previous token", auth)
	}
}

// The cache keys on the caller's subject and groups too: an answer for a
// caller with no groups must not answer for the same user with groups.
func TestCacheKeyIncludesSubjectAndGroups(t *testing.T) {
	path := filepath.Join(t.TempDir(), "assign.map")
	writeMap(t, path, "GROUP physics ap3\nSUBJECT svc-alice ap4\n* /.*/ ap1\n")
	ch, err := Build(Config{Backends: []string{BackendMapfile}, Mapfile: path}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, tc := range []struct {
		req  Request
		want string
	}{
		{Request{User: "alice@d", Kind: KindJob}, "ap1"},
		{Request{User: "alice@d", Kind: KindJob, Groups: []string{"physics"}}, "ap3"},
		{Request{User: "alice@d", Kind: KindJob, Groups: []string{"users", "physics"}}, "ap3"},
		{Request{User: "alice@d", Kind: KindJob, Subject: "svc-alice"}, "ap4"},
		{Request{User: "alice@d", Kind: KindJob}, "ap1"},
	} {
		a, err := ch.Resolve(ctx, tc.req)
		if err != nil || a.Schedd != tc.want {
			t.Errorf("%+v: %s %v, want %s", tc.req, a.Schedd, err, tc.want)
		}
	}
	// Group order does not matter.
	if cacheKey(Request{User: "u", Groups: []string{"a", "b"}}) != cacheKey(Request{User: "u", Groups: []string{"b", "a"}}) {
		t.Error("the cache key depends on group order")
	}
}

// Checking the mapfile for changes is not on the request path: a file
// whose read hangs (a stuck NFS mount) must not hang a submission.
func TestMapfileReadDoesNotBlockRequests(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "assign.map")
	writeMap(t, path, "USER alice@d ap1\n")
	m, err := NewMapfile(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	m.checkEvery = time.Millisecond
	// Replace the file with a FIFO: opening it blocks until a writer comes.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	t.Cleanup(func() {
		// Unblock any reader left waiting on the FIFO.
		if f, err := os.OpenFile(path, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil { //nolint:gosec // the test's own FIFO
			_ = f.Close()
		}
	})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go m.Run(ctx)
	time.Sleep(20 * time.Millisecond) // let the background check start and block
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = m.Generation()
		if a, err := m.Assign(context.Background(), Request{User: "alice@d"}); err != nil || a.Schedd != "ap1" {
			t.Errorf("Assign while the file blocks: %+v %v, want the map in force", a, err)
		}
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("a request blocked on the mapfile's read")
	}
}

// A request whose caller has gone away is not a backend failure: nothing
// is logged as one, and no last known good answer is handed to nobody.
func TestCancelledRequestIsNotABackendFailure(t *testing.T) {
	logs := &logRecorder{}
	clk := newClock()
	b := &fakeBackend{fn: func(Request) (Assignment, error) { return Assignment{Schedd: "ap2", TTL: time.Second}, nil }}
	ch := newTestChain(t, []Backend{{Name: "rest", Assigner: b}}, Options{Now: clk.now, Logger: logs})
	if _, err := ch.Resolve(context.Background(), alice); err != nil {
		t.Fatal(err)
	}
	clk.advance(2 * time.Second)
	b.fn = func(Request) (Assignment, error) { return Assignment{}, context.Canceled }
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	a, err := ch.Resolve(ctx, alice)
	if err == nil || a.Stale {
		t.Errorf("cancelled request: %+v %v, want an error and no stale answer", a, err)
	}
	if n := logs.count("error") + logs.count("warn"); n != 0 {
		t.Errorf("a cancelled request logged %d backend failures", n)
	}
}

// The last-known-good window runs from when the answer expires, so a
// long-TTL answer is covered for the full window after it lapses.
func TestStaleWindowRunsFromExpiry(t *testing.T) {
	clk := newClock()
	var broken atomic.Bool
	b := &fakeBackend{fn: func(Request) (Assignment, error) {
		if broken.Load() {
			return Assignment{}, errors.New("down")
		}
		return Assignment{Schedd: "ap2", TTL: 50 * time.Minute}, nil
	}}
	ch := newTestChain(t, []Backend{{Name: "rest", Assigner: b}}, Options{Now: clk.now, Stale: time.Hour})
	if _, err := ch.Resolve(context.Background(), alice); err != nil {
		t.Fatal(err)
	}
	broken.Store(true)
	clk.advance(100 * time.Minute) // expired 50 minutes ago
	if a, err := ch.Resolve(context.Background(), alice); err != nil || !a.Stale {
		t.Fatalf("50 minutes after expiry, within the hour: %+v %v", a, err)
	}
	clk.advance(11 * time.Minute) // expired 61 minutes ago
	_, err := ch.Resolve(context.Background(), alice)
	wantErr(t, err, http.StatusServiceUnavailable, ReasonUnavailable)
}

// Plain http is accepted only to a literal loopback address: a name such
// as localhost resolves however the host's resolver says.
func TestRESTPlainHTTPOnlyToLiteralLoopback(t *testing.T) {
	for _, u := range []string{"http://localhost:8080", "http://LOCALHOST", "http://localhost.example.org"} {
		if _, err := NewREST(u, "", RESTOptions{}); err == nil {
			t.Errorf("%s was accepted", u)
		}
	}
	for _, u := range []string{"http://127.0.0.1:1", "http://[::1]:1", "http://127.1.2.3"} {
		if _, err := NewREST(u, "", RESTOptions{}); err != nil {
			t.Errorf("%s: %v", u, err)
		}
	}
}

// A transport error names the service, not the user it asked about: it
// goes to a log an administrator reads.
func TestRESTErrorsOmitTheQuery(t *testing.T) {
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	r, err := NewREST("http://"+addr, "", RESTOptions{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = r.Assign(context.Background(), Request{User: "alice@example.org", Subject: "secret-subject", Groups: []string{"hidden-group"}})
	if err == nil {
		t.Fatal("a closed port answered")
	}
	for _, leak := range []string{"alice", "secret-subject", "hidden-group"} {
		if strings.Contains(err.Error(), leak) {
			t.Errorf("error %q names %q", err, leak)
		}
	}
	if !strings.Contains(err.Error(), "/v1/assignment") {
		t.Errorf("error %q does not name the service", err)
	}
}

// A redirect is not followed: not to a live server that would answer,
// and the bearer never reaches it.
func TestRESTDoesNotFollowRedirects(t *testing.T) {
	var reached atomic.Int64
	var leaked atomic.Value
	leaked.Store("")
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached.Add(1)
		leaked.Store(r.Header.Get("Authorization"))
		_, _ = w.Write([]byte(`{"schedd":"evil.example.org"}`))
	}))
	t.Cleanup(evil.Close)
	r, _, _ := newREST(t, func(w http.ResponseWriter, req *http.Request) {
		http.Redirect(w, req, evil.URL+"/v1/assignment?"+req.URL.RawQuery, http.StatusFound) //nolint:gosec // the redirect under test
	})
	a, err := r.Assign(context.Background(), Request{User: "alice@example.org"})
	if err == nil || a.Schedd != "" {
		t.Errorf("a redirect answered %+v %v, want an error", a, err)
	}
	if n := reached.Load(); n != 0 {
		t.Errorf("the redirect target was asked %d times (Authorization %q)", n, leaked.Load())
	}
}

// USER compares the domain without regard to case, as HTCondor compares
// domains; the user part stays exact.
func TestMapfileUserDomainIsCaseInsensitive(t *testing.T) {
	path := filepath.Join(t.TempDir(), "assign.map")
	writeMap(t, path, "USER alice@Example.ORG ap1\nGROUP Physics@Example.org ap2\n")
	m, err := NewMapfile(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		req  Request
		want string
	}{
		{Request{User: "alice@example.org"}, "ap1"},
		{Request{User: "alice@EXAMPLE.org"}, "ap1"},
		{Request{User: "Alice@example.org"}, ""},
		{Request{User: "x@d", Groups: []string{"physics@example.org"}}, ""}, // groups are exact
	} {
		a, err := m.Assign(context.Background(), tc.req)
		if a.Schedd != tc.want || (tc.want == "" && !errors.Is(err, ErrNoAnswer)) {
			t.Errorf("%+v: %q %v, want %q", tc.req, a.Schedd, err, tc.want)
		}
	}
}

// A literal that looks like an expression is probably a mistake carried
// over from a classic-mode mapfile, where every principal is one; say so.
func TestMapfileWarnsOnRegexLookingLiteral(t *testing.T) {
	path := filepath.Join(t.TempDir(), "assign.map")
	writeMap(t, path, "USER ^alice@.*$ ap1\nGROUP \"cms.*\" ap2\nUSER bob@d ap3\n")
	logs := &logRecorder{}
	if _, err := NewMapfile(path, logs); err != nil {
		t.Fatal(err)
	}
	if n := logs.count("warn"); n != 2 {
		t.Errorf("%d warnings, want one per literal that looks like an expression (2)", n)
	}
}
