package apassign

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// restService is a test assignment service that records what it was
// asked.
type restService struct {
	mu      sync.Mutex
	queries []string
	auths   []string
	handler func(w http.ResponseWriter, r *http.Request)
}

func (s *restService) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.queries = append(s.queries, r.URL.Path+"?"+r.URL.RawQuery)
	s.auths = append(s.auths, r.Header.Get("Authorization"))
	s.mu.Unlock()
	s.handler(w, r)
}

func (s *restService) last() (string, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.queries[len(s.queries)-1], s.auths[len(s.auths)-1]
}

func newREST(t *testing.T, h func(w http.ResponseWriter, r *http.Request)) (*REST, *restService, string) {
	t.Helper()
	svc := &restService{handler: h}
	ts := httptest.NewServer(svc)
	t.Cleanup(ts.Close)
	tokFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokFile, []byte("s3cret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := NewREST(ts.URL+"/base/", tokFile, RESTOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return r, svc, tokFile
}

func TestRESTAnswers(t *testing.T) {
	r, svc, _ := newREST(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("user") {
		case "alice@example.org":
			_, _ = w.Write([]byte(`{"schedd":"ap12.example.org","alternates":["ap13.example.org"],"ttl_seconds":120,"extra":1}`))
		case "nobody@example.org":
			w.WriteHeader(http.StatusNotFound)
		case "banned@example.org":
			w.WriteHeader(http.StatusForbidden)
		case "broken@example.org":
			http.Error(w, "boom", http.StatusInternalServerError)
		case "redirect@example.org":
			http.Redirect(w, r, "https://elsewhere.example.org/", http.StatusFound)
		case "garbage@example.org":
			_, _ = w.Write([]byte(`<html>not json</html>`))
		case "empty@example.org":
			_, _ = w.Write([]byte(`{"alternates":["x"]}`))
		case "huge@example.org":
			_, _ = w.Write([]byte(`{"schedd":"ap1","pad":"` + strings.Repeat("x", RESTMaxBody) + `"}`))
		case "nottl@example.org":
			_, _ = w.Write([]byte(`{"schedd":"ap1"}`))
		}
	})
	ctx := context.Background()

	a, err := r.Assign(ctx, Request{User: "alice@example.org", Subject: "https://idp/alice", Groups: []string{"cms", "a b"}, Kind: KindDAG})
	if err != nil || a.Schedd != "ap12.example.org" || strings.Join(a.Alternates, ",") != "ap13.example.org" || a.TTL != 2*time.Minute {
		t.Fatalf("got %+v %v", a, err)
	}
	q, auth := svc.last()
	if auth != "Bearer s3cret" {
		t.Errorf("Authorization %q", auth)
	}
	for _, want := range []string{"/base/v1/assignment?", "user=alice%40example.org", "subject=https%3A%2F%2Fidp%2Falice",
		"kind=dag", "group=cms", "group=a+b"} {
		if !strings.Contains(q, want) {
			t.Errorf("request %q lacks %q", q, want)
		}
	}

	if _, err := r.Assign(ctx, Request{User: "nobody@example.org"}); !errors.Is(err, ErrNoAnswer) {
		t.Errorf("404: %v, want ErrNoAnswer", err)
	}
	if _, err := r.Assign(ctx, Request{User: "banned@example.org"}); !errors.Is(err, ErrDenied) {
		t.Errorf("403: %v, want ErrDenied", err)
	}
	for _, u := range []string{"broken", "redirect", "garbage", "empty", "huge"} {
		_, err := r.Assign(ctx, Request{User: u + "@example.org"})
		if err == nil || errors.Is(err, ErrNoAnswer) || errors.Is(err, ErrDenied) {
			t.Errorf("%s: %v, want a backend error", u, err)
		}
	}
	if a, err := r.Assign(ctx, Request{User: "nottl@example.org"}); err != nil || a.TTL != 0 {
		t.Errorf("no ttl_seconds: %+v %v, want TTL 0 (the backend default applies)", a, err)
	}
}

func TestRESTTimeout(t *testing.T) {
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	svc := &restService{handler: func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}}
	ts := httptest.NewServer(svc)
	t.Cleanup(ts.Close)
	r, err := NewREST(ts.URL, "", RESTOptions{Client: &http.Client{Timeout: 100 * time.Millisecond}})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if _, err := r.Assign(context.Background(), Request{User: "a@b"}); err == nil {
		t.Fatal("a hung service answered")
	}
	if el := time.Since(start); el > 2*time.Second {
		t.Errorf("took %v", el)
	}
	// A client timeout longer than the chain's is clamped to it.
	r, err = NewREST(ts.URL, "", RESTOptions{Client: &http.Client{Timeout: time.Hour}})
	if err != nil {
		t.Fatal(err)
	}
	if r.client.Timeout != DefaultTimeout {
		t.Errorf("client timeout %v, want %v", r.client.Timeout, DefaultTimeout)
	}
}

// Through the chain, a 500 is an error that does not fall through to the
// default, and a 404 is "ask the next".
func TestRESTInChain(t *testing.T) {
	status := http.StatusInternalServerError
	var mu sync.Mutex
	svc := &restService{handler: func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.WriteHeader(status)
	}}
	ts := httptest.NewServer(svc)
	t.Cleanup(ts.Close)
	ch, err := Build(Config{Backends: []string{BackendREST}, RESTURL: ts.URL, Default: "ap1"}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = ch.Resolve(context.Background(), alice)
	wantErr(t, err, http.StatusServiceUnavailable, ReasonUnavailable)
	mu.Lock()
	status = http.StatusNotFound
	mu.Unlock()
	a, err := ch.Resolve(context.Background(), alice)
	if err != nil || a.Schedd != "ap1" {
		t.Fatalf("404 then default: %+v %v", a, err)
	}
}

func TestRESTTokenFileReread(t *testing.T) {
	r, svc, tokFile := newREST(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"schedd":"ap1"}`))
	})
	if _, err := r.Assign(context.Background(), Request{User: "a@b"}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tokFile, []byte("rotated-token-value"), 0o600); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(time.Minute)
	if err := os.Chtimes(tokFile, future, future); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Assign(context.Background(), Request{User: "a@b"}); err != nil {
		t.Fatal(err)
	}
	if _, auth := svc.last(); auth != "Bearer rotated-token-value" {
		t.Errorf("after rotation the header was %q", auth)
	}
}

func TestNewRESTValidation(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct {
		url, token, err string
	}{
		{url: "", err: "needs HTTP_API_AP_ASSIGNMENT_REST_URL"},
		{url: "http://assign.example.org", err: "must use https"},
		{url: "ftp://assign.example.org", err: "https"},
		{url: "assign.example.org/v1", err: "absolute"},
		{url: "https://assign.example.org/?x=1", err: "query"},
		{url: "https://assign.example.org", token: filepath.Join(dir, "missing"), err: "TOKEN_FILE"},
	} {
		if _, err := NewREST(tc.url, tc.token, RESTOptions{}); err == nil || !strings.Contains(err.Error(), tc.err) {
			t.Errorf("%q: %v, want %q", tc.url, err, tc.err)
		}
	}
	for _, ok := range []string{"https://assign.example.org/base", "http://127.0.0.1:8080", "http://localhost:1", "http://[::1]:2"} {
		if _, err := NewREST(ok, "", RESTOptions{}); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	empty := filepath.Join(dir, "empty")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewREST("https://a.example.org", empty, RESTOptions{}); err == nil {
		t.Error("an empty token file was accepted")
	}
}

func TestRESTOverTLS(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"schedd":"ap9"}`))
	}))
	t.Cleanup(ts.Close)
	r, err := NewREST(ts.URL, "", RESTOptions{Client: ts.Client()})
	if err != nil {
		t.Fatal(err)
	}
	if a, err := r.Assign(context.Background(), Request{User: "a@b"}); err != nil || a.Schedd != "ap9" {
		t.Fatalf("%+v %v", a, err)
	}
}
