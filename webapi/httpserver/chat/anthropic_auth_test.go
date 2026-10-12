package chat

import (
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeKey stages an API key file with the given mode, the way an
// operator (or the kubelet) would.
func writeKey(t *testing.T, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(path, []byte("sk-test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// WriteFile's mode is subject to umask; chmod is not.
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestNewAnthropicClientKeyFileMode pins the mode policy to the one the
// KEK loader uses: other-bits are refused, group bits are not. 0440 is
// what a Kubernetes secret volume is under fsGroup, and a stricter
// check here crash-looped the server at startup with "has world/group
// perms" on exactly that deployment.
func TestNewAnthropicClientKeyFileMode(t *testing.T) {
	cases := []struct {
		mode os.FileMode
		ok   bool
	}{
		{0o600, true},
		{0o400, true},
		{0o440, true},
		{0o640, true},
		{0o644, false},
		{0o604, false},
		{0o444, false},
	}
	for _, tc := range cases {
		c, err := NewAnthropicClient(AnthropicConfig{APIKeyFile: writeKey(t, tc.mode)})
		if tc.ok {
			if err != nil {
				t.Errorf("mode %#o: unexpected error: %v", tc.mode, err)
			} else if c == nil {
				t.Errorf("mode %#o: nil client", tc.mode)
			}
			continue
		}
		if err == nil {
			t.Errorf("mode %#o: expected refusal, got a client", tc.mode)
		} else if !strings.Contains(err.Error(), "world-accessible") {
			t.Errorf("mode %#o: unexpected error text: %v", tc.mode, err)
		}
	}
}

// roundTripFunc adapts a function to http.RoundTripper so the test can
// see the request the client built.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// TestStreamAuthScheme checks which header carries the key. Anthropic's
// API reads x-api-key; a gateway in front of it (Envoy AI Gateway,
// LiteLLM) authenticates "Authorization: Bearer" and ignores x-api-key,
// answering 403 to a request that only has the latter.
func TestStreamAuthScheme(t *testing.T) {
	cases := []struct {
		scheme     string
		wantAPIKey string
		wantAuthz  string
	}{
		{"", "sk-test", ""},
		{"x-api-key", "sk-test", ""},
		{"bearer", "", "Bearer sk-test"},
		{"Bearer", "", "Bearer sk-test"},
	}
	for _, tc := range cases {
		var got *http.Request
		client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			got = r
			body := "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
				Body:       io.NopCloser(strings.NewReader(body)),
				Request:    r,
			}, nil
		})}
		c, err := NewAnthropicClient(AnthropicConfig{
			APIKeyFile: writeKey(t, 0o600),
			AuthScheme: tc.scheme,
			HTTPClient: client,
		})
		if err != nil {
			t.Fatalf("scheme %q: %v", tc.scheme, err)
		}
		// Drain the stream so the goroutine runs to completion; the
		// stub answers a bare message_stop, so this returns at once.
		events := 0
		for range c.Stream(context.Background(), "", nil, nil, "") {
			events++
		}
		_ = events
		if got == nil {
			t.Fatalf("scheme %q: no request dispatched", tc.scheme)
		}
		if v := got.Header.Get("x-api-key"); v != tc.wantAPIKey {
			t.Errorf("scheme %q: x-api-key = %q, want %q", tc.scheme, v, tc.wantAPIKey)
		}
		if v := got.Header.Get("Authorization"); v != tc.wantAuthz {
			t.Errorf("scheme %q: Authorization = %q, want %q", tc.scheme, v, tc.wantAuthz)
		}
		if v := got.Header.Get("anthropic-version"); v != AnthropicAPIVersion {
			t.Errorf("scheme %q: anthropic-version = %q", tc.scheme, v)
		}
	}
}

// TestNewAnthropicClientRejectsUnknownAuthScheme: a typo in the config
// is a startup error, not a silent fall-back to x-api-key that fails
// 403 on the first chat.
func TestNewAnthropicClientRejectsUnknownAuthScheme(t *testing.T) {
	_, err := NewAnthropicClient(AnthropicConfig{APIKeyFile: writeKey(t, 0o600), AuthScheme: "basic"})
	if err == nil || !strings.Contains(err.Error(), "unknown LLM auth scheme") {
		t.Fatalf("expected unknown-scheme error, got %v", err)
	}
}
