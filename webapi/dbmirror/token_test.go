package dbmirror

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// A Locator with no token source behaves exactly as before: no token is
// offered and nothing is reported about it. A deployment that never
// configured one has not misconfigured anything.
func TestNoTokenSourceIsSilent(t *testing.T) {
	l := NewLocator(nil, nil)

	if got := l.Health().TokenError; got != "" {
		t.Errorf("TokenError = %q, want empty when no source is configured", got)
	}
}

// A source that fails must not be silent: the connection then falls back
// to the ambient methods, and a dial error naming FS, Kerberos and SSL
// reads as exhaustive while omitting the one that was skipped.
func TestFailingTokenSourceIsReported(t *testing.T) {
	l := NewLocator(nil, nil)
	l.SetTokenSource(func(context.Context) (string, error) {
		return "", errors.New("signing key unreadable")
	})

	l.noteTokenFailure(errors.New("signing key unreadable"))

	got := l.Health().TokenError
	if !strings.Contains(got, "signing key unreadable") {
		t.Errorf("TokenError = %q, want the underlying reason", got)
	}
}

// An empty token with no error is its own failure mode and must not read
// as success.
func TestEmptyTokenIsReported(t *testing.T) {
	l := NewLocator(nil, nil)
	l.noteTokenFailure(nil)

	if got := l.Health().TokenError; !strings.Contains(got, "empty token") {
		t.Errorf("TokenError = %q, want it to name the empty token", got)
	}
}

// The setter is what the handler uses after construction, so it has to
// actually take effect.
func TestSetTokenSourceTakesEffect(t *testing.T) {
	l := NewLocator(nil, nil)
	if l.opts.TokenSource != nil {
		t.Fatal("a fresh Locator should have no token source")
	}
	l.SetTokenSource(func(context.Context) (string, error) { return "tok", nil })
	if l.opts.TokenSource == nil {
		t.Fatal("SetTokenSource did not attach the source")
	}
	got, err := l.opts.TokenSource(context.Background())
	if err != nil || got != "tok" {
		t.Errorf("source returned (%q, %v)", got, err)
	}
}

// Calling it on a nil Locator must not panic: mirror routing is optional
// and callers hold a possibly-nil one.
func TestSetTokenSourceOnNilLocator(_ *testing.T) {
	var l *Locator
	l.SetTokenSource(func(context.Context) (string, error) { return "", nil })
}
