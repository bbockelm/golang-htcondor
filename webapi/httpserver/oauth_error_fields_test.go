package httpserver

import (
	"errors"
	"fmt"
	"testing"

	"github.com/ory/fosite"
)

// fieldsMap turns the key/value slice into a map for assertions.
func fieldsMap(t *testing.T, kv []any) map[string]string {
	t.Helper()
	if len(kv)%2 != 0 {
		t.Fatalf("odd number of log fields: %d", len(kv))
	}
	m := make(map[string]string, len(kv)/2)
	for i := 0; i < len(kv); i += 2 {
		m[fmt.Sprint(kv[i])] = fmt.Sprint(kv[i+1])
	}
	return m
}

// TestOAuthErrorFieldsSurfacesDebug is the regression this exists for: a
// token-endpoint 500 reached the log as "error=server_error
// root_error=server_error" and told the operator nothing, because
// RFC6749Error.Error() is just the code and the cause was in DebugField.
func TestOAuthErrorFieldsSurfacesDebug(t *testing.T) {
	err := fosite.ErrServerError.WithDebug("sql: no rows in result set")

	got := fieldsMap(t, oauthErrorFields(err))

	if got["error"] != "server_error" {
		t.Errorf("error = %q, want server_error", got["error"])
	}
	if got["debug"] != "sql: no rows in result set" {
		t.Errorf("debug = %q, want the storage error", got["debug"])
	}
	// The bug was that this was the ONLY thing logged.
	if len(got) < 2 {
		t.Errorf("only %d field(s) logged (%v); the debug detail is the whole point", len(got), got)
	}
}

// TestOAuthErrorFieldsIncludesWrappedCause covers the other shape, where
// fosite carries a separate wrapped error rather than a debug string.
func TestOAuthErrorFieldsIncludesWrappedCause(t *testing.T) {
	cause := errors.New("connection refused")
	err := fosite.ErrServerError.WithWrap(cause)

	got := fieldsMap(t, oauthErrorFields(err))
	if got["cause"] != "connection refused" {
		t.Errorf("cause = %q, want %q", got["cause"], cause)
	}
}

// TestOAuthErrorFieldsNonFositeError keeps plain errors readable rather
// than dropping them when they are not RFC6749Errors.
func TestOAuthErrorFieldsNonFositeError(t *testing.T) {
	got := fieldsMap(t, oauthErrorFields(errors.New("boom")))
	if got["error"] != "boom" {
		t.Errorf("error = %q, want boom", got["error"])
	}
}

// TestOAuthErrorFieldsNoDuplicateCause guards the noise case: fosite's
// base errors are their own cause, and logging "cause=server_error"
// next to "error=server_error" is the uninformative output this
// replaced.
func TestOAuthErrorFieldsNoDuplicateCause(t *testing.T) {
	got := fieldsMap(t, oauthErrorFields(fosite.ErrServerError))
	if c, ok := got["cause"]; ok && c == got["error"] {
		t.Errorf("cause %q duplicates error %q", c, got["error"])
	}
}
