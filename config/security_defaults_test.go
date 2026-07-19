package config

import (
	"strings"
	"testing"
)

// TestCryptoMethodDefault verifies the bootstrapped crypto default resolves with no operator
// config. (The authentication-method defaults are built programmatically in the security
// layer from cedar's implemented methods, not bootstrapped here — see the htcondor package's
// security tests.)
func TestCryptoMethodDefault(t *testing.T) {
	cfg, err := NewFromReader(strings.NewReader(""))
	if err != nil {
		t.Fatal(err)
	}
	got, ok := cfg.Get("SEC_DEFAULT_CRYPTO_METHODS")
	if !ok || strings.TrimSpace(got) != "AES" {
		t.Errorf("SEC_DEFAULT_CRYPTO_METHODS = %q (ok=%v), want AES", got, ok)
	}
}

// TestSubsystemPrefixResolution is the regression for the client Subsystem bug: an operator
// value scoped TOOL.<param> resolves only when the config was built with Subsystem "TOOL"
// (as the htcondordb-cli/capi clients now do); an empty subsystem silently ignores it.
func TestSubsystemPrefixResolution(t *testing.T) {
	const text = "TOOL.SEC_CLIENT_AUTHENTICATION_METHODS = FS SSL PASSWORD\n"

	withTool, err := NewFromReaderWithOptions(strings.NewReader(text), ConfigOptions{Subsystem: "TOOL"})
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := withTool.Get("SEC_CLIENT_AUTHENTICATION_METHODS"); !ok || got != "FS SSL PASSWORD" {
		t.Errorf("with Subsystem=TOOL: got %q (ok=%v), want operator value 'FS SSL PASSWORD'", got, ok)
	}

	// Empty subsystem: the TOOL.-scoped value is invisible, so it falls back to the default.
	noSub, err := NewFromReader(strings.NewReader(text))
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := noSub.Get("SEC_CLIENT_AUTHENTICATION_METHODS"); got == "FS SSL PASSWORD" {
		t.Errorf("empty subsystem should NOT resolve the TOOL.-scoped override, but got %q", got)
	}
}
