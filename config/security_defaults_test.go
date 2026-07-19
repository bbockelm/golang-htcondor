package config

import (
	"strings"
	"testing"
)

// TestSecurityMethodDefaults verifies the bootstrapped security defaults resolve even with
// no operator config (the "missing bootstrapping" fix): these params live only inside
// param_info.in metaknobs upstream, so without an override cfg.Get returns false and
// encryption/auth negotiation has no configured basis.
func TestSecurityMethodDefaults(t *testing.T) {
	cfg, err := NewFromReader(strings.NewReader(""))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		key       string
		want      string
		substring bool
	}{
		{"SEC_DEFAULT_CRYPTO_METHODS", "AES", false},
		{"SEC_CLIENT_CRYPTO_METHODS", "AES", false},              // $(SEC_DEFAULT_CRYPTO_METHODS)
		{"SEC_CLIENT_AUTHENTICATION_METHODS", "ANONYMOUS", true}, // ...,ANONYMOUS for encrypted READ
		{"SEC_DEFAULT_AUTHENTICATION_METHODS", "IDTOKENS", true}, // pre-existing override
	}
	for _, c := range cases {
		got, ok := cfg.Get(c.key)
		if !ok {
			t.Errorf("%s: not set (bootstrap default missing)", c.key)
			continue
		}
		if c.substring {
			if !strings.Contains(got, c.want) {
				t.Errorf("%s = %q, want it to contain %q", c.key, got, c.want)
			}
		} else if strings.TrimSpace(got) != c.want {
			t.Errorf("%s = %q, want %q", c.key, got, c.want)
		}
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
