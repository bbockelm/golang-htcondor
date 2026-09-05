package htcondor

import (
	"strings"
	"testing"
)

// The rule two APIs now share, stated once.
func TestValidateOAuthCredential(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		reject bool
		why    string
	}{
		{
			name:  "a JSON document is what the credd expects",
			input: `{"access_token":"abc","expires_in":3600}`,
		},
		{
			name:  "empty asks a credmon to mint one",
			input: "",
			why:   "a local credmon watches for the stored file and never reads it",
		},
		{
			name:   "a bare token stores and then breaks every read",
			input:  "abc123",
			reject: true,
		},
		{
			name:   "truncated JSON is still not JSON",
			input:  `{"access_token":`,
			reject: true,
		},
		{
			name:  "a JSON scalar is valid JSON, so the credd can parse it",
			input: `"abc123"`,
			why:   "this checks parseability, which is what the credd needs; it is not a schema check",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateOAuthCredential("scitokens", []byte(tc.input))
			switch {
			case tc.reject && err == nil:
				t.Fatalf("accepted %q; storing it succeeds and then fails every later read", tc.input)
			case !tc.reject && err != nil:
				t.Fatalf("refused %q: %v (%s)", tc.input, err, tc.why)
			}
			if err == nil {
				return
			}
			// The error is the only thing the caller sees, and the
			// caller is usually a model or a script that has no other
			// way to learn the rule. It has to name the service, say
			// what is wrong, and show what right looks like.
			for _, want := range []string{"scitokens", "not valid JSON", "access_token"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("the error omits %q, so it does not explain itself: %v", want, err)
				}
			}
		})
	}
}
