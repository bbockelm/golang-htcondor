package httpserver

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestDecodeStringListHandlesStoredJSON is the regression test for the admin
// UI showing OAuth2 scopes and grant types as JSON fragments.
//
// The storage layer writes these columns with json.Marshal, so the row holds
// `["openid","mcp:read"]`. Splitting that on commas produced list items like
// `["openid"` and `"mcp:read"]`, which the SPA faithfully rendered — brackets,
// quotes and all.
func TestDecodeStringListHandlesStoredJSON(t *testing.T) {
	// Build the input the same way CreateClient does, rather than
	// hand-writing it, so this stays honest if the encoding changes.
	scopes := []string{"openid", "offline_access", "mcp:read", "mcp:write"}
	blob, err := json.Marshal(scopes)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	got := decodeStringList(string(blob))
	if strings.Join(got, ",") != strings.Join(scopes, ",") {
		t.Errorf("decodeStringList(%s) = %q, want %q", blob, got, scopes)
	}
	for _, v := range got {
		if strings.ContainsAny(v, `["]`) {
			t.Errorf("scope %q still carries JSON punctuation", v)
		}
	}
}

func TestDecodeStringList(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
		want []string
	}{
		{"json array", `["a","b"]`, []string{"a", "b"}},
		{"json array with spaces", `["a", "b"]`, []string{"a", "b"}},
		{"empty json array", `[]`, nil},
		{"json array of empties", `["",""]`, nil},
		{"single element", `["only"]`, []string{"only"}},
		// Legacy rows, and any column that was never JSON-encoded.
		{"comma separated", "a,b", []string{"a", "b"}},
		{"space separated", "a b", []string{"a", "b"}},
		{"empty", "", nil},
		{"whitespace only", "   ", nil},
		// A value containing a comma survives JSON decoding but would be
		// mangled by the old splitter — which is the point of parsing.
		{"element containing a comma", `["a,b","c"]`, []string{"a,b", "c"}},
		// Malformed JSON falls back to splitting rather than vanishing.
		// The result is ugly — the punctuation survives — but the
		// fallback's job is to not lose the value, not to clean it up,
		// and an admin looking at a corrupt row should see the corruption.
		{"malformed json falls back verbatim", `["a"`, []string{`["a"`}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := decodeStringList(tc.in)
			if len(got) != len(tc.want) {
				t.Fatalf("decodeStringList(%q) = %q, want %q", tc.in, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("decodeStringList(%q)[%d] = %q, want %q", tc.in, i, got[i], tc.want[i])
				}
			}
		})
	}
}
