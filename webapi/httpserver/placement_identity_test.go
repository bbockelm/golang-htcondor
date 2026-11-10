package httpserver

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// The expected values below were produced by CPython 3.14 running pdwebapp's
// sanitizer, re.sub(r"[^@.\w-]+", "_", s.strip())[:64]. They cover the three
// places Python's behavior differs from a naive Go port: Unicode-aware \w
// (letters and numbers of every script, but not combining marks), Unicode
// str.strip (including U+001C..U+001F, which Go does not call space), and
// truncation by code point rather than byte.
func TestSanitizePlacementUsernameMatchesPdwebapp(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"alice@wisc.edu", "alice@wisc.edu"},
		{"http://cilogon.org/serverA/users/12345", "http_cilogon.org_serverA_users_12345"},
		{"  bob@example.org \t", "bob@example.org"},
		{"Ünïcødé.User@例え.jp", "Ünïcødé.User@例え.jp"},
		{"éclair@example.org", "e_clair@example.org"},
		{"user name with spaces", "user_name_with_spaces"},
		{`a+b=c/d\e`, "a_b_c_d_e"},
		{"\x1cpadded\x1f", "padded"},
		{" nbsp　", "nbsp"},
		{"x²³½Ⅻ٣", "x²³½Ⅻ٣"},
		{"emoji😀here", "emoji_here"},
		{"tab\tand\nnewline", "tab_and_newline"},
		{"--..@@__", "--..@@__"},
		{strings.Repeat("a", 70), strings.Repeat("a", 64)},
		{strings.Repeat("é", 70), strings.Repeat("é", 64)},
		{"日本語ユーザー@大学.ac.jp", "日本語ユーザー@大学.ac.jp"},
		{"!!!", "_"},
		{"café\u200bzero-width", "café_zero-width"},
		{"O'Brien@uni.edu", "O_Brien@uni.edu"},
	} {
		if got := sanitizePlacementUsername(tc.in); got != tc.want {
			t.Errorf("sanitize(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestSanitizedIdentityIsAtMost64CodePoints(t *testing.T) {
	got := sanitizePlacementUsername(strings.Repeat("日", 100))
	if n := utf8.RuneCountInString(got); n != 64 {
		t.Errorf("length = %d code points, want 64", n)
	}
}

func TestPlacementIdentityTakesFirstNonEmptyClaim(t *testing.T) {
	claims := map[string]any{
		"eppn":   "",
		"email":  42, // not a string: skipped, as pdwebapp skips it
		"sub":    "http://cilogon.org/serverA/users/7",
		"name":   "Alice Example",
		"groups": []any{"a"},
	}
	if got := placementIdentityFromClaims(claims, []string{"eppn", "email", "sub"}); got != "http_cilogon.org_serverA_users_7" {
		t.Errorf("identity = %q", got)
	}
	if got := placementIdentityFromClaims(claims, nil); got != "http_cilogon.org_serverA_users_7" {
		t.Errorf("default (sub) identity = %q", got)
	}
	if got := placementIdentityFromClaims(claims, []string{"eppn", "missing"}); got != "" {
		t.Errorf("no usable claim gave %q, want empty", got)
	}
	if got := placementDisplayName(claims, nil); got != "Alice Example" {
		t.Errorf("display name = %q", got)
	}
}
