package httpserver

import (
	"strings"
	"unicode"
)

// The placement identity is the "identity" a browser session presents to
// condor_placementd: the left-hand column of its map file.
//
// It must come out byte-for-byte what CHTC's placement-webapp (pdwebapp)
// produced from the same claims, or every existing map file line stops
// matching. pdwebapp takes the first non-empty string among an ordered list
// of userinfo claims (USERNAME_FIELDS) and passes it through
//
//	re.sub(r"[^@.\w-]+", "_", name.strip())[:64]
//
// in Python 3, where str.strip, \w and slicing are all Unicode-aware. The
// functions below reproduce those three exactly; placement_identity_test.go
// holds vectors generated with CPython.

// placementIdentityMaxLen is pdwebapp's MAX_USERNAME_LENGTH, counted in
// code points as Python slices strings.
const placementIdentityMaxLen = 64

// defaultPlacementIdentityClaims is pdwebapp's default USERNAME_FIELDS.
var defaultPlacementIdentityClaims = []string{"sub"}

// defaultPlacementDisplayNameClaims is pdwebapp's DISPLAY_NAME_FIELDS.
var defaultPlacementDisplayNameClaims = []string{"name"}

// placementIdentity derives the identity from userinfo claims: the first
// listed claim holding a non-empty string, sanitized. It returns "" when no
// claim qualifies -- or when the result sanitizes to nothing, which pdwebapp
// would have refused as well.
func placementIdentityFromClaims(claims map[string]any, order []string) string {
	if len(order) == 0 {
		order = defaultPlacementIdentityClaims
	}
	for _, name := range order {
		raw, ok := claims[name].(string)
		if !ok || raw == "" {
			continue
		}
		return sanitizePlacementUsername(raw)
	}
	return ""
}

// placementDisplayName is the first listed claim holding a non-empty
// string, as profileText makes it: it is shown to its owner, and to
// administrators with an access request.
func placementDisplayName(claims map[string]any, order []string) string {
	if len(order) == 0 {
		order = defaultPlacementDisplayNameClaims
	}
	for _, name := range order {
		if v, ok := claims[name].(string); ok {
			if v = profileText(v); v != "" {
				return v
			}
		}
	}
	return ""
}

// placementEmail is the provider's email claim, as profileText makes it,
// when the provider says it verified the address (email_verified true);
// otherwise "". An unverified address is whatever the person typed into
// their account, and administrators would read it as a fact.
func placementEmail(claims map[string]any) string {
	switch v := claims["email_verified"].(type) {
	case bool:
		if !v {
			return ""
		}
	case string:
		if !strings.EqualFold(v, "true") {
			return ""
		}
	default:
		return ""
	}
	email, _ := claims["email"].(string)
	return profileText(email)
}

// profileTextMaxLen bounds a name or email kept from the provider, in
// characters.
const profileTextMaxLen = 256

// profileText is text a provider sent about a person, made fit to keep
// and show: control and invisible format characters (bidirectional
// overrides, zero-width characters) removed, trimmed, and at most
// profileTextMaxLen characters.
func profileText(s string) string {
	s = strings.ToValidUTF8(s, "")
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if r := []rune(s); len(r) > profileTextMaxLen {
		s = strings.TrimSpace(string(r[:profileTextMaxLen]))
	}
	return s
}

// sanitizePlacementUsername is pdwebapp's util.sanitize_username.
func sanitizePlacementUsername(name string) string {
	name = strings.TrimFunc(name, pythonIsSpace)
	var b strings.Builder
	inRun := false
	for _, r := range name {
		if r == '@' || r == '.' || r == '-' || pythonIsWord(r) {
			b.WriteRune(r)
			inRun = false
			continue
		}
		// [^@.\w-]+ replaces a whole run with one underscore.
		if !inRun {
			b.WriteByte('_')
			inRun = true
		}
	}
	out := []rune(b.String())
	if len(out) > placementIdentityMaxLen {
		out = out[:placementIdentityMaxLen]
	}
	return string(out)
}

// pythonIsWord is \w in a Python 3 str pattern: str.isalnum() or '_'.
// isalnum is a letter (categories L*) or a character with a numeric type,
// which in practice is category N*. Combining marks are NOT word
// characters there, unlike in some other regex engines.
func pythonIsWord(r rune) bool {
	return r == '_' || unicode.IsLetter(r) || unicode.IsNumber(r)
}

// pythonIsSpace is str.isspace(): Go's unicode.IsSpace plus the four
// information separators U+001C..U+001F, which Python counts as whitespace
// (bidirectional class B or S) and Go does not.
func pythonIsSpace(r rune) bool {
	return unicode.IsSpace(r) || (r >= 0x1c && r <= 0x1f)
}
