package httpserver

import (
	"strings"
	"unicode"
)

// The placement identity is the "foreign ID" a browser session presents to
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

// placementForeignIDMaxLen is pdwebapp's MAX_USERNAME_LENGTH, counted in
// code points as Python slices strings.
const placementForeignIDMaxLen = 64

// defaultPlacementIdentityClaims is pdwebapp's default USERNAME_FIELDS.
var defaultPlacementIdentityClaims = []string{"sub"}

// defaultPlacementDisplayNameClaims is pdwebapp's DISPLAY_NAME_FIELDS.
var defaultPlacementDisplayNameClaims = []string{"name"}

// placementForeignID derives the foreign ID from userinfo claims: the first
// listed claim holding a non-empty string, sanitized. It returns "" when no
// claim qualifies -- or when the result sanitizes to nothing, which pdwebapp
// would have refused as well.
func placementForeignID(claims map[string]any, order []string) string {
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
// string, unsanitized: it is only ever shown to its owner.
func placementDisplayName(claims map[string]any, order []string) string {
	if len(order) == 0 {
		order = defaultPlacementDisplayNameClaims
	}
	for _, name := range order {
		if v, ok := claims[name].(string); ok && v != "" {
			return v
		}
	}
	return ""
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
	if len(out) > placementForeignIDMaxLen {
		out = out[:placementForeignIDMaxLen]
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
