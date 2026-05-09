package httpserver

import (
	"strings"
	"testing"
)

// TestEncodeJobAttributeValue locks the JSON-shape → ClassAd-expression
// mapping for the PATCH /api/v1/jobs[/{id}] handler. The cases that
// matter most are:
//
//   - String escaping. We rely on classad.Quote (= fmt.Sprintf("%q", v))
//     for backslash/quote/newline/tab handling. A regression that goes
//     back to a hand-rolled "replace \\ then \"" loop would reintroduce
//     the silent-corruption-on-newlines bug the SPA edit row tripped on.
//
//   - Bare-value pass-through for the chat-tool API surface — strings
//     are assumed to be pre-encoded ClassAd, numbers/bools/null take
//     the obvious shape.
//
//   - Type validation: bad input never silently becomes a literal-bad
//     classad expression that the schedd parser rejects with a
//     mysterious 500.
func TestEncodeJobAttributeValue(t *testing.T) {
	t.Run("BareStringPassThrough", func(t *testing.T) {
		// The chat tool path: LLM provided a ClassAd expression like
		// `"already-quoted"` or `RequestMemory * 2`. Don't double-quote.
		got, err := encodeJobAttributeValue("X", `"already-quoted"`)
		if err != nil {
			t.Fatal(err)
		}
		if got != `"already-quoted"` {
			t.Errorf("bare string was rewritten: got %q", got)
		}
	})

	t.Run("BareNumber", func(t *testing.T) {
		got, _ := encodeJobAttributeValue("X", float64(42))
		if got != "42" {
			t.Errorf("integer-valued float lost: got %q", got)
		}
		got, _ = encodeJobAttributeValue("X", float64(3.5))
		if got != "3.5" {
			t.Errorf("real lost: got %q", got)
		}
	})

	t.Run("BareBool", func(t *testing.T) {
		gotT, _ := encodeJobAttributeValue("X", true)
		gotF, _ := encodeJobAttributeValue("X", false)
		if gotT != "true" || gotF != "false" {
			t.Errorf("bool encoding wrong: %q / %q", gotT, gotF)
		}
	})

	t.Run("BareNullIsUndefined", func(t *testing.T) {
		got, _ := encodeJobAttributeValue("X", nil)
		if got != "UNDEFINED" {
			t.Errorf("null encoding wrong: %q", got)
		}
	})

	t.Run("TypedStringQuotesViaLibrary", func(t *testing.T) {
		// The SPA path: user typed raw text including quotes,
		// backslashes, and newlines. The library has to escape them
		// all. This is the case my hand-rolled JS encoder got wrong.
		input := map[string]any{
			"type":  "string",
			"value": "line1\nline2\twith \"quotes\" and \\back",
		}
		got, err := encodeJobAttributeValue("X", input)
		if err != nil {
			t.Fatal(err)
		}
		// Surrounding quotes
		if !strings.HasPrefix(got, `"`) || !strings.HasSuffix(got, `"`) {
			t.Errorf("missing surrounding quotes: %q", got)
		}
		// Escapes for each special char. Don't pin the EXACT byte
		// sequence (the library could legitimately emit \x0A vs \n)
		// — just verify no raw newline / tab leaked through.
		if strings.ContainsRune(got, '\n') {
			t.Errorf("raw newline leaked into encoded string: %q", got)
		}
		if strings.ContainsRune(got, '\t') {
			t.Errorf("raw tab leaked into encoded string: %q", got)
		}
		// Inner quote got escaped.
		if !strings.Contains(got, `\"`) {
			t.Errorf("inner quote not escaped: %q", got)
		}
		// Inner backslash got escaped.
		if !strings.Contains(got, `\\`) {
			t.Errorf("inner backslash not escaped: %q", got)
		}
	})

	t.Run("TypedInteger", func(t *testing.T) {
		got, err := encodeJobAttributeValue("X", map[string]any{
			"type": "integer", "value": "42",
		})
		if err != nil || got != "42" {
			t.Errorf("integer typed: got=%q err=%v", got, err)
		}
		// A leading + or surrounding whitespace should still parse.
		got, err = encodeJobAttributeValue("X", map[string]any{
			"type": "integer", "value": "  -7  ",
		})
		if err != nil || got != "-7" {
			t.Errorf("trimmed integer: got=%q err=%v", got, err)
		}
		// Non-integer rejected.
		if _, err := encodeJobAttributeValue("X", map[string]any{
			"type": "integer", "value": "1.5",
		}); err == nil {
			t.Error("expected error on non-integer typed integer")
		}
	})

	t.Run("TypedReal", func(t *testing.T) {
		got, err := encodeJobAttributeValue("X", map[string]any{
			"type": "real", "value": "3.14",
		})
		if err != nil || got != "3.14" {
			t.Errorf("real: got=%q err=%v", got, err)
		}
	})

	t.Run("TypedBoolean", func(t *testing.T) {
		got, _ := encodeJobAttributeValue("X", map[string]any{
			"type": "boolean", "value": "TRUE",
		})
		if got != "true" {
			t.Errorf("uppercase TRUE not normalised: %q", got)
		}
		if _, err := encodeJobAttributeValue("X", map[string]any{
			"type": "boolean", "value": "yes",
		}); err == nil {
			t.Error("expected error on non-true/false boolean")
		}
	})

	t.Run("TypedRaw", func(t *testing.T) {
		got, err := encodeJobAttributeValue("X", map[string]any{
			"type": "raw", "value": "RequestMemory * 2",
		})
		if err != nil || got != "RequestMemory * 2" {
			t.Errorf("raw passthrough: got=%q err=%v", got, err)
		}
		// Empty raw rejected — too easy to "set X to nothing"
		// silently and have it become a literal empty string.
		if _, err := encodeJobAttributeValue("X", map[string]any{
			"type": "raw", "value": "   ",
		}); err == nil {
			t.Error("expected error on whitespace-only raw expression")
		}
	})

	t.Run("TypedUnknownType", func(t *testing.T) {
		if _, err := encodeJobAttributeValue("X", map[string]any{
			"type": "octopus", "value": "8",
		}); err == nil {
			t.Error("expected error on unknown type")
		}
	})

	t.Run("TypedMissingFields", func(t *testing.T) {
		if _, err := encodeJobAttributeValue("X", map[string]any{
			"value": "42",
		}); err == nil {
			t.Error("expected error when 'type' missing")
		}
		if _, err := encodeJobAttributeValue("X", map[string]any{
			"type": "string",
		}); err == nil {
			t.Error("expected error when 'value' missing")
		}
	})
}
