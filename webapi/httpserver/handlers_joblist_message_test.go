package httpserver

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode"
)

// The explanation is concatenated into a sentence by every consumer --
// the jobs page renders it directly after "Showing the first N jobs." --
// so it has to be whole sentences on its own. A lowercase fragment
// reads as a broken line in the UI, which is how it was first noticed.
func TestPaginationExplanationIsWholeSentences(t *testing.T) {
	// The trailer closes an array the handler opened, so it only parses
	// in context.
	body := `{"jobs":[]` + strings.TrimPrefix(scheddJobListTrailer(10, 10, ""), "]")
	var got map[string]any
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatalf("trailer does not close a valid document: %v\n%s", err, body)
	}
	msg, _ := got["pagination_unavailable"].(string)
	if msg == "" {
		t.Fatal("a truncated, unpageable answer must explain itself")
	}
	if r := []rune(msg)[0]; !unicode.IsUpper(r) {
		t.Errorf("starts lowercase, so it reads as a fragment where it is appended: %q", msg)
	}
	if !strings.HasSuffix(msg, ".") {
		t.Errorf("does not end a sentence, so the next clause runs into it: %q", msg)
	}
}
