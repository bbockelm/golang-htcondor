package agentguide

import (
	"strings"
	"testing"
)

// TestSubmitOutputStatesTheRule: the text is the whole of this package, so
// the only thing to check is that it still says the things the surfaces
// quoting it are relying on it to say. A rewrite that drops the /dev/null
// sentence leaves both assistants free to write it again.
func TestSubmitOutputStatesTheRule(t *testing.T) {
	text := SubmitOutput()
	for _, want := range []string{
		"output", "error", "log", // all three commands named
		"/dev/null", // the spelling an assistant reaches for
		"$(ProcId)", // what makes the names per-process
		"DISCARD",   // the consequence, stated as such
	} {
		if !strings.Contains(text, want) {
			t.Errorf("the submit-output rule no longer mentions %q", want)
		}
	}
}

// TestSubmitOutputIsMarkdownSection: both destinations splice this into a
// larger Markdown document, so it has to start as a section of one and not
// bring its own trailing blank lines into the join.
func TestSubmitOutputIsMarkdownSection(t *testing.T) {
	text := SubmitOutput()
	if !strings.HasPrefix(text, "## ") {
		t.Errorf("the block should open with a Markdown heading, got %q", firstLine(text))
	}
	if strings.HasSuffix(text, "\n\n") {
		t.Error("the block should end with a single newline; the caller adds the separation")
	}
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
