package mcpserver

import (
	"strings"
	"testing"

	"github.com/bbockelm/golang-htcondor/webapi/agentguide"
)

// TestSubmitFilesTopicCarriesTheSharedRules: the submit-file guidance an
// MCP agent reads and the guidance the browser assistant reads have to be
// the same guidance. They were not, and the half that was missing was the
// half saying where a job's output goes -- so the assistant that had only
// its own copy scaffolded jobs that threw their output away.
//
// The matching assertion on the other surface is in httpserver.
func TestSubmitFilesTopicCarriesTheSharedRules(t *testing.T) {
	text, ok := guideText("submit_files")
	if !ok {
		t.Fatal("the guide has no submit_files topic")
	}
	if !strings.Contains(text, agentguide.SubmitOutput()) {
		t.Error("the submit_files topic no longer contains the shared submit-output rules verbatim")
	}
}

// TestGuideAppendixNamesRealTopics: an appendix keyed on a topic that does
// not exist is text nobody is ever served, and nothing else would notice.
func TestGuideAppendixNamesRealTopics(t *testing.T) {
	for topic := range guideAppendix {
		if _, ok := guideText(topic); !ok {
			t.Errorf("guideAppendix names %q, which is not a guide topic", topic)
		}
	}
}
