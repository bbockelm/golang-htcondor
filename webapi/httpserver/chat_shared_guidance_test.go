package httpserver

import (
	"strings"
	"testing"

	"github.com/bbockelm/golang-htcondor/webapi/agentguide"
)

// TestSubmitPagePromptCarriesTheSharedRules: the submission page's
// assistant writes submit descriptions, and the rules it follows have to
// be the same ones the MCP server gives the agents it serves. They were
// not: this prompt said nothing about output, error or log, so templates
// it scaffolded sent stdout and stderr to /dev/null and had no event log.
//
// The matching assertion on the other surface is in mcpserver.
func TestSubmitPagePromptCarriesTheSharedRules(t *testing.T) {
	prompt, ok := chatPageInstructions()["submit"]
	if !ok {
		t.Fatal("no system-prompt entry for the submit page")
	}
	if !strings.Contains(prompt, agentguide.SubmitOutput()) {
		t.Error("the submit page's prompt no longer contains the shared submit-output rules verbatim")
	}
}

// TestSubmitPagePromptKeepsItsOwnRules guards the splice: composing the
// prompt from two halves plus a shared block is easy to get wrong in a way
// that silently drops one half, and the half carrying "do not write a queue
// line" is load-bearing for the page.
func TestSubmitPagePromptKeepsItsOwnRules(t *testing.T) {
	prompt := chatPageInstructions()["submit"]
	for _, want := range []string{
		"The user is on the job-submission page.", // opens with the head
		"DO NOT write a \"queue\" line",           // last rule before the splice
		"list_submit_templates",                   // first rule after it
		"SAVING A TEMPLATE:",                      // closes with the tail
	} {
		if !strings.Contains(prompt, want) {
			t.Errorf("the composed submit prompt is missing %q", want)
		}
	}
}
