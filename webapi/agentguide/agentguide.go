// Package agentguide holds the guidance that every agent surface on this
// server states identically.
//
// Two assistants write submit descriptions here: the MCP server, which
// serves agents running outside this process, and the chat assistant on the
// web submission page. They are separate code paths carrying separate
// prompts, and a rule written into only one of them is a rule the other
// gets wrong. That is not hypothetical -- the chat assistant scaffolded
// custom templates whose stdout and stderr went nowhere and which had no
// event log, because the paragraph telling it not to existed only in the
// MCP guide.
//
// What belongs here is the narrow set of rules both surfaces must say the
// same way: facts about HTCondor that hold no matter who is asking. What
// does not belong here is anything a surface knows and the other cannot --
// MCP's tool names, the submission page's UI affordances -- which stays in
// each surface's own text.
//
// The blocks are Markdown because both destinations are Markdown: an MCP
// doc_guide topic and an LLM system prompt.
package agentguide

import _ "embed"

//go:embed submit_output.md
var submitOutput string

// SubmitOutput is the rule for output, error and log: set all three, to
// real files, every time.
//
// It is a rule rather than a suggestion because the failure is silent and
// unrecoverable. A job whose output was discarded looks exactly like a job
// that printed nothing, and the bytes are not recoverable afterwards at any
// price -- the only remedy is to run the work again. submitlint.Inspect
// warns about the same mistake after the fact; this is the half that can
// still prevent it.
func SubmitOutput() string { return submitOutput }
