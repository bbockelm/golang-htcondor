package mcpserver

import (
	"bytes"
	"encoding/json"
	"path"
	"strings"
	"sync"

	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/webapi/redact"
)

// Masking credentials in tool results.
//
// Several tools hand a caller bytes that a job produced, and a job's
// output is whatever the job wrote. `get_job_stdout` on a job whose
// payload ran `cat $_CONDOR_CREDS/<service>.use`, or whose framework
// logged the config it had just loaded, returns that credential. So does
// `exec_in_job`, and so does `get_job_output` for any file in the
// sandbox. The caller is usually a model, so the credential lands in a
// context window and from there in a transcript and a provider's logs.
//
// None of that is an attack. It is a job printing its own environment,
// which jobs do, and the point of masking it is the same as the point of
// masking a build log: to make the accident less likely, not to stop
// somebody who means it. Anyone who can run code in a job can encode a
// credential past any pattern, and this does not pretend otherwise.
//
// Applied at the one chokepoint both transports share, for two reasons.
// A tool added later is covered without anybody remembering to cover it,
// which is how the admin-view redaction and the tool results came to
// disagree in the first place. And the surfaces that were not on
// anyone's list are covered too: a hold reason quoting the presigned URL
// a transfer failed on reaches a caller through analyze_issues, not
// through any of the tools the report named.

// redactionExemptTools are the tools whose results are NOT masked.
//
// Not a policy setting, which is why it is here and not in the operator's
// configuration. The entire output of these three is a credential this
// server has just minted for the caller, and masking it does not protect
// anything -- the caller is the party it was minted for -- while handing
// back a URL that cannot be redeemed. The failure would surface later and
// somewhere else, as "invalid or expired token" at whoever fetched it.
var redactionExemptTools = []string{
	"create_output_download_url",
	"create_input_upload_url",
	"create_watch_url",
}

// redactionState is what a reconfigure swaps in.
//
// A stored state with a nil Redactor means the operator turned masking
// OFF. No stored state at all means nobody has configured it, and that
// is deliberately not the same thing: a Server built by some path that
// does not call SetSecretRedaction gets the default rules rather than
// nothing. Collapsing the two would make "nobody wired this up" and
// "the site asked for no masking" indistinguishable, and the first of
// those is a bug that should not quietly turn the feature off.
type redactionState struct {
	r *redact.Redactor
}

// defaultRedactor is what an unconfigured Server uses. Built once:
// compiling the rule set is not free and the result is immutable.
var defaultRedactor = sync.OnceValue(func() *redact.Redactor {
	r, _, _ := redact.New(redact.Default(), nil)
	return r
})

// SetSecretRedaction installs the operator's masking policy: the dynamic
// half of HTTP_API_MCP_REDACT_SECRETS and HTTP_API_MCP_REDACT_DISABLED_RULES.
//
// Logs what it did, in both directions. A site that turns this off has
// made a decision somebody should be able to find later in a log, and a
// site that disables a rule because it was noisy needs to see that the
// setting took -- a mistyped rule id is otherwise indistinguishable from
// a rule that stopped matching.
func (s *Server) SetSecretRedaction(enabled bool, disabledRules string) {
	if !enabled {
		s.redaction.Store(&redactionState{})
		s.logger.Info(logging.DestinationMCP,
			"MCP credential masking is off; job output reaches callers exactly as the job wrote it",
			"setting", "HTTP_API_MCP_REDACT_SECRETS")
		return
	}

	off := splitList(disabledRules)
	r, dropped, unmatched := redact.New(redact.Default(), off)
	for _, pat := range unmatched {
		s.logger.Error(logging.DestinationMCP,
			"Ignoring an HTTP_API_MCP_REDACT_DISABLED_RULES pattern that names no rule; the rules it was meant to turn off are still in force",
			"pattern", pat)
	}
	if len(dropped) > 0 {
		s.logger.Info(logging.DestinationMCP, "MCP credential masking rules turned off by configuration",
			"rules", strings.Join(dropped, " "))
	}
	s.redaction.Store(&redactionState{r: r})
}

// splitList parses a comma- or whitespace-separated setting, matching how
// the other by-name settings here are written.
func splitList(spec string) []string {
	return strings.FieldsFunc(spec, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
	})
}

// redactorFor returns the redactor to apply to one tool's result, or nil
// when the result is to be returned as it is.
func (s *Server) redactorFor(tool string) *redact.Redactor {
	st := s.redaction.Load()
	if st != nil && st.r == nil {
		return nil // the site turned masking off
	}
	for _, exempt := range redactionExemptTools {
		if ok, err := path.Match(exempt, tool); err == nil && ok {
			return nil
		}
	}
	if st == nil {
		// Never configured; see redactionState.
		return defaultRedactor()
	}
	return st.r
}

// redactToolResult masks credentials in one successful tool result and
// says so in the result when it changed anything.
//
// Returns the result untouched -- the same value, not a copy -- when
// nothing matched, which is the overwhelmingly common case and the one
// worth not paying for.
func (s *Server) redactToolResult(tool string, result interface{}) interface{} {
	r := s.redactorFor(tool)
	if r == nil || result == nil {
		return result
	}

	// Marshalling is how the result is examined, because that is the
	// form it is about to be sent in anyway. Walking the Go value
	// instead would mean reflecting over whatever a handler returned --
	// typed structs, *classad.ClassAd with its own marshaller, maps
	// shared with server state -- and getting that wrong means either
	// mutating state a handler still holds or missing a field.
	raw, err := json.Marshal(result)
	if err != nil {
		// A result that cannot be marshalled cannot be sent either, so
		// the transport is about to fail on this anyway. Nothing is
		// masked and nothing is claimed to be.
		s.logger.Warn(logging.DestinationMCP,
			"could not examine a tool result for credentials; returning it unmasked",
			"tool", tool, "error", err.Error())
		return result
	}
	if !r.MightContain(raw) {
		return result
	}

	// UseNumber, so a job id or a byte count comes back out of the walk
	// as the digits it went in as. Decoding JSON numbers into float64 --
	// the default -- would silently re-render anything past 2^53, and
	// this is a filter, not a place where values change.
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var generic interface{}
	if err := dec.Decode(&generic); err != nil {
		s.logger.Warn(logging.DestinationMCP,
			"could not examine a tool result for credentials; returning it unmasked",
			"tool", tool, "error", err.Error())
		return result
	}

	walked, res := redactValue(generic, r)
	if !res.Changed() {
		// The prescan found a needle and no rule matched it. Hand back
		// the original rather than the round-tripped copy.
		return result
	}

	m, ok := walked.(map[string]interface{})
	if !ok {
		// Every handler returns a result envelope, so there is nowhere
		// to put the note. The masking stands -- returning the
		// credential would be worse -- but say so, because a result
		// changed without the caller being told is the one outcome this
		// is not supposed to produce.
		s.logger.Warn(logging.DestinationMCP,
			"masked credentials in a tool result with no envelope to carry the notice",
			"tool", tool, "values", res.Values())
		return walked
	}
	noteRedaction(m, res)
	s.logger.Info(logging.DestinationMCP, "masked credentials in a tool result",
		"tool", tool, "values", res.Values(), "rules", strings.Join(res.Kinds(), " "))
	return m
}

// redactValue walks a decoded JSON value, masking every string in it.
//
// Every string, rather than the text blocks alone: a handler files the
// same bytes under `content` for a person to read and under
// `structuredContent` for a client to parse, and masking one of the two
// leaves the credential in the result and puts a note on it saying
// otherwise.
func redactValue(v interface{}, r *redact.Redactor) (interface{}, *redact.Result) {
	switch t := v.(type) {
	case string:
		out, res := r.Redact(t)
		return out, res
	case map[string]interface{}:
		var all *redact.Result
		for k, e := range t {
			out, res := redactValue(e, r)
			if res.Changed() {
				t[k] = out
				all = all.Merge(res)
			}
		}
		return t, all
	case []interface{}:
		var all *redact.Result
		for i, e := range t {
			out, res := redactValue(e, r)
			if res.Changed() {
				t[i] = out
				all = all.Merge(res)
			}
		}
		return t, all
	default:
		return v, nil
	}
}

// noteRedaction tells the caller the result was changed.
//
// Both halves of the result, because both have a reader. The text block
// is what a model sees, and without the note it has output with a hole
// in it and no account of why -- which reads as a broken tool, and the
// reasonable next move is to try a different one for the same bytes. The
// structured payload gets the same fact as data, for a client that acts
// on results rather than reading them.
func noteRedaction(m map[string]interface{}, res *redact.Result) {
	summary := map[string]interface{}{
		"applied": true,
		"values":  res.Values(),
		"kinds":   res.Kinds(),
	}
	for _, key := range []string{"structuredContent", "metadata"} {
		if sc, ok := m[key].(map[string]interface{}); ok {
			sc["redaction"] = summary
		}
	}

	note := res.Note()
	blocks, ok := m["content"].([]interface{})
	if !ok {
		m["content"] = []interface{}{map[string]interface{}{"type": "text", "text": note}}
		return
	}
	// Appended to the last text block rather than added as a block of
	// its own: a client that renders only the first block -- several do --
	// would otherwise never show it.
	for i := len(blocks) - 1; i >= 0; i-- {
		b, ok := blocks[i].(map[string]interface{})
		if !ok || b["type"] != "text" {
			continue
		}
		text, _ := b["text"].(string)
		b["text"] = strings.TrimRight(text, "\n") + "\n\n" + note
		return
	}
	m["content"] = append(blocks, map[string]interface{}{"type": "text", "text": note})
}
