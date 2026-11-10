package mcpserver

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/bbockelm/golang-htcondor/logging"
)

// serverWithRedaction builds the smallest server that can run a result
// through the masking step.
func serverWithRedaction(t *testing.T, enabled bool, disabledRules string) *Server {
	t.Helper()
	logger, err := logging.New(&logging.Config{OutputPath: "stderr"})
	if err != nil {
		t.Fatalf("building a logger: %v", err)
	}
	s := &Server{logger: logger}
	s.SetSecretRedaction(enabled, disabledRules)
	return s
}

// A result as a handler builds one: the curated text and the structured
// payload carrying the same bytes.
func outputResult(text string) map[string]interface{} {
	structured := map[string]interface{}{
		"job_id":      "42.0",
		"output_type": "stdout",
		"size":        len(text),
		"content":     text,
	}
	return map[string]interface{}{
		"content":           []map[string]interface{}{{"type": "text", "text": "Job 42.0 stdout:\n" + text}},
		"metadata":          structured,
		"structuredContent": structured,
	}
}

func TestRedactsBothHalvesOfAResult(t *testing.T) {
	s := serverWithRedaction(t, true, "")
	const secret = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

	out := s.redactToolResult("get_job_stdout", outputResult("pushing with "+secret+"\n"))

	raw, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("marshalling the masked result: %v", err)
	}
	// The whole point of masking the structured half too: a handler
	// files the same bytes twice, and leaving one copy would put the
	// credential in the result under a note saying it was not there.
	if strings.Contains(string(raw), secret) {
		t.Fatalf("the credential survived somewhere in the result:\n%s", raw)
	}
	if !strings.Contains(string(raw), "REDACTED:github-token") {
		t.Errorf("no marker in the result:\n%s", raw)
	}
}

func TestNoteIsAppendedToTheTextBlock(t *testing.T) {
	s := serverWithRedaction(t, true, "")
	out := s.redactToolResult("get_job_stdout",
		outputResult("token: ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"))

	m := out.(map[string]interface{})
	blocks := m["content"].([]interface{})
	last := blocks[len(blocks)-1].(map[string]interface{})
	text := last["text"].(string)

	if !strings.Contains(text, "Job 42.0 stdout:") {
		t.Errorf("the note replaced the output instead of following it:\n%s", text)
	}
	if !strings.Contains(text, "replaced with [REDACTED:...]") {
		t.Errorf("the caller is not told the result was changed:\n%s", text)
	}

	// The structured half carries the same fact as data, for a client
	// that acts on results rather than reading them.
	sc := m["structuredContent"].(map[string]interface{})
	red, ok := sc["redaction"].(map[string]interface{})
	if !ok {
		t.Fatalf("no redaction summary in structuredContent: %#v", sc)
	}
	if red["applied"] != true {
		t.Errorf("redaction summary does not say it applied: %#v", red)
	}
}

// Nothing to mask must cost nothing and change nothing -- not even the
// identity of the value, since a round-trip through JSON would quietly
// re-render anything the encoder spells differently.
func TestCleanResultIsReturnedUntouched(t *testing.T) {
	s := serverWithRedaction(t, true, "")
	in := outputResult("job completed, 148213 events, 0 errors\n")
	out := s.redactToolResult("get_job_stdout", in)

	m, ok := out.(map[string]interface{})
	if !ok {
		t.Fatalf("result changed type: %T", out)
	}
	if _, has := m["structuredContent"].(map[string]interface{})["redaction"]; has {
		t.Error("a clean result was annotated as redacted")
	}
	blocks := m["content"].([]map[string]interface{})
	if strings.Contains(blocks[0]["text"].(string), "REDACTED") {
		t.Error("a clean result was modified")
	}
}

// A tool whose entire output is a credential this server just minted for
// the caller must come back intact. Masking it protects nobody -- the
// caller is who it was minted for -- and returns a URL that cannot be
// redeemed, with the failure surfacing later and somewhere else.
func TestURLMintingToolsAreExempt(t *testing.T) {
	s := serverWithRedaction(t, true, "")
	// Shaped like what shareurl.Signer produces: base64url payload, a
	// dot, base64url HMAC. Its payload is JSON, so it opens with `eyJ`.
	url := "https://ap.example.edu/api/v1/share/output?t=" +
		"eyJDbHVzdGVyIjoxMjM0LCJQcm9jIjowLCJPd25lciI6ImJib2NrZWxtIn0.c2lnbmF0dXJlYnl0ZXNoZXJl"

	for _, tool := range []string{"create_output_download_url", "create_input_upload_url", "create_watch_url"} {
		in := map[string]interface{}{
			"content":           []map[string]interface{}{{"type": "text", "text": "Download: " + url}},
			"structuredContent": map[string]interface{}{"url": url},
		}
		raw, _ := json.Marshal(s.redactToolResult(tool, in))
		if !strings.Contains(string(raw), url) {
			t.Errorf("%s: the minted URL did not survive:\n%s", tool, raw)
		}
	}
}

func TestDisablingRedactionEntirely(t *testing.T) {
	s := serverWithRedaction(t, false, "")
	const secret = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	raw, _ := json.Marshal(s.redactToolResult("get_job_stdout", outputResult(secret)))
	if !strings.Contains(string(raw), secret) {
		t.Errorf("masking was off and something was masked anyway:\n%s", raw)
	}
}

func TestDisablingOneRule(t *testing.T) {
	s := serverWithRedaction(t, true, "github-*")
	const tok = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	const key = "AKIAIOSFODNN7EXAMPLE" //nolint:gosec // G101: AWS's own documented example key, as a fixture
	raw, _ := json.Marshal(s.redactToolResult("get_job_stdout", outputResult(tok+" "+key)))
	if !strings.Contains(string(raw), tok) {
		t.Error("a disabled rule still fired")
	}
	if strings.Contains(string(raw), key) {
		t.Error("turning off one rule turned off another")
	}
}

// The masking step runs after finalizeToolResult, so whatever that step
// promised about the result's shape has to still be true afterwards.
// Numbers are the part most easily lost: the walk decodes the result
// from JSON, and the default decoding turns every number into a float64.
func TestNumbersSurviveTheWalk(t *testing.T) {
	s := serverWithRedaction(t, true, "")
	structured := map[string]interface{}{ //nolint:gosec // G101: a fixture shaped like a token, which is the point
		"bytes_sent":   int64(9007199254740993), // 2^53 + 1
		"cluster":      42,
		"content":      "token: ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"elapsed_secs": 1.5,
	}
	in := map[string]interface{}{
		"content":           []map[string]interface{}{{"type": "text", "text": "x"}},
		"structuredContent": structured,
	}
	raw, err := json.Marshal(s.redactToolResult("get_job_stdout", in))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"bytes_sent":9007199254740993`, `"cluster":42`, `"elapsed_secs":1.5`} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("expected %s in the result:\n%s", want, raw)
		}
	}
}

// One credential printed in both halves of a result is one secret, not
// two. A caller told "2" goes looking for a second one.
func TestOneSecretInTwoPlacesCountsOnce(t *testing.T) {
	s := serverWithRedaction(t, true, "")
	out := s.redactToolResult("get_job_stdout",
		outputResult("ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"))
	sc := out.(map[string]interface{})["structuredContent"].(map[string]interface{})
	red := sc["redaction"].(map[string]interface{})
	if red["values"] != 1 {
		t.Errorf("expected 1 distinct secret, got %v", red["values"])
	}
}

// A Server nobody configured masks anyway. "Not wired up" is a bug, and
// the version of that bug where the feature silently does nothing is the
// one that would not be noticed -- the results look exactly like results
// from a site that chose to turn it off.
func TestUnconfiguredServerStillMasks(t *testing.T) {
	s := &Server{}
	if s.redactorFor("get_job_stdout") == nil {
		t.Fatal("a Server that was never configured does no masking at all")
	}
	// And the site's own "off" is still honoured, or this would be a
	// setting that cannot be turned off.
	s = serverWithRedaction(t, false, "")
	if s.redactorFor("get_job_stdout") != nil {
		t.Error("an explicit off was overridden by the default")
	}
}

// Masking is on unless a site asks for it off. A Config built without
// mentioning it -- by a test, or by a caller written before the setting
// existed -- has to get the protective behaviour.
func TestDefaultIsOn(t *testing.T) {
	logger, err := logging.New(&logging.Config{OutputPath: "stderr"})
	if err != nil {
		t.Fatalf("building a logger: %v", err)
	}
	s := &Server{logger: logger}
	var cfg Config
	s.SetSecretRedaction(!cfg.DisableSecretRedaction, cfg.RedactDisabledRules)
	if s.redactorFor("get_job_stdout") == nil {
		t.Fatal("a zero Config left credential masking off")
	}
}

// The masking step files its summary under `redaction` in the structured
// payload, which adds a property to a result whose outputSchema a client
// validates. A schema that constrained its top level -- additionalProperties
// false, or a type every property must satisfy -- would turn a masked
// result into a client-side failure for a tool that succeeded, which is
// the exact failure structured_contract.go exists to prevent.
//
// Two schemas already constrain additionalProperties to a number type,
// at `totals` and `slot_types`. They are nested, so the summary does not
// reach them, and this is what says so out loud.
func TestEverySchemaAcceptsTheRedactionSummary(t *testing.T) {
	for tool := range outputSchemas {
		schema := outputSchemaFor(tool)
		if schema == nil {
			t.Errorf("%s: outputSchemaFor disagrees with the outputSchemas table", tool)
			continue
		}
		ap, has := schema["additionalProperties"]
		if !has {
			// Absent means permitted, per JSON Schema.
			continue
		}
		if allowed, ok := ap.(bool); ok && allowed {
			continue
		}
		t.Errorf("%s: its outputSchema constrains additionalProperties to %#v, "+
			"so the redaction summary would not validate", tool, ap)
	}
}
