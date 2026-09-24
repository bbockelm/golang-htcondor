package issues

import (
	"regexp"
	"strings"
	"testing"
)

// The old pipeline, kept here as the oracle: twelve regexes over the
// whole message, then split. The optimised one masks per token, and the
// only way to know that is a speedup rather than a behaviour change is
// to run both over a corpus and compare.
var legacyRules = []struct {
	re   *regexp.Regexp
	with string
}{
	{regexp.MustCompile(`\b[a-zA-Z][a-zA-Z0-9+.-]*://[^\s,)"'|]+`), "<url>"},
	{regexp.MustCompile(`\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(\.\d+)?Z?\b`), "<time>"},
	{regexp.MustCompile(`\b\d{4}-\d{2}-\d{2}\b`), "<date>"},
	{regexp.MustCompile(`\bslot\d+(_\d+)?@\S+`), "<slot>"},
	{regexp.MustCompile(`\b[\w.-]+@[\w.-]+\b`), "<host>"},
	{regexp.MustCompile(`\bv?\d+\.\d+(\.\d+)+\b`), "<ver>"},
	{regexp.MustCompile(`\b\d{1,3}(\.\d{1,3}){3}(:\d+)?\b`), "<ip>"},
	{regexp.MustCompile(`(/[\w.+-]+){2,}/?`), "<path>"},
	{regexp.MustCompile(`\b[a-zA-Z][\w-]*(\.[\w-]+){2,}\b`), "<host>"},
	{regexp.MustCompile(`\b[0-9a-fA-F]{8,}\b`), "<hex>"},
	{regexp.MustCompile(`\b\d+\b`), "<num>"},
	{regexp.MustCompile(`\b(?:[a-zA-Z]+[_-]?)*\d[\w-]*\b`), "<id>"},
}

func legacyTokens(message string) []string {
	out := message
	for _, r := range legacyRules {
		out = r.re.ReplaceAllString(out, r.with)
	}
	return tokenize(out)
}

func TestPerTokenMaskingMatchesTheWholeMessagePipeline(t *testing.T) {
	msgs := []string{}
	for _, r := range corpus(4000, 60, 40) {
		msgs = append(msgs, r.Message)
	}
	msgs = append(msgs,
		"Error from slot1_40@glidein_181693_77062752@a529.anvil.rcac.purdue.edu: memory usage exceeded request_memory",
		"The job exceeded allowed execute duration of 20:00:00",
		"User requested pause new work; let current running jobs finish; no automatic restart (by user anzheng.li)",
		"Transfer output files failure at the execution point using protocol osdf. Details: Pelican Client Error: remote object already exists, upload aborted (Version: 7.26.0; Site: UWM-Mortimer) ( URL file = osdf:///ospool/uw-shared/x/Merged_2025-09-29T02:10:18.952_0000.root )||FILETRANSFER:1:non-zero exit (1) from /tmp/glide_AGd9bW/main/condor/libexec/stash_plugin. |",
		"Job disconnected too long: JobLeaseDuration (2400 seconds) expired",
		"Error from slot1_2@OTHER-EP.698b098b8a9c: memory usage exceeded request_memory",
		"started at 2025-09-29 02:10:18 and failed",
		"deadbeef cafebabe 10.0.0.1:9618 /var/lib/condor/execute/dir_1/glide_x",
	)
	mismatches := 0
	for _, m := range msgs {
		want := strings.Join(legacyTokens(m), " ")
		got := strings.Join(MaskedTokens(m), " ")
		if got != want && mismatches < 5 {
			mismatches++
			t.Errorf("masking differs\n  message: %s\n      old: %s\n      new: %s", m, want, got)
		}
	}
}
