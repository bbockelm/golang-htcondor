package mcpserver

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/bbockelm/golang-htcondor/logging"
)

// What masking costs per call, end to end: marshal the result, prescan
// it, and -- only when a needle hits -- decode and walk it.
//
// Here rather than in the redact package because the engine's own
// numbers understate this by about half, and that is not an accident of
// the benchmark. A result carries the job's output three times: once in
// the text block a person reads, and once in each of `metadata` and
// `structuredContent`, which handlers build from the same map. The
// prescan runs over the marshalled form, so it sees all three.
//
// Three corpora, because what the prescan does with a result is the
// whole cost model. "plain" trips no needle and is returned untouched.
// "needled" contains the words that wake the broadest rules -- a query
// string, the word "token" -- so the rules run and match nothing.
// "dirty" actually carries a credential, so it is decoded and walked
// as well.
func BenchmarkRedactToolResultCost(b *testing.B) {
	logger, _ := logging.New(&logging.Config{OutputPath: "stderr"})
	s := &Server{logger: logger}
	s.SetSecretRedaction(true, "")

	line := map[string]string{
		"plain":   "2026-11-07 14:23:11 INFO  event 148213 chi2=1.2345e-08 out=/srv/run/part-00031.root sha=9f8c2a1b4d6e8f0a2c4e6080a2c4e6080a2c4e60\n",
		"needled": "2026-11-07 14:23:11 INFO  GET https://data.example.edu/f.root?range=0-1024 auth=token refreshed, 148213 events\n",
		"dirty":   "2026-11-07 14:23:11 INFO  pushing with ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n", //nolint:gosec // G101: a fixture
	}
	for _, size := range []int{4 << 10, 100 << 10, 1 << 20} {
		for _, kind := range []string{"plain", "needled", "dirty"} {
			var sb strings.Builder
			for sb.Len() < size {
				sb.WriteString(line[kind])
			}
			text := sb.String()
			name := map[int]string{4 << 10: "4KB", 100 << 10: "100KB", 1 << 20: "1MB"}[size]
			b.Run(name+"/"+kind, func(b *testing.B) {
				b.SetBytes(int64(len(text)))
				for i := 0; i < b.N; i++ {
					s.redactToolResult("get_job_stdout", outputResult(text))
				}
			})
		}
	}
}

// What the result costs to marshal at all, which the transport pays
// whether or not this change exists. The honest denominator.
func BenchmarkMarshalAlone(b *testing.B) {
	var sb strings.Builder
	for sb.Len() < 100<<10 {
		sb.WriteString("2026-11-07 14:23:11 INFO  event 148213 chi2=1.2345e-08 out=/srv/run/part-00031.root\n")
	}
	r := outputResult(sb.String())
	b.SetBytes(int64(sb.Len()))
	for i := 0; i < b.N; i++ {
		if _, err := json.Marshal(r); err != nil {
			b.Fatal(err)
		}
	}
}
