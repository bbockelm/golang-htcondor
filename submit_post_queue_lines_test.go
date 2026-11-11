package htcondor

import (
	"strings"
	"testing"
)

// TestLinesAfterQueueDoNotReachTheAd pins where a submit file stops being
// read. condor_submit reads only as far as the queue line
// (parse_up_to_q_line in submit_utils.cpp); the queue statement ends the
// cluster and what follows belongs to the next one.
//
// `+Attr` is the case that matters, because it is the only kind of line that
// ever got past the queue statement here: every other spelling, `My.Attr`
// among them, is read as a queue argument and fails the parse, so none of
// them could reach the ad to be noticed. A `+Attr` below `queue` used to land
// on the job.
//
// Failing that parse is itself a divergence -- condor_submit accepts the file
// and starts a second cluster -- but a separate one, and not what this fixes.
func TestLinesAfterQueueDoNotReachTheAd(t *testing.T) {
	cases := []struct {
		name string
		src  string
	}{
		{"plus form", "executable = /bin/sleep\nqueue\n+Late = \"leaked\"\n"},
		{"no trailing newline", "executable = /bin/sleep\nqueue\n+Late = \"leaked\""},
		{"empty value", "executable = /bin/sleep\nqueue\n+Late ="},
		{"after queue with a count", "executable = /bin/sleep\nqueue 2\n+Late = \"leaked\"\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sf, err := ParseSubmitFile(strings.NewReader(tc.src))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			ad, err := sf.MakeJobAd(JobID{Cluster: 1, Proc: 0}, nil)
			if err != nil {
				t.Fatalf("MakeJobAd: %v", err)
			}
			if v, ok := ad.Lookup("Late"); ok {
				t.Errorf("Late = %s; a line after the queue statement is not part of this cluster", v)
			}
		})
	}
}

// TestPlusAttributeBeforeQueueStillLands is the other half: stopping at the
// queue line must not stop one line early.
func TestPlusAttributeBeforeQueueStillLands(t *testing.T) {
	sf, err := ParseSubmitFile(strings.NewReader("executable = /bin/sleep\n+Early = \"kept\"\nqueue\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	ad, err := sf.MakeJobAd(JobID{Cluster: 1, Proc: 0}, nil)
	if err != nil {
		t.Fatalf("MakeJobAd: %v", err)
	}
	v, ok := ad.Lookup("Early")
	if !ok {
		t.Fatal("Early is not on the ad")
	}
	if got := v.String(); got != `"kept"` {
		t.Errorf("Early = %s, want \"kept\"", got)
	}
}
