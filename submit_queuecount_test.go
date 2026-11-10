package htcondor

import (
	"strings"
	"testing"
)

// TestQueueCountAndVars: the submit parser is the only thing that knows how
// many processes a queue statement makes, because the statement has several
// forms that count differently. A caller re-reading the text got `queue 2 x
// in (a, b)` and the inline `from ((rows))` form wrong, which is why these
// are exported rather than re-derived.
func TestQueueCountAndVars(t *testing.T) {
	for _, tc := range []struct {
		name      string
		raw       string
		wantCount int
		wantVars  []string
	}{
		{"bare queue", "executable = r.sh\nqueue\n", 1, nil},
		{"no queue statement at all", "executable = r.sh\n", 1, nil},
		{"literal count", "executable = r.sh\nqueue 10\n", 10, nil},
		{"item list", "executable = r.sh\nqueue name in (a, b)\n", 2, []string{"name"}},
		{"count times item list", "executable = r.sh\nqueue 2 name in (a, b)\n", 4, []string{"name"}},
		{"inline rows", "executable = r.sh\nqueue name from ((\nalice\nbob\ncarol\n))\n", 3, []string{"name"}},
		{"several vars", "executable = r.sh\nqueue a, b from ((\n1, 2\n3, 4\n))\n", 2, []string{"a", "b"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sf, err := ParseSubmitFile(strings.NewReader(tc.raw))
			if err != nil {
				t.Fatalf("parsing: %v", err)
			}
			if got := sf.QueueCount(); got != tc.wantCount {
				t.Errorf("QueueCount() = %d, want %d", got, tc.wantCount)
			}
			got := sf.QueueVars()
			if len(got) != len(tc.wantVars) {
				t.Fatalf("QueueVars() = %v, want %v", got, tc.wantVars)
			}
			for i := range got {
				if got[i] != tc.wantVars[i] {
					t.Errorf("QueueVars()[%d] = %q, want %q", i, got[i], tc.wantVars[i])
				}
			}
		})
	}
}

// TestQueueVarsIsACopy: the names belong to the parsed submit file and
// outlive the call, so a caller that sorts or overwrites them in place
// would be editing the file's own state.
func TestQueueVarsIsACopy(t *testing.T) {
	sf, err := ParseSubmitFile(strings.NewReader("executable = r.sh\nqueue a, b from ((\n1, 2\n))\n"))
	if err != nil {
		t.Fatalf("parsing: %v", err)
	}
	first := sf.QueueVars()
	if len(first) < 2 {
		t.Fatalf("expected two queue variables, got %v", first)
	}
	first[0] = "clobbered"
	if second := sf.QueueVars(); second[0] == "clobbered" {
		t.Error("QueueVars() hands out the submit file's own slice")
	}
}
