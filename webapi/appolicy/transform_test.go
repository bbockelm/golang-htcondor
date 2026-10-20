package appolicy

import (
	"reflect"
	"strings"
	"testing"
)

func TestSummarizeTransform(t *testing.T) {
	for _, tc := range []struct {
		name string
		text string
		want TransformSummary
	}{
		{
			name: "commands with and without =",
			text: "# map the owner\nCOPY Owner = AcctGroupUser\nCOPY AcctGroup RequestedAcctGroup\n" +
				"EVALSET AcctGroup = usermap(\"G\",AcctGroupUser,AcctGroup)\nevalset AccountingGroup join(\".\",AcctGroup,AcctGroupUser)\n",
			want: TransformSummary{OK: true,
				Copy:    []string{"Owner -> AcctGroupUser", "AcctGroup -> RequestedAcctGroup"},
				EvalSet: []string{"AcctGroup", "AccountingGroup"}},
		},
		{
			name: "requirements, universe, macros, regex",
			text: "NAME Pelican\nREQUIREMENTS isUndefined(PelicanRetryEnabled)\nUNIVERSE vanilla\n" +
				"retry_delay = 300\nEVALMACRO d = $(retry_delay) + random(300)\nSET PelicanRetryEnabled true\n" +
				"DEFAULT RequestDisk 1024\nRENAME /^Resource(.+)/ Original\\1\nDELETE /^Debug/\nDELETE Foo\n",
			want: TransformSummary{OK: true, Requirements: "isUndefined(PelicanRetryEnabled)", Universe: "vanilla",
				Set: []string{"PelicanRetryEnabled"}, Default: []string{"RequestDisk"},
				Rename: []string{"/^Resource(.+)/ -> Original\\1"}, Delete: []string{"/^Debug/", "Foo"}},
		},
		{
			name: "conditional",
			text: "REQUIREMENTS TargetAnnexName =!= undefined\n" +
				"if defined MY.Requirements\n  SET Requirements x && ($(MY.Requirements))\nelse\n  SET Requirements x\nendif\n" +
				"warning : this is a warning\n",
			want: TransformSummary{OK: true, Requirements: "TargetAnnexName =!= undefined",
				Set: []string{"Requirements", "Requirements"}, Conditional: true},
		},
		{
			name: "nested heredoc assignment",
			text: "body @=end\nSET Nope 1\nnot a statement\n@end\nSET Yes 1\n",
			want: TransformSummary{OK: true, Set: []string{"Yes"}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := SummarizeTransform(tc.text)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("got  %+v\nwant %+v", got, tc.want)
			}
		})
	}
}

// What cannot be read is said to be unreadable, not summarized from the
// lines that could be.
func TestSummarizeTransformRefusesToGuess(t *testing.T) {
	for _, tc := range []struct{ name, text, reason string }{
		{"old ClassAd form", "[ Requirements = JobUniverse == 5; set_WantDocker = true; ]", "old ClassAd"},
		{"unknown keyword", "SET A 1\nFROBNICATE B\nSET C 1\n", "line 2"},
		{"command without arguments", "SET\n", "line 1"},
		{"copy without a target", "COPY Owner\n", "line 1"},
		{"empty", "  \n", "empty"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := SummarizeTransform(tc.text)
			if got.OK || !strings.Contains(got.Reason, tc.reason) {
				t.Errorf("got %+v, want a refusal mentioning %q", got, tc.reason)
			}
			if len(got.Set) > 0 {
				t.Errorf("a refused summary still lists attributes: %v", got.Set)
			}
			if !strings.HasPrefix(got.Prose(), "Could not summarize") {
				t.Errorf("prose = %q", got.Prose())
			}
		})
	}
}

func TestTransformProse(t *testing.T) {
	s := SummarizeTransform("REQUIREMENTS JobUniverse == 5\nSET WantDocker true\nDEFAULT DockerImage \"x\"\n")
	want := "Applies to jobs where `JobUniverse == 5`. It sets WantDocker; sets, where the job has no value, DockerImage."
	if got := s.Prose(); got != want {
		t.Errorf("prose =\n%q\nwant\n%q", got, want)
	}
	if got := s.Compact(); got != "REQUIREMENTS JobUniverse == 5; SET WantDocker; DEFAULT DockerImage" {
		t.Errorf("compact = %q", got)
	}
}
