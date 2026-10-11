package jobargs

import (
	"slices"
	"testing"

	"github.com/PelicanPlatform/classad/classad"
)

func TestSplitV2(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want []string
	}{
		{"plain", "-f -l . -Dag workflow.dag", []string{"-f", "-l", ".", "-Dag", "workflow.dag"}},
		{"quoted run", "-Dag 'my workflow.dag' -MaxIdle 5", []string{"-Dag", "my workflow.dag", "-MaxIdle", "5"}},
		{"doubled quote", "-Dag 'it''s.dag'", []string{"-Dag", "it's.dag"}},
		{"doubled quote alone", "''''", []string{"'"}},
		{"empty quoted argument", "a '' b", []string{"a", "", "b"}},
		{"only an empty quoted argument", "''", []string{""}},
		{"quote joins a word", "pre'fix suf'post", []string{"prefix sufpost"}},
		{"extra whitespace", " \t -f   -Dag\na.dag ", []string{"-f", "-Dag", "a.dag"}},
		{"empty", "", nil},
		{"whitespace only", "   ", nil},
		{"version string", `-CsdVersion '$CondorVersion: 25.4.0 BuildID: test $' -MaxIdle 5`,
			[]string{"-CsdVersion", "$CondorVersion: 25.4.0 BuildID: test $", "-MaxIdle", "5"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := SplitV2(tc.raw); !slices.Equal(got, tc.want) {
				t.Errorf("SplitV2(%q) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}

func TestSplitV1(t *testing.T) {
	if got := SplitV1("  a 'b c'\td "); !slices.Equal(got, []string{"a", "'b", "c'", "d"}) {
		t.Errorf("SplitV1 = %q: V1 has no quoting", got)
	}
	if got := SplitV1(""); got != nil {
		t.Errorf("SplitV1(\"\") = %q, want nil", got)
	}
}

// Arguments wins when both are present; Args is the fallback.
func TestFromAd(t *testing.T) {
	ad, err := classad.ParseOld("Arguments = \"x 'y z'\"\nArgs = \"old style\"")
	if err != nil {
		t.Fatal(err)
	}
	if got := FromAd(ad); !slices.Equal(got, []string{"x", "y z"}) {
		t.Errorf("FromAd = %q, want the V2 Arguments", got)
	}
	ad, err = classad.ParseOld("Arguments = \"\"\nArgs = \"old style\"")
	if err != nil {
		t.Fatal(err)
	}
	if got := FromAd(ad); !slices.Equal(got, []string{"old", "style"}) {
		t.Errorf("FromAd = %q, want the V1 Args", got)
	}
	if got := FromAd(classad.New()); got != nil {
		t.Errorf("FromAd(empty) = %q, want nil", got)
	}
}
