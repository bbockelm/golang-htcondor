package aggregate

import (
	"testing"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/PelicanPlatform/classad/db"
	"github.com/PelicanPlatform/classad/dbrpc"
)

// TestEveryKindLabelsTheSameTypedOrNot runs each kind of group down both paths
// -- a server that sent typed group values and one too old to -- and requires
// one label from both. The fallback parses the text back, so a kind the parser
// renders differently from the value would show up here as a disagreement
// rather than as a label that is merely odd.
func TestEveryKindLabelsTheSameTypedOrNot(t *testing.T) {
	cases := []struct {
		name  string
		value classad.Value
		want  string
	}{
		{"owner", classad.NewStringValue("alice"), "alice"},
		{"an AP name", classad.NewStringValue("ap1.example.org"), "ap1.example.org"},
		{"a string holding a quote", classad.NewStringValue(`he said "hi"`), `he said "hi"`},
		{"a string holding a backslash", classad.NewStringValue(`C:\tmp`), `C:\tmp`},
		{"a string that reads as a number", classad.NewStringValue("4"), "4"},
		{"the empty string", classad.NewStringValue(""), ""},
		{"a hold code", classad.NewIntValue(13), "13"},
		{"a negative integer", classad.NewIntValue(-1), "-1"},
		{"a real", classad.NewRealValue(1.5), "1.5"},
		{"a bool", classad.NewBoolValue(true), "true"},
		{"undefined", classad.NewUndefinedValue(), "undefined"},
		{"a list", classad.NewListValue([]classad.Value{classad.NewIntValue(1), classad.NewIntValue(2)}), "{ 1,2 }"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			text := db.GroupValueText(c.value)
			typed := dbrpc.AggRow{Group: []string{text}, GroupValues: []classad.Value{c.value}}
			if got := GroupLabel(typed, 0); got != c.want {
				t.Errorf("typed: label of %s = %q, want %q", text, got, c.want)
			}
			untyped := dbrpc.AggRow{Group: []string{text}}
			if got := GroupLabel(untyped, 0); got != c.want {
				t.Errorf("untyped: label of %s = %q, want %q", text, got, c.want)
			}
		})
	}
}

// TestAStringGroupArrivesQuoted pins the upstream behaviour this whole file
// exists for. If htcondordb ever stops quoting a string group, GroupLabel
// still answers alice and nothing below it notices -- this is what would say
// so, and it is the reason the labels are not simply the group text.
func TestAStringGroupArrivesQuoted(t *testing.T) {
	if got := db.GroupValueText(classad.NewStringValue("alice")); got != `"alice"` {
		t.Errorf("group text of the string alice = %s, want \"alice\"", got)
	}
	if got := db.GroupValueText(classad.NewIntValue(4)); got != "4" {
		t.Errorf("group text of the integer 4 = %s, want 4", got)
	}
}

// TestLabelsDoNotMergeGroupsTheTextKeepsApart is the cost of labelling: the
// string "4" and the integer 4 are two groups and read alike once labelled.
// The row keeps both apart, so a caller that needs the distinction has it.
func TestLabelsDoNotMergeGroupsTheTextKeepsApart(t *testing.T) {
	str := dbrpc.AggRow{Group: []string{db.GroupValueText(classad.NewStringValue("4"))}}
	num := dbrpc.AggRow{Group: []string{db.GroupValueText(classad.NewIntValue(4))}}
	if GroupLabel(str, 0) != GroupLabel(num, 0) {
		t.Fatalf("the labels differ; this test is asserting that they do not")
	}
	if str.Group[0] == num.Group[0] {
		t.Errorf("the string 4 and the integer 4 share a group text %q", str.Group[0])
	}
}

func TestGroupLabelsReadsEveryColumnInOrder(t *testing.T) {
	r := dbrpc.AggRow{
		Group: []string{`"alice"`, "13", `"ap1.example.org"`},
		GroupValues: []classad.Value{
			classad.NewStringValue("alice"),
			classad.NewIntValue(13),
			classad.NewStringValue("ap1.example.org"),
		},
	}
	got := GroupLabels(r)
	want := []string{"alice", "13", "ap1.example.org"}
	if len(got) != len(want) {
		t.Fatalf("labels = %q, want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("label %d = %q, want %q", i, got[i], want[i])
		}
	}
	if GroupLabels(dbrpc.AggRow{}) != nil {
		t.Errorf("a row with no groups labels as %q, want nil", GroupLabels(dbrpc.AggRow{}))
	}
}

// TestAShortGroupValuesFallsBackPerColumn covers a row whose typed values do
// not cover every column. The doc on AggRow.GroupValues promises one per group
// column or nil, so this is defensive -- but the fallback is per column, and a
// loop that read GroupValues by the group's length would panic here.
func TestAShortGroupValuesFallsBackPerColumn(t *testing.T) {
	r := dbrpc.AggRow{
		Group:       []string{`"alice"`, `"ap1.example.org"`},
		GroupValues: []classad.Value{classad.NewStringValue("alice")},
	}
	got := GroupLabels(r)
	if len(got) != 2 || got[0] != "alice" || got[1] != "ap1.example.org" {
		t.Errorf("labels = %q, want [alice ap1.example.org]", got)
	}
}

func TestAnIndexOutsideTheRowIsEmpty(t *testing.T) {
	r := dbrpc.AggRow{Group: []string{`"alice"`}}
	if got := GroupLabel(r, 1); got != "" {
		t.Errorf("label past the last column = %q, want empty", got)
	}
	if got := GroupLabel(r, -1); got != "" {
		t.Errorf("label at a negative index = %q, want empty", got)
	}
	if got := GroupLabel(dbrpc.AggRow{}, 0); got != "" {
		t.Errorf("label of a row with no groups = %q, want empty", got)
	}
}
