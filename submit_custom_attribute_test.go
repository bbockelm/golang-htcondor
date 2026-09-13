// Custom job attributes: `+Attr = expr` and `MY.Attr = expr`.
//
// Both spellings mean "put this attribute on the job ad", and the value
// is a ClassAd expression rather than text. Neither of those held
// before: the '+' form reached the job ad as nothing at all, and the
// MY. form arrived under the name "MY.Attr" with its quotes still on.
package htcondor

import (
	"strings"
	"testing"

	"github.com/PelicanPlatform/classad/classad"
)

// attrOf returns the ClassAd rendering of one attribute of the first
// proc ad produced by src.
func attrOf(t *testing.T, src, attr string) (string, bool) {
	t.Helper()
	sf, err := ParseSubmitFile(strings.NewReader(src))
	if err != nil {
		t.Fatalf("ParseSubmitFile: %v\n%s", err, src)
	}
	result, err := sf.Submit(1)
	if err != nil {
		t.Fatalf("Submit: %v\n%s", err, src)
	}
	expr, ok := result.ProcAds[0].Lookup(attr)
	if !ok {
		return "", false
	}
	return expr.String(), true
}

const customAttrPreamble = "universe = vanilla\nexecutable = /bin/true\n"

func TestCustomAttributeValuesKeepTheirType(t *testing.T) {
	tests := []struct {
		name string
		line string
		attr string
		want string
	}{
		// The quotes belong to the ClassAd string literal, not to the
		// value: a job tagged "nightly" must not come out tagged
		// "\"nightly\"", which is what a text-inspecting heuristic
		// produced and what a constraint like Tag == "nightly" would
		// then fail to match.
		{"string", `+Tag = "nightly"`, "Tag", `"nightly"`},
		{"integer", `+Retries = 3`, "Retries", "3"},
		// A negative literal renders as the unary-minus expression the
		// ClassAd parser built; what matters is that it evaluates to
		// -2, which TestCustomAttributeLiteralsEvaluate checks.
		{"negative integer", `+Offset = -2`, "Offset", "(-2)"},
		{"float", `+Factor = 1.5`, "Factor", "1.5"},
		{"boolean", `+WantGPU = true`, "WantGPU", "true"},
		{"boolean false", `+WantGPU = false`, "WantGPU", "false"},
		// An expression has to arrive as an expression; it is evaluated
		// later, against the machine ad, by whoever reads the job.
		{"arithmetic", `+HalfMem = RequestMemory / 2`, "HalfMem", "(RequestMemory / 2)"},
		{"comparison", `+Big = (RequestMemory > 4096)`, "Big", "(RequestMemory > 4096)"},
		{"attribute reference", `+Mirror = Owner`, "Mirror", "Owner"},
		{"list", `+Sites = { "A", "B" }`, "Sites", `{"A", "B"}`},
		// Single-character names: the lexer's lookahead was off by one
		// and rejected these, and since the grammar has no error
		// production for a stray '+', the line vanished silently.
		{"single character name", `+X = 1`, "X", "1"},
		// MY. is the same thing said differently, and the prefix is not
		// part of the attribute name.
		{"MY. prefix", `MY.Tag = "nightly"`, "Tag", `"nightly"`},
		{"my. lowercase", `my.Tag = "nightly"`, "Tag", `"nightly"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := attrOf(t, customAttrPreamble+tt.line+"\nqueue\n", tt.attr)
			if !ok {
				t.Fatalf("attribute %s is missing from the job ad", tt.attr)
			}
			if got != tt.want {
				t.Errorf("%s = %s, want %s", tt.attr, got, tt.want)
			}
		})
	}
}

// TestCustomAttributeLiteralsEvaluate checks the values rather than
// their rendering: an attribute is useful because a constraint or a
// policy expression can evaluate it, not because it prints a certain
// way.
func TestCustomAttributeLiteralsEvaluate(t *testing.T) {
	sf, err := ParseSubmitFile(strings.NewReader(customAttrPreamble +
		"+Tag = \"nightly\"\n+Retries = 3\n+Offset = -2\n+Factor = 1.5\n+WantGPU = true\nqueue\n"))
	if err != nil {
		t.Fatalf("ParseSubmitFile: %v", err)
	}
	result, err := sf.Submit(1)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	ad := result.ProcAds[0]

	if got, ok := ad.EvaluateAttrString("Tag"); !ok || got != "nightly" {
		t.Errorf("Tag evaluates to %q (present=%v), want nightly", got, ok)
	}
	if got, ok := ad.EvaluateAttrInt("Retries"); !ok || got != 3 {
		t.Errorf("Retries evaluates to %d (present=%v), want 3", got, ok)
	}
	if got, ok := ad.EvaluateAttrInt("Offset"); !ok || got != -2 {
		t.Errorf("Offset evaluates to %d (present=%v), want -2", got, ok)
	}
	if got, ok := ad.EvaluateAttrReal("Factor"); !ok || got != 1.5 {
		t.Errorf("Factor evaluates to %v (present=%v), want 1.5", got, ok)
	}
	if got, ok := ad.EvaluateAttrBool("WantGPU"); !ok || !got {
		t.Errorf("WantGPU evaluates to %v (present=%v), want true", got, ok)
	}
}

func TestCustomAttributeExpandsMacros(t *testing.T) {
	src := customAttrPreamble + "project = ligo\n+Project = \"$(project)\"\n+Which = $(Process)\nqueue 2\n"
	got, ok := attrOf(t, src, "Project")
	if !ok || got != `"ligo"` {
		t.Errorf("Project = %s (present=%v), want \"ligo\"", got, ok)
	}

	// $(Process) differs per proc, so the attribute has to be built per
	// proc rather than once for the cluster.
	sf, err := ParseSubmitFile(strings.NewReader(src))
	if err != nil {
		t.Fatalf("ParseSubmitFile: %v", err)
	}
	result, err := sf.Submit(1)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	for i, ad := range result.ProcAds {
		expr, ok := ad.Lookup("Which")
		if !ok {
			t.Fatalf("proc %d has no Which attribute", i)
		}
		if got, want := expr.String(), string(rune('0'+i)); got != want {
			t.Errorf("proc %d: Which = %s, want %s", i, got, want)
		}
	}
}

// TestCustomAttributeDoesNotBecomeASubmitCommand: the prefix is what
// separates the two namespaces, and confusing them either way is a bug.
// `+Executable = "x"` must set a job attribute, not redirect the job.
func TestCustomAttributeDoesNotBecomeASubmitCommand(t *testing.T) {
	src := customAttrPreamble + `+Arguments = "not-the-real-arguments"` + "\narguments = real\nqueue\n"
	got, ok := attrOf(t, src, "Args")
	if !ok {
		t.Fatal("job ad has no Args attribute")
	}
	if !strings.Contains(got, "real") {
		t.Errorf("Args = %s; the + attribute overrode the arguments submit command", got)
	}
}

// And the other direction: an ordinary macro is not a job attribute.
func TestPlainMacroIsNotAJobAttribute(t *testing.T) {
	if got, ok := attrOf(t, customAttrPreamble+"MyTag = \"nightly\"\nqueue\n", "MyTag"); ok {
		t.Errorf("plain macro MyTag reached the job ad as %s", got)
	}
}

// TestCustomAttributeIsNotASubmitCommand covers the namespace boundary
// from the direction that actually hurt: a custom attribute spelled
// like a submit command must not mark that command as set by the file.
//
// `submitCommand` reads a value only when the file assigned the name,
// because the submit config is seeded with HTCondor's param_info
// defaults and an unassigned lookup returns the default. So a
// `+Max_Transfer_Input_Mb = 5` that marked max_transfer_input_mb as
// assigned put MaxTransferInputMB = -1 (the param default) on the job —
// the leak that makes a schedd protecting the attribute reject the
// submission outright.
func TestCustomAttributeIsNotASubmitCommand(t *testing.T) {
	sf, err := ParseSubmitFile(strings.NewReader(customAttrPreamble + "+Max_Transfer_Input_Mb = 5\nqueue\n"))
	if err != nil {
		t.Fatalf("ParseSubmitFile: %v", err)
	}
	if v, ok := sf.submitCommand("max_transfer_input_mb"); ok {
		t.Errorf("+Max_Transfer_Input_Mb made the submit command max_transfer_input_mb look assigned (value %q)", v)
	}

	result, err := sf.Submit(1)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	ad := result.ProcAds[0]
	// The attribute the user asked for is there...
	if got, ok := ad.EvaluateAttrInt("Max_Transfer_Input_Mb"); !ok || got != 5 {
		t.Errorf("Max_Transfer_Input_Mb = %d (present=%v), want 5", got, ok)
	}
	// ...and the param_info default is not.
	if expr, ok := ad.Lookup("MaxTransferInputMB"); ok {
		t.Errorf("job ad carries MaxTransferInputMB = %s from the config default", expr.String())
	}
}

// TestCustomAttributeDefinesTheMyMacro: `+Foo` defines $(MY.Foo), the
// same as condor_submit, and does not define $(Foo).
func TestCustomAttributeDefinesTheMyMacro(t *testing.T) {
	got, ok := attrOf(t, customAttrPreamble+"+Tag = \"nightly\"\n+Echo = $(MY.Tag)\nqueue\n", "Echo")
	if !ok || got != `"nightly"` {
		t.Errorf("Echo = %s (present=%v), want \"nightly\" — $(MY.Tag) did not expand", got, ok)
	}

	// And the bare name is not a macro: $(Tag) expands to nothing,
	// which here means the attribute cannot be built at all.
	sf, err := ParseSubmitFile(strings.NewReader(customAttrPreamble + "+Tag = \"nightly\"\n+Echo = \"$(Tag)\"\nqueue\n"))
	if err != nil {
		t.Fatalf("ParseSubmitFile: %v", err)
	}
	result, err := sf.Submit(1)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if got, ok := result.ProcAds[0].EvaluateAttrString("Echo"); !ok || got != "" {
		t.Errorf("Echo = %q (present=%v); $(Tag) should not expand — +Tag defines $(MY.Tag)", got, ok)
	}
}

func TestCustomAttributeRejectsAnUnparsableExpression(t *testing.T) {
	sf, err := ParseSubmitFile(strings.NewReader(customAttrPreamble + "+Broken = ((\nqueue\n"))
	if err != nil {
		// Rejecting it at parse time is also an acceptable answer.
		return
	}
	_, err = sf.Submit(1)
	if err == nil {
		t.Fatal("a custom attribute that is not an expression was accepted")
	}
	// The message has to name the attribute: the submit file may have
	// a dozen of them and the error is otherwise unactionable.
	if !strings.Contains(err.Error(), "Broken") {
		t.Errorf("error does not name the attribute: %v", err)
	}
}

// TestCustomAttributeSurvivesTheClassAdRoundTrip: the job ad is
// serialized to the schedd and parsed back, so an attribute that only
// looks right in memory is not right.
func TestCustomAttributeSurvivesTheClassAdRoundTrip(t *testing.T) {
	sf, err := ParseSubmitFile(strings.NewReader(customAttrPreamble + `+Tag = "nightly"` + "\n+Retries = 3\nqueue\n"))
	if err != nil {
		t.Fatalf("ParseSubmitFile: %v", err)
	}
	result, err := sf.Submit(1)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}

	reparsed, err := classad.Parse(result.ProcAds[0].String())
	if err != nil {
		t.Fatalf("the generated ad does not parse back: %v", err)
	}
	if got, ok := reparsed.EvaluateAttrString("Tag"); !ok || got != "nightly" {
		t.Errorf("after a round trip Tag evaluates to %q (present=%v), want nightly", got, ok)
	}
	if got, ok := reparsed.EvaluateAttrInt("Retries"); !ok || got != 3 {
		t.Errorf("after a round trip Retries evaluates to %d (present=%v), want 3", got, ok)
	}
}
