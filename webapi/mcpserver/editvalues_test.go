package mcpserver

import (
	"strings"
	"testing"

	"github.com/PelicanPlatform/classad/classad"
)

// A job ad the way the queue hands it back: RequestMemory numeric,
// RequestCpus numeric, and an attribute that is a string today.
func adWithNumbers(t *testing.T) *classad.ClassAd {
	t.Helper()
	ad, err := classad.Parse(`[RequestMemory = 128; RequestCpus = 1; MyLabel = "old"]`)
	if err != nil {
		t.Fatalf("parsing the fixture ad: %v", err)
	}
	return ad
}

func TestNumericAttributeGivenAsAStringIsWrittenAsANumber(t *testing.T) {
	attrs, notes, err := classAdValues(
		map[string]interface{}{"RequestMemory": "256"}, adWithNumbers(t))
	if err != nil {
		t.Fatalf("classAdValues: %v", err)
	}
	// The bug this exists for: "256" written as a ClassAd string leaves
	// RequestMemory unmatchable against the startd's Memory.
	if got := attrs["RequestMemory"]; got != "256" {
		t.Errorf("RequestMemory = %s, want 256 (unquoted)", got)
	}
	if len(notes) != 1 || !strings.Contains(notes[0], "RequestMemory") {
		t.Errorf("the coercion was not reported: %v", notes)
	}
}

func TestNonNumericStringForANumericAttributeIsRefused(t *testing.T) {
	_, _, err := classAdValues(
		map[string]interface{}{"RequestMemory": "lots"}, adWithNumbers(t))
	if err == nil {
		t.Fatal("setting RequestMemory to \"lots\" was accepted; it leaves the job unmatchable")
	}
	if !strings.Contains(err.Error(), "RequestMemory") {
		t.Errorf("the error does not name the attribute: %v", err)
	}
}

func TestStringsStayStringsWhereTheAttributeIsNotNumeric(t *testing.T) {
	attrs, notes, err := classAdValues(map[string]interface{}{
		"MyLabel": "new",   // a string today
		"MyNewer": "12345", // does not exist yet, and numeric-looking
	}, adWithNumbers(t))
	if err != nil {
		t.Fatalf("classAdValues: %v", err)
	}
	if got := attrs["MyLabel"]; got != `"new"` {
		t.Errorf("MyLabel = %s, want a quoted string", got)
	}
	// A new attribute has no type to honor, and guessing that a numeric
	// string means a number would be its own trap -- an accession
	// number or a run id is a string that happens to be digits.
	if got := attrs["MyNewer"]; got != `"12345"` {
		t.Errorf("MyNewer = %s, want a quoted string", got)
	}
	if len(notes) != 0 {
		t.Errorf("nothing was coerced, so nothing should be reported: %v", notes)
	}
}

func TestNumbersAndBooleansAndNullMapDirectly(t *testing.T) {
	attrs, _, err := classAdValues(map[string]interface{}{
		"RequestMemory": float64(512),
		"RequestCpus":   2.5,
		"WantGPU":       true,
		"NiceUser":      false,
		"Gone":          nil,
	}, adWithNumbers(t))
	if err != nil {
		t.Fatalf("classAdValues: %v", err)
	}
	for attr, want := range map[string]string{
		"RequestMemory": "512",
		"WantGPU":       "true",
		"NiceUser":      "false",
		"Gone":          "UNDEFINED",
	} {
		if attrs[attr] != want {
			t.Errorf("%s = %s, want %s", attr, attrs[attr], want)
		}
	}
	if !strings.HasPrefix(attrs["RequestCpus"], "2.5") {
		t.Errorf("RequestCpus = %s, want 2.5", attrs["RequestCpus"])
	}
}

// Without the current ad -- the lookup failed, or the caller is a unit
// test -- a string is a string. Losing the coercion is the cost; writing
// a number over an attribute whose type is unknown would be worse.
func TestWithoutTheCurrentAdStringsAreStrings(t *testing.T) {
	attrs, notes, err := classAdValues(map[string]interface{}{"RequestMemory": "256"}, nil)
	if err != nil {
		t.Fatalf("classAdValues: %v", err)
	}
	if got := attrs["RequestMemory"]; got != `"256"` {
		t.Errorf("RequestMemory = %s, want a quoted string", got)
	}
	if len(notes) != 0 {
		t.Errorf("unexpected notes: %v", notes)
	}
}

// Two bad values must produce the same error every run.
func TestRefusalIsDeterministic(t *testing.T) {
	updates := map[string]interface{}{
		"RequestMemory": "lots",
		"RequestCpus":   "many",
	}
	first := ""
	for i := 0; i < 20; i++ {
		_, _, err := classAdValues(updates, adWithNumbers(t))
		if err == nil {
			t.Fatal("expected a refusal")
		}
		if first == "" {
			first = err.Error()
		} else if err.Error() != first {
			t.Fatalf("map order decided the error:\n%s\n%s", first, err.Error())
		}
	}
}
