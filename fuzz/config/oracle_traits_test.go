package fuzzconfig

import (
	"strings"
	"testing"
)

// TestLibcCanaryStillMeansGlibc pins the Go side of the canary.
//
// The warning compares the oracle against the Go model rather than against a
// hard-coded string, which keeps it from rotting -- but only while the model
// still gives glibc's answer. If printf.go ever stopped doing that, the two
// sides would agree on a non-glibc oracle and the warning would go silent on
// exactly the platform it exists for.
//
// `0X1P+0%Z.0` is what glibc prints, measured directly:
//
//	snprintf(buf, n, "%A%ZZ", 1.0)  ->  0X1P+0%Z   (glibc 2.36, gcc:13)
//
// then $REAL appends `.0` because there is no `.` in it. macOS libc gives
// `0X1P+0ZZ` for the same format, which is the whole point of the canary.
func TestLibcCanaryStillMeansGlibc(t *testing.T) {
	const wantGlibc = "0X1P+0%Z.0"
	res := GoParseExpand(Prelude(libcCanary))
	if res.Uncomparable != "" {
		t.Fatalf("the canary became uncomparable on the Go side: %s", res.Uncomparable)
	}
	got := ""
	for _, line := range strings.Split(Canon(res.Table), "\n") {
		if k, v, ok := strings.Cut(line, "\x1f"); ok && k == "0" {
			got = v
			break
		}
	}
	if got != wantGlibc {
		t.Errorf("the Go model expands %s to %q, want %q -- the canary no longer stands for glibc",
			libcCanary, got, wantGlibc)
	}
}

// TestLibcWarningFor pins when the note is printed, without depending on the
// C library of whatever host runs the test.
func TestLibcWarningFor(t *testing.T) {
	if w := libcWarningFor("0X1P+0%Z.0", "0X1P+0%Z.0"); w != "" {
		t.Errorf("a matching oracle warned: %q", w)
	}
	w := libcWarningFor("0X1P+0ZZ.0", "0X1P+0%Z.0")
	if w == "" {
		t.Error("an oracle that disagrees with the model did not warn")
	}
	for _, want := range []string{"0X1P+0ZZ.0", "0X1P+0%Z.0", libcCanary} {
		if !strings.Contains(w, want) {
			t.Errorf("the warning does not name %q: %q", want, w)
		}
	}
	// Nothing to say when either side could not answer.
	if w := libcWarningFor("", "0X1P+0%Z.0"); w != "" {
		t.Errorf("warned with no oracle value: %q", w)
	}
	if w := libcWarningFor("0X1P+0ZZ.0", ""); w != "" {
		t.Errorf("warned with no model value: %q", w)
	}
}
