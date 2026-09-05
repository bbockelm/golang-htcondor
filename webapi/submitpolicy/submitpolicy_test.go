package submitpolicy

import (
	"strings"
	"testing"
)

// commandValue returns the EFFECTIVE value of a submit command: the last
// assignment before the first queue statement, which is what
// condor_submit evaluates. Asserting on this rather than on substring
// presence is the whole point -- a test that merely checked the file
// "contains log =" would pass even when the user's value wins over an
// override.
func commandValue(t *testing.T, submitFile, command string) (string, bool) {
	t.Helper()
	value := ""
	found := false
	for _, line := range strings.Split(submitFile, "\n") {
		trimmed := strings.TrimSpace(line)
		if isQueueLine(trimmed) {
			break
		}
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		name, rest, ok := strings.Cut(trimmed, "=")
		if !ok {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(name), command) {
			value = strings.TrimSpace(rest)
			found = true
		}
	}
	return value, found
}

// An unconfigured policy must be byte-for-byte inert. A deployment that
// sets neither knob should not be able to tell this code exists.
func TestZeroPolicyIsInert(t *testing.T) {
	const file = "executable = /bin/true\nlog = job.log\nqueue\n"
	if got := (Policy{}).Apply(file); got != file {
		t.Errorf("zero policy changed the submit file:\n%s", got)
	}
	if got := (Policy{Defaults: "  \n\t", Overrides: ""}).Apply(file); got != file {
		t.Errorf("whitespace-only policy changed the submit file:\n%s", got)
	}
	if !(Policy{}).IsZero() {
		t.Error("zero value must report IsZero")
	}
}

// A default fills a gap...
func TestDefaultAppliesWhenTheFileIsSilent(t *testing.T) {
	p := Policy{Defaults: "log = /home/alice/jobs.log"}
	got := p.Apply("executable = /bin/true\nqueue\n")

	value, ok := commandValue(t, got, "log")
	if !ok {
		t.Fatalf("no effective log command:\n%s", got)
	}
	if value != "/home/alice/jobs.log" {
		t.Errorf("log = %q, want the default", value)
	}
}

// ...and yields the moment the user expresses a preference. This is the
// property that separates a default from an override.
func TestDefaultLosesToTheUsersOwnValue(t *testing.T) {
	p := Policy{Defaults: "log = /home/alice/default.log"}
	got := p.Apply("executable = /bin/true\nlog = mine.log\nqueue\n")

	value, _ := commandValue(t, got, "log")
	if value != "mine.log" {
		t.Errorf("log = %q, want the user's own value to win", value)
	}
}

// An override wins over what the user wrote. This is the ap40 case: the
// schedd rejects a log outside the home directory, and that is not the
// user's to opt out of.
func TestOverrideBeatsTheUsersValue(t *testing.T) {
	p := Policy{Overrides: "log = /home/alice/forced.log"}
	got := p.Apply("executable = /bin/true\nlog = /tmp/nope.log\nqueue\n")

	value, _ := commandValue(t, got, "log")
	if value != "/home/alice/forced.log" {
		t.Errorf("log = %q, want the override to win", value)
	}
}

// Both hooks at once, on different commands, each behaving in character.
func TestDefaultsAndOverridesTogether(t *testing.T) {
	p := Policy{
		Defaults:  "log = /home/alice/default.log\nrequest_memory = 512",
		Overrides: "accounting_group = grp_ap40",
	}
	got := p.Apply("executable = /bin/true\nrequest_memory = 2048\nqueue\n")

	if v, _ := commandValue(t, got, "log"); v != "/home/alice/default.log" {
		t.Errorf("log = %q, want the default (file was silent)", v)
	}
	if v, _ := commandValue(t, got, "request_memory"); v != "2048" {
		t.Errorf("request_memory = %q, want the user's value", v)
	}
	if v, _ := commandValue(t, got, "accounting_group"); v != "grp_ap40" {
		t.Errorf("accounting_group = %q, want the override", v)
	}
}

// The overrides must land ABOVE the queue statement. Below it they would
// apply to nothing at all -- the job is already described by then.
func TestOverridesLandAboveQueue(t *testing.T) {
	p := Policy{Overrides: "accounting_group = grp_ap40"}
	got := p.Apply("executable = /bin/true\nqueue 5\n")

	overrideAt := strings.Index(got, "accounting_group")
	queueAt := strings.Index(got, "queue 5")
	if overrideAt < 0 || queueAt < 0 {
		t.Fatalf("missing content:\n%s", got)
	}
	if overrideAt > queueAt {
		t.Errorf("override was spliced below the queue statement, where it does nothing:\n%s", got)
	}
}

// With several queue statements the block goes above the first, so it is
// in force for all of them.
func TestOverridesLandAboveTheFirstOfSeveralQueues(t *testing.T) {
	p := Policy{Overrides: "accounting_group = grp_ap40"}
	got := p.Apply("executable = /bin/a\nqueue\nexecutable = /bin/b\nqueue\n")

	if strings.Index(got, "accounting_group") > strings.Index(got, "queue") {
		t.Errorf("override is not above the first queue:\n%s", got)
	}
	if v, _ := commandValue(t, got, "accounting_group"); v != "grp_ap40" {
		t.Errorf("override is not in force for the first queue: %q", v)
	}
}

// The templates path hands over a body with no queue statement and
// appends its own `queue ... from (...)` afterwards, so an appended
// override still lands above it.
func TestNoQueueStatementAppends(t *testing.T) {
	p := Policy{Overrides: "accounting_group = grp_ap40"}
	got := p.Apply("executable = /bin/true\nlog = job.log\n")

	if !strings.Contains(got, "accounting_group = grp_ap40") {
		t.Fatalf("override missing:\n%s", got)
	}
	// Simulate what the templates endpoint does next.
	final := got + "queue name from (alice)\n"
	if v, _ := commandValue(t, final, "accounting_group"); v != "grp_ap40" {
		t.Errorf("override did not survive the appended queue: %q", v)
	}
}

// A line whose first word merely starts with "queue" is not a queue
// statement; treating it as one would splice the overrides too early.
func TestQueueDetectionIsExact(t *testing.T) {
	cases := map[string]bool{
		"queue":                  true,
		"  queue  ":              true,
		"QUEUE":                  true,
		"Queue 5":                true,
		"queue name from (a, b)": true,
		"queuedepth = 4":         false,
		"# queue":                false,
		"":                       false,
		"request_queue = 4":      false,
	}
	for line, want := range cases {
		if got := isQueueLine(line); got != want {
			t.Errorf("isQueueLine(%q) = %v, want %v", line, got, want)
		}
	}
}

// A submit file with no trailing newline must not have the operator's
// first line welded onto its last one.
func TestNoTrailingNewlineIsHandled(t *testing.T) {
	p := Policy{Overrides: "accounting_group = grp_ap40"}
	got := p.Apply("executable = /bin/true")

	if strings.Contains(got, "/bin/trueaccounting_group") ||
		strings.Contains(got, "/bin/true# ---") {
		t.Errorf("lines were welded together:\n%q", got)
	}
	if v, _ := commandValue(t, got, "accounting_group"); v != "grp_ap40" {
		t.Errorf("accounting_group = %q", v)
	}
	if v, _ := commandValue(t, got, "executable"); v != "/bin/true" {
		t.Errorf("executable = %q, want it intact", v)
	}
}

// The markers say where the lines came from, so an operator reading a
// generated submit file is not left guessing.
func TestBlocksAreLabelled(t *testing.T) {
	got := Policy{Defaults: "log = a.log", Overrides: "accounting_group = g"}.
		Apply("executable = /bin/true\nqueue\n")

	for _, want := range []string{
		"HTTP_API_SUBMIT_FILE_DEFAULTS",
		"HTTP_API_SUBMIT_FILE_OVERRIDES",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the generated file does not name %s:\n%s", want, got)
		}
	}
}
