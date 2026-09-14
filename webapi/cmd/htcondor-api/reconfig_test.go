package main

import (
	"reflect"
	"strings"
	"testing"

	"github.com/bbockelm/golang-htcondor/config"
)

// fakeTarget records what a reconfigure applied to the running server.
type fakeTarget struct {
	instructions []string
}

func (f *fakeTarget) SetMCPInstructions(s string) { f.instructions = append(f.instructions, s) }

// configFrom builds a Config from literal file contents, the way the daemon
// builds one from CONDOR_CONFIG on reconfigure.
func configFrom(t *testing.T, body string) *config.Config {
	t.Helper()
	cfg, err := config.NewFromReader(strings.NewReader(body))
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	return cfg
}

// TestReconfigAppliesDynamicParam verifies a dynamic parameter reaches the
// running server, which is the whole point of the wiring: before this, SIGHUP
// reloaded the file and changed nothing but log levels.
func TestReconfigAppliesDynamicParam(t *testing.T) {
	target := &fakeTarget{}
	w := newReconfigWatcher(configFrom(t, "MCP_INSTRUCTIONS = original\n"), target, nil)

	applied, needRestart := w.diff(configFrom(t, "MCP_INSTRUCTIONS = revised\n"))

	if want := []string{"MCP_INSTRUCTIONS"}; !reflect.DeepEqual(applied, want) {
		t.Errorf("applied = %v, want %v", applied, want)
	}
	if len(needRestart) != 0 {
		t.Errorf("needRestart = %v, want none", needRestart)
	}
	if want := []string{"revised"}; !reflect.DeepEqual(target.instructions, want) {
		t.Errorf("server received %v, want %v", target.instructions, want)
	}
}

// TestReconfigReportsRestartOnlyParam covers the case that prompted this: an
// operator edits HTTP_API_BASE_URL, sends SIGHUP, and needs to be told the
// running server is still using the old value.
func TestReconfigReportsRestartOnlyParam(t *testing.T) {
	target := &fakeTarget{}
	w := newReconfigWatcher(configFrom(t, "HTTP_API_BASE_URL = https://old.example.org\n"), target, nil)

	applied, needRestart := w.diff(configFrom(t, "HTTP_API_BASE_URL = https://new.example.org\n"))

	if want := []string{"HTTP_API_BASE_URL"}; !reflect.DeepEqual(needRestart, want) {
		t.Errorf("needRestart = %v, want %v", needRestart, want)
	}
	if len(applied) != 0 {
		t.Errorf("applied = %v, want none -- the value is only read at startup", applied)
	}
	if len(target.instructions) != 0 {
		t.Errorf("server was touched for a restart-only parameter: %v", target.instructions)
	}
}

// TestReconfigReportsEachChangeOnce verifies a restart-only change is reported
// when it happens and not on every reconfigure from then until restart. An
// operator who reconfigures for an unrelated reason should not be re-warned
// about something they already know.
func TestReconfigReportsEachChangeOnce(t *testing.T) {
	target := &fakeTarget{}
	w := newReconfigWatcher(configFrom(t, "HTTP_API_BASE_URL = https://old.example.org\n"), target, nil)
	changed := configFrom(t, "HTTP_API_BASE_URL = https://new.example.org\n")

	if _, needRestart := w.diff(changed); len(needRestart) != 1 {
		t.Fatalf("first reconfigure: needRestart = %v, want one entry", needRestart)
	}
	applied, needRestart := w.diff(changed)
	if len(needRestart) != 0 || len(applied) != 0 {
		t.Errorf("second reconfigure with the same config reported applied=%v needRestart=%v, want neither",
			applied, needRestart)
	}
}

// TestReconfigIgnoresUnchangedConfig guards the quiet path: reloading the same
// configuration must not re-apply anything, because applying is not always free
// (a setter can be observable to clients).
func TestReconfigIgnoresUnchangedConfig(t *testing.T) {
	body := "MCP_INSTRUCTIONS = steady\nHTTP_API_BASE_URL = https://example.org\n"
	target := &fakeTarget{}
	w := newReconfigWatcher(configFrom(t, body), target, nil)

	applied, needRestart := w.diff(configFrom(t, body))

	if len(applied) != 0 || len(needRestart) != 0 {
		t.Errorf("unchanged config reported applied=%v needRestart=%v, want neither", applied, needRestart)
	}
	if len(target.instructions) != 0 {
		t.Errorf("unchanged config still pushed to the server: %v", target.instructions)
	}
}

// TestReconfigTreatsUnsetAndEmptyAlike verifies that spelling out a parameter
// the daemon already treats as empty is not reported as a change.
func TestReconfigTreatsUnsetAndEmptyAlike(t *testing.T) {
	target := &fakeTarget{}
	w := newReconfigWatcher(configFrom(t, "# nothing set\n"), target, nil)

	applied, needRestart := w.diff(configFrom(t, "MCP_INSTRUCTIONS =\n"))

	if len(applied) != 0 || len(needRestart) != 0 {
		t.Errorf("empty value reported applied=%v needRestart=%v, want neither", applied, needRestart)
	}
}

// TestReconfigParamsAreUnique catches the copy-paste failure the table invites:
// a duplicated name would make one entry unreachable, and if the two disagreed
// about being dynamic, the parameter would silently stop being applied.
func TestReconfigParamsAreUnique(t *testing.T) {
	seen := map[string]bool{}
	for _, p := range reconfigParams {
		if seen[p.name] {
			t.Errorf("duplicate entry for %s", p.name)
		}
		seen[p.name] = true
	}
}
