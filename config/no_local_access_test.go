package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoLocalAccessInclude checks that a config parsed with
// NoLocalAccess refuses both include forms, and that the same text is
// accepted without the option — so the refusal is what stops it, not a
// grammar problem.
func TestNoLocalAccessInclude(t *testing.T) {
	dir := t.TempDir()
	included := filepath.Join(dir, "included.conf")
	if err := os.WriteFile(included, []byte("FROM_INCLUDE = yes\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct{ name, text string }{
		{"include", "include : \"" + included + "\"\n"},
		{"include ifexist", "include ifexist : \"" + included + "\"\n"},
	} {
		strict := NewEmptyWithOptions(ConfigOptions{NoLocalAccess: true})
		if err := strict.parseAndExecute(strings.NewReader(tc.text)); err == nil {
			t.Errorf("%s: expected a refusal", tc.name)
		} else if !strings.Contains(err.Error(), "not allowed") {
			t.Errorf("%s: unexpected error: %v", tc.name, err)
		}
		if got, _ := strict.Get("FROM_INCLUDE"); got != "" {
			t.Errorf("%s: included value reached the config: %q", tc.name, got)
		}

		relaxed := NewEmpty()
		if err := relaxed.parseAndExecute(strings.NewReader(tc.text)); err != nil {
			t.Errorf("%s: expected the default config to accept it: %v", tc.name, err)
			continue
		}
		if got, _ := relaxed.Get("FROM_INCLUDE"); got != "yes" {
			t.Errorf("%s: expected the include to be read by default, got %q", tc.name, got)
		}
	}
}

// TestNoLocalAccessIncludeCommand is the command-execution case: an
// `include command` runs a shell command as whoever is parsing.
func TestNoLocalAccessIncludeCommand(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "ran")

	text := "include command : touch " + marker + "\n"
	strict := NewEmptyWithOptions(ConfigOptions{NoLocalAccess: true})
	if err := strict.parseAndExecute(strings.NewReader(text)); err == nil {
		t.Error("expected `include command` to be refused")
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("`include command` ran the command despite NoLocalAccess")
	}

	if err := NewEmpty().parseAndExecute(strings.NewReader(text)); err != nil {
		t.Fatalf("expected the default config to run it: %v", err)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Errorf("expected the command to have run by default: %v", err)
	}
}

// TestNoLocalAccessEnv checks $ENV() cannot read the parsing process's
// environment under NoLocalAccess.
func TestNoLocalAccessEnv(t *testing.T) {
	t.Setenv("NO_LOCAL_ACCESS_PROBE", "daemon-secret")

	strict := NewEmptyWithOptions(ConfigOptions{NoLocalAccess: true})
	if err := strict.parseAndExecute(strings.NewReader("VALUE = $ENV(NO_LOCAL_ACCESS_PROBE)\n")); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got, _ := strict.Get("VALUE"); strings.Contains(got, "daemon-secret") {
		t.Errorf("$ENV() leaked the environment: %q", got)
	}

	relaxed := NewEmpty()
	if err := relaxed.parseAndExecute(strings.NewReader("VALUE = $ENV(NO_LOCAL_ACCESS_PROBE)\n")); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got, _ := relaxed.Get("VALUE"); got != "daemon-secret" {
		t.Errorf("expected $ENV() to expand by default, got %q", got)
	}
}
