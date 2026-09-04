package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParamDefaults(t *testing.T) {
	cfg, err := New()
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// Test that some known defaults from param_info.in are loaded
	// SHUTDOWN_FAST_TIMEOUT should default to 300
	val, ok := cfg.Get("SHUTDOWN_FAST_TIMEOUT")
	if !ok {
		t.Error("SHUTDOWN_FAST_TIMEOUT not found in defaults")
	} else if val != "300" {
		t.Errorf("SHUTDOWN_FAST_TIMEOUT = %q, want '300'", val)
	}

	// PREEN_INTERVAL should default to 86400
	val, ok = cfg.Get("PREEN_INTERVAL")
	if !ok {
		t.Error("PREEN_INTERVAL not found in defaults")
	} else if val != "86400" {
		t.Errorf("PREEN_INTERVAL = %q, want '86400'", val)
	}

	// MASTER should have a default with $(SBIN) in it (unexpanded)
	val, ok = cfg.Get("MASTER")
	if !ok {
		t.Error("MASTER not found in defaults")
	}
	// The value should contain SBIN since defaults are unexpanded
	// and SBIN is not defined, so it will remain as $(SBIN)
	if !strings.Contains(val, "SBIN") && !strings.Contains(val, "sbin") {
		t.Errorf("MASTER = %q, expected to contain SBIN reference", val)
	}
}

func TestConfigOptions(t *testing.T) {
	// Test with subsystem option
	cfg, err := NewWithOptions(ConfigOptions{
		Subsystem: "SCHEDD",
		LocalName: "test-node",
	})
	if err != nil {
		t.Fatalf("NewWithOptions() failed: %v", err)
	}

	// Check SUBSYSTEM is set correctly
	val, ok := cfg.Get("SUBSYSTEM")
	if !ok {
		t.Error("SUBSYSTEM not set")
	} else if val != "SCHEDD" {
		t.Errorf("SUBSYSTEM = %q, want 'SCHEDD'", val)
	}

	// Check LOCAL_NAME is set correctly
	val, ok = cfg.Get("LOCAL_NAME")
	if !ok {
		t.Error("LOCAL_NAME not set")
	} else if val != "test-node" {
		t.Errorf("LOCAL_NAME = %q, want 'test-node'", val)
	}
}

func TestConfigOptionsFromReader(t *testing.T) {
	input := `
CUSTOM_VAR = $(SUBSYSTEM)_value
`
	cfg, err := NewFromReaderWithOptions(strings.NewReader(input), ConfigOptions{
		Subsystem: "STARTD",
	})
	if err != nil {
		t.Fatalf("NewFromReaderWithOptions() failed: %v", err)
	}

	// Check SUBSYSTEM is set from options
	val, ok := cfg.Get("SUBSYSTEM")
	if !ok {
		t.Error("SUBSYSTEM not set")
	} else if val != "STARTD" {
		t.Errorf("SUBSYSTEM = %q, want 'STARTD'", val)
	}

	// Check CUSTOM_VAR uses the subsystem value
	val, ok = cfg.Get("CUSTOM_VAR")
	if !ok {
		t.Error("CUSTOM_VAR not set")
	} else if val != "STARTD_value" {
		t.Errorf("CUSTOM_VAR = %q, want 'STARTD_value'", val)
	}
}

func TestParamDefaultsWithMacros(t *testing.T) {
	// Many param defaults contain macro references like $(LOG), $(SBIN), etc.
	// These should remain unexpanded until Get() is called
	cfg, err := New()
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// Set a base directory
	cfg.Set("SBIN", "/usr/local/condor/sbin")

	// Now MASTER should expand to the full path
	val, ok := cfg.Get("MASTER")
	if !ok {
		t.Error("MASTER not found")
	}
	// Should now have the expanded path
	if !strings.Contains(val, "/usr/local/condor/sbin") {
		t.Errorf("MASTER = %q, expected to contain '/usr/local/condor/sbin'", val)
	}
}

func TestDefaultSubsystem(t *testing.T) {
	// Without specifying subsystem, it should default to "TOOL"
	cfg, err := New()
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	val, ok := cfg.Get("SUBSYSTEM")
	if !ok {
		t.Error("SUBSYSTEM not set")
	} else if val != "TOOL" {
		t.Errorf("SUBSYSTEM = %q, want 'TOOL'", val)
	}
}

// TestParamInfoSourceMatchesSnapshot guards against the vendored snapshot and
// the generated code drifting apart: editing param/SOURCE_VERSION without
// re-running "go generate" leaves ParamInfoSource claiming the old release.
func TestParamInfoSourceMatchesSnapshot(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "param", "SOURCE_VERSION"))
	if err != nil {
		t.Fatalf("reading param/SOURCE_VERSION: %v", err)
	}
	want := strings.TrimSpace(string(data))
	if want == "" {
		t.Fatal("param/SOURCE_VERSION is empty")
	}
	if ParamInfoSource != want {
		t.Errorf("ParamInfoSource = %q, but param/SOURCE_VERSION says %q; re-run go generate ./config/", ParamInfoSource, want)
	}
}
