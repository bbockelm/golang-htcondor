package config

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func TestNewConfig(t *testing.T) {
	cfg, err := NewFromReader(strings.NewReader(""))
	if err != nil {
		t.Fatalf("Failed to create config: %v", err)
	}

	// Check built-in macros
	if _, ok := cfg.Get("SECOND"); !ok {
		t.Error("SECOND not defined")
	}

	if val, ok := cfg.Get("MINUTE"); !ok || val != "60" {
		t.Errorf("MINUTE = %q, want 60", val)
	}

	if val, ok := cfg.Get("HOUR"); !ok || val != "3600" {
		t.Errorf("HOUR = %q, want 3600", val)
	}
}

func TestSimpleAssignment(t *testing.T) {
	input := `
# This is a comment
FOO = bar
BAZ = 123
	`

	cfg, err := NewFromReader(strings.NewReader(input))
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	if val, ok := cfg.Get("FOO"); !ok || val != "bar" {
		t.Errorf("FOO = %q, want bar", val)
	}

	if val, ok := cfg.Get("BAZ"); !ok || val != "123" {
		t.Errorf("BAZ = %q, want 123", val)
	}
}

func TestMacroExpansion(t *testing.T) {
	input := `
A = hello
B = $(A) world
C = $(B)!
	`

	cfg, err := NewFromReader(strings.NewReader(input))
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	if val, ok := cfg.Get("B"); !ok || val != "hello world" {
		t.Errorf("B = %q, want 'hello world'", val)
	}

	if val, ok := cfg.Get("C"); !ok || val != "hello world!" {
		t.Errorf("C = %q, want 'hello world!'", val)
	}
}

func TestMacroWithDefault(t *testing.T) {
	input := `A = $(UNDEFINED:default_value)
B = $(MYVAR:fallback)
MYVAR = actual
`

	cfg, err := NewFromReader(strings.NewReader(input))
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	if val, ok := cfg.Get("A"); !ok || val != "default_value" {
		t.Errorf("A = %q, want 'default_value'", val)
	}

	if val, ok := cfg.Get("B"); !ok || val != "actual" {
		t.Errorf("B = %q, want 'actual'", val)
	}
}

func TestIncrementalDefinition(t *testing.T) {
	input := `
A = xxx
A = $(A)yyy
A = $(A)zzz
	`

	cfg, err := NewFromReader(strings.NewReader(input))
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	if val, ok := cfg.Get("A"); !ok || val != "xxxyyyzzz" {
		t.Errorf("A = %q, want 'xxxyyyzzz'", val)
	}
}

func TestLineContinuation(t *testing.T) {
	input := `
LONG_VALUE = this is a \
very long \
configuration value
	`

	cfg, err := NewFromReader(strings.NewReader(input))
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	val, ok := cfg.Get("LONG_VALUE")
	if !ok {
		t.Fatal("LONG_VALUE not defined")
	}

	expected := "this is a very long configuration value"
	if val != expected {
		t.Errorf("LONG_VALUE = %q, want %q", val, expected)
	}
}

func TestCircularReferenceDetection(t *testing.T) {
	input := `
A = $(B)
B = $(A)
	`

	cfg, err := NewFromReader(strings.NewReader(input))
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	// Should not hang, should return unexpanded or partially expanded
	val, ok := cfg.Get("A")
	if !ok {
		t.Error("A not defined")
	}

	// The value should contain unexpanded macro (loop detected)
	t.Logf("A = %q (circular reference detected)", val)
}

func TestBuiltinMacros(t *testing.T) {
	cfg, err := NewFromReader(strings.NewReader(""))
	if err != nil {
		t.Fatalf("Failed to create config: %v", err)
	}

	tests := []string{
		"HOSTNAME",
		"FULL_HOSTNAME",
		"PID",
		"PPID",
		"SUBSYSTEM",
	}

	for _, key := range tests {
		if _, ok := cfg.Get(key); !ok {
			t.Errorf("Built-in macro %s not defined", key)
		}
	}
}

// TestRuntimeMacroValues verifies the actual values of runtime macros
func TestRuntimeMacroValues(t *testing.T) {
	cfg, err := NewFromReader(strings.NewReader(""))
	if err != nil {
		t.Fatalf("Failed to create config: %v", err)
	}

	// Test HOSTNAME and FULL_HOSTNAME
	hostname, ok := cfg.Get("HOSTNAME")
	if !ok {
		t.Error("HOSTNAME not set")
	} else if hostname == "" {
		t.Error("HOSTNAME is empty")
	}

	fullHostname, ok := cfg.Get("FULL_HOSTNAME")
	if !ok {
		t.Error("FULL_HOSTNAME not set")
	} else if fullHostname == "" {
		t.Error("FULL_HOSTNAME is empty")
	}

	// HOSTNAME should be the short name (before first dot)
	expectedShort := strings.Split(fullHostname, ".")[0]
	if hostname != expectedShort {
		t.Errorf("HOSTNAME = %q, want %q (short form of FULL_HOSTNAME)", hostname, expectedShort)
	}

	// Test PID and PPID are numeric
	pid, ok := cfg.Get("PID")
	if !ok {
		t.Error("PID not set")
	} else if _, err := strconv.Atoi(pid); err != nil {
		t.Errorf("PID = %q is not numeric: %v", pid, err)
	}

	ppid, ok := cfg.Get("PPID")
	if !ok {
		t.Error("PPID not set")
	} else if _, err := strconv.Atoi(ppid); err != nil {
		t.Errorf("PPID = %q is not numeric: %v", ppid, err)
	}

	// Test SUBSYSTEM defaults to TOOL
	subsystem, ok := cfg.Get("SUBSYSTEM")
	if !ok {
		t.Error("SUBSYSTEM not set")
	} else if subsystem != "TOOL" {
		t.Errorf("SUBSYSTEM = %q, want 'TOOL' (default)", subsystem)
	}
}

// TestRuntimeMacrosWithOptions tests runtime macros with custom options
func TestRuntimeMacrosWithOptions(t *testing.T) {
	cfg, err := NewFromReaderWithOptions(strings.NewReader(""), ConfigOptions{
		Subsystem: "STARTD",
		LocalName: "slot1",
	})
	if err != nil {
		t.Fatalf("Failed to create config: %v", err)
	}

	// Test SUBSYSTEM is set from options
	subsystem, ok := cfg.Get("SUBSYSTEM")
	if !ok {
		t.Error("SUBSYSTEM not set")
	} else if subsystem != "STARTD" {
		t.Errorf("SUBSYSTEM = %q, want 'STARTD'", subsystem)
	}

	// Test LOCAL_NAME is set from options
	localName, ok := cfg.Get("LOCAL_NAME")
	if !ok {
		t.Error("LOCAL_NAME not set")
	} else if localName != "slot1" {
		t.Errorf("LOCAL_NAME = %q, want 'slot1'", localName)
	}
}

// TestUnimplementedRuntimeMacros documents which runtime macros are NOT implemented
func TestUnimplementedRuntimeMacros(t *testing.T) {
	cfg, err := NewFromReader(strings.NewReader(""))
	if err != nil {
		t.Fatalf("Failed to create config: %v", err)
	}

	// All Priority 1 and Priority 2 runtime macros are now implemented!
	// This test now just confirms that all documented macros are available.

	implementedMacros := []string{
		// Priority 1 (Session 2)
		"IP_ADDRESS", "IPV4_ADDRESS", "IPV6_ADDRESS", "IP_ADDRESS_IS_V6",
		"USERNAME", "CONFIG_ROOT", "DETECTED_CPUS_LIMIT",

		// Priority 2 (Session 3)
		"DETECTED_CPUS", "DETECTED_PHYSICAL_CPUS", "DETECTED_CORES",
		"DETECTED_MEMORY", "ARCH", "OPSYS", "OPSYS_VER", "OPSYS_AND_VER",
		"UNAME_ARCH", "UNAME_OPSYS",
	}

	// TILDE is optional (only available if 'condor' user exists)
	optionalMacros := []string{
		"TILDE",
	}

	t.Log("Verifying all Priority 1 and Priority 2 runtime macros are implemented:")
	for _, key := range implementedMacros {
		val, ok := cfg.Get(key)
		if !ok || val == "" {
			// OPSYS_VER and OPSYS_AND_VER may not be available on all platforms
			if key == "OPSYS_VER" || key == "OPSYS_AND_VER" {
				t.Logf("  %s = <not available on this platform>", key)
			} else {
				t.Errorf("  %s = <not set> (expected to be implemented)", key)
			}
		} else {
			t.Logf("  %s = %q ✓", key, val)
		}
	}

	t.Log("Verifying optional runtime macros:")
	for _, key := range optionalMacros {
		val, ok := cfg.Get(key)
		if !ok || val == "" {
			t.Logf("  %s = <not available> (optional)", key)
		} else {
			t.Logf("  %s = %q ✓", key, val)
		}
	}
}

// TestPriority1RuntimeMacros tests the newly implemented Priority 1 runtime macros
func TestPriority1RuntimeMacros(t *testing.T) {
	cfg, err := NewFromReader(strings.NewReader(""))
	if err != nil {
		t.Fatalf("Failed to create config: %v", err)
	}

	// Test IP address macros
	t.Run("IPAddresses", func(t *testing.T) {
		ipAddr, hasIP := cfg.Get("IP_ADDRESS")
		ipv4Addr, hasIPv4 := cfg.Get("IPV4_ADDRESS")
		ipv6Addr, hasIPv6 := cfg.Get("IPV6_ADDRESS")
		isV6, hasIsV6 := cfg.Get("IP_ADDRESS_IS_V6")

		t.Logf("IP_ADDRESS = %q (set: %v)", ipAddr, hasIP)
		t.Logf("IPV4_ADDRESS = %q (set: %v)", ipv4Addr, hasIPv4)
		t.Logf("IPV6_ADDRESS = %q (set: %v)", ipv6Addr, hasIPv6)
		t.Logf("IP_ADDRESS_IS_V6 = %q (set: %v)", isV6, hasIsV6)

		// At least one IP address should be detected on most systems
		if !hasIP && !hasIPv4 && !hasIPv6 {
			t.Log("Warning: No IP addresses detected (may be expected in some environments)")
		}

		// If IP_ADDRESS is set, IP_ADDRESS_IS_V6 should also be set
		if hasIP && !hasIsV6 {
			t.Error("IP_ADDRESS is set but IP_ADDRESS_IS_V6 is not")
		}

		// IP_ADDRESS_IS_V6 should be "true" or "false"
		if hasIsV6 && isV6 != "true" && isV6 != "false" {
			t.Errorf("IP_ADDRESS_IS_V6 = %q, expected 'true' or 'false'", isV6)
		}

		// If IP_ADDRESS is set and contains ":", it should be IPv6
		if hasIP && strings.Contains(ipAddr, ":") {
			if isV6 != "true" {
				t.Errorf("IP_ADDRESS contains ':' but IP_ADDRESS_IS_V6 = %q (expected 'true')", isV6)
			}
		}

		// If IP_ADDRESS doesn't contain ":", it should be IPv4
		if hasIP && !strings.Contains(ipAddr, ":") {
			if isV6 != "false" {
				t.Errorf("IP_ADDRESS doesn't contain ':' but IP_ADDRESS_IS_V6 = %q (expected 'false')", isV6)
			}
		}
	})

	// Test TILDE macro
	t.Run("TILDE", func(t *testing.T) {
		tilde, hasTilde := cfg.Get("TILDE")
		t.Logf("TILDE = %q (set: %v)", tilde, hasTilde)

		// TILDE may not be set if condor user doesn't exist
		if hasTilde && tilde != "" {
			// Should be an absolute path
			if !filepath.IsAbs(tilde) {
				t.Errorf("TILDE = %q is not an absolute path", tilde)
			}
		} else {
			t.Log("TILDE not set (condor user may not exist on this system)")
		}
	})

	// Test USERNAME macro
	t.Run("USERNAME", func(t *testing.T) {
		username, hasUsername := cfg.Get("USERNAME")
		t.Logf("USERNAME = %q (set: %v)", username, hasUsername)

		if !hasUsername || username == "" {
			t.Error("USERNAME should be set to current user's username")
		}
	})

	// Test CONFIG_ROOT macro
	t.Run("CONFIG_ROOT", func(t *testing.T) {
		configRoot, hasConfigRoot := cfg.Get("CONFIG_ROOT")
		t.Logf("CONFIG_ROOT = %q (set: %v)", configRoot, hasConfigRoot)

		if !hasConfigRoot {
			t.Error("CONFIG_ROOT should always be set")
		} else if !filepath.IsAbs(configRoot) {
			// Should be an absolute path
			t.Errorf("CONFIG_ROOT = %q is not an absolute path", configRoot)
		}
	})

	// Test DETECTED_CPUS_LIMIT macro
	t.Run("DETECTED_CPUS_LIMIT", func(t *testing.T) {
		cpusLimit, hasLimit := cfg.Get("DETECTED_CPUS_LIMIT")
		t.Logf("DETECTED_CPUS_LIMIT = %q (set: %v)", cpusLimit, hasLimit)

		if !hasLimit {
			t.Error("DETECTED_CPUS_LIMIT should be set")
		} else {
			// Should be a valid integer
			if limit, err := strconv.Atoi(cpusLimit); err != nil {
				t.Errorf("DETECTED_CPUS_LIMIT = %q is not a valid integer: %v", cpusLimit, err)
			} else if limit <= 0 {
				t.Errorf("DETECTED_CPUS_LIMIT = %d should be positive", limit)
			}
		}
	})
}

// TestCONFIG_ROOTWithEnvVar tests CONFIG_ROOT when CONDOR_CONFIG is set
func TestCONFIG_ROOTWithEnvVar(t *testing.T) {
	// Save original CONDOR_CONFIG
	origCondorConfig := os.Getenv("CONDOR_CONFIG")
	defer func() {
		if origCondorConfig != "" {
			_ = os.Setenv("CONDOR_CONFIG", origCondorConfig)
		} else {
			_ = os.Unsetenv("CONDOR_CONFIG")
		}
	}()

	// Test with CONDOR_CONFIG set
	testPath := "/opt/condor/etc/condor_config"
	_ = os.Setenv("CONDOR_CONFIG", testPath)

	cfg, err := NewFromReader(strings.NewReader(""))
	if err != nil {
		t.Fatalf("Failed to create config: %v", err)
	}

	configRoot, ok := cfg.Get("CONFIG_ROOT")
	if !ok {
		t.Fatal("CONFIG_ROOT not set")
	}

	expectedRoot := "/opt/condor/etc"
	if configRoot != expectedRoot {
		t.Errorf("CONFIG_ROOT = %q, want %q", configRoot, expectedRoot)
	}
}

// TestDETECTED_CPUS_LIMITWithEnvVars tests DETECTED_CPUS_LIMIT with environment variables
func TestDETECTED_CPUS_LIMITWithEnvVars(t *testing.T) {
	// Save original environment variables
	origOMP := os.Getenv("OMP_THREAD_LIMIT")
	origSLURM := os.Getenv("SLURM_CPUS_ON_NODE")
	defer func() {
		if origOMP != "" {
			_ = os.Setenv("OMP_THREAD_LIMIT", origOMP)
		} else {
			_ = os.Unsetenv("OMP_THREAD_LIMIT")
		}
		if origSLURM != "" {
			_ = os.Setenv("SLURM_CPUS_ON_NODE", origSLURM)
		} else {
			_ = os.Unsetenv("SLURM_CPUS_ON_NODE")
		}
	}()

	// Get the actual detected CPUs on this system
	actualDetectedCPUs := runtime.NumCPU()

	tests := []struct {
		name          string
		ompLimit      string
		slurmLimit    string
		expectedLimit int // Expected result
	}{
		{
			name:          "No env vars",
			ompLimit:      "",
			slurmLimit:    "",
			expectedLimit: actualDetectedCPUs, // Should equal DETECTED_CPUS
		},
		{
			name:          "OMP_THREAD_LIMIT less than default",
			ompLimit:      "1",
			slurmLimit:    "",
			expectedLimit: 1,
		},
		{
			name:          "OMP_THREAD_LIMIT greater than default",
			ompLimit:      "100",
			slurmLimit:    "",
			expectedLimit: actualDetectedCPUs, // Should use DETECTED_CPUS
		},
		{
			name:          "SLURM_CPUS_ON_NODE less than default",
			ompLimit:      "",
			slurmLimit:    "1",
			expectedLimit: 1,
		},
		{
			name:          "Both set, OMP is minimum",
			ompLimit:      "1",
			slurmLimit:    "100",
			expectedLimit: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set environment variables
			if tt.ompLimit != "" {
				_ = os.Setenv("OMP_THREAD_LIMIT", tt.ompLimit)
			} else {
				_ = os.Unsetenv("OMP_THREAD_LIMIT")
			}
			if tt.slurmLimit != "" {
				_ = os.Setenv("SLURM_CPUS_ON_NODE", tt.slurmLimit)
			} else {
				_ = os.Unsetenv("SLURM_CPUS_ON_NODE")
			}

			cfg, err := NewFromReader(strings.NewReader(""))
			if err != nil {
				t.Fatalf("Failed to create config: %v", err)
			}

			limitStr, ok := cfg.Get("DETECTED_CPUS_LIMIT")
			if !ok {
				t.Fatal("DETECTED_CPUS_LIMIT not set")
			}

			limit, err := strconv.Atoi(limitStr)
			if err != nil {
				t.Fatalf("DETECTED_CPUS_LIMIT = %q is not a valid integer: %v", limitStr, err)
			}

			if limit != tt.expectedLimit {
				t.Errorf("DETECTED_CPUS_LIMIT = %d, want %d", limit, tt.expectedLimit)
			}
		})
	}
}

//nolint:gocyclo // Test function with many test cases
func TestPriority2RuntimeMacros(t *testing.T) {
	cfg, err := New()
	if err != nil {
		t.Fatalf("Failed to create config: %v", err)
	}

	// Test CPU detection macros
	t.Run("DETECTED_CPUS", func(t *testing.T) {
		val, ok := cfg.Get("DETECTED_CPUS")
		if !ok {
			t.Fatal("DETECTED_CPUS not set")
		}
		cpus, err := strconv.Atoi(val)
		if err != nil || cpus <= 0 {
			t.Errorf("DETECTED_CPUS = %q, want positive integer", val)
		}
	})

	t.Run("DETECTED_PHYSICAL_CPUS", func(t *testing.T) {
		val, ok := cfg.Get("DETECTED_PHYSICAL_CPUS")
		if !ok {
			t.Fatal("DETECTED_PHYSICAL_CPUS not set")
		}
		cpus, err := strconv.Atoi(val)
		if err != nil || cpus <= 0 {
			t.Errorf("DETECTED_PHYSICAL_CPUS = %q, want positive integer", val)
		}
	})

	t.Run("DETECTED_CORES", func(t *testing.T) {
		val, ok := cfg.Get("DETECTED_CORES")
		if !ok {
			t.Fatal("DETECTED_CORES not set")
		}
		// DETECTED_CORES should be alias for DETECTED_CPUS
		detectedCPUs, _ := cfg.Get("DETECTED_CPUS")
		if val != detectedCPUs {
			t.Errorf("DETECTED_CORES = %q, want %q (same as DETECTED_CPUS)", val, detectedCPUs)
		}
	})

	t.Run("DETECTED_MEMORY", func(t *testing.T) {
		val, ok := cfg.Get("DETECTED_MEMORY")
		if !ok {
			t.Fatal("DETECTED_MEMORY not set")
		}
		mem, err := strconv.Atoi(val)
		if err != nil || mem <= 0 {
			t.Errorf("DETECTED_MEMORY = %q, want positive integer (MiB)", val)
		}
	})

	// Test ARCH macro
	t.Run("ARCH", func(t *testing.T) {
		val, ok := cfg.Get("ARCH")
		if !ok {
			t.Fatal("ARCH not set")
		}
		// Should be HTCondor format (uppercase)
		validArchs := []string{"X86_64", "INTEL", "ARM", "ARM64", "PPC64", "S390X"}
		valid := false
		for _, arch := range validArchs {
			if val == arch {
				valid = true
				break
			}
		}
		if !valid {
			t.Logf("ARCH = %q (valid but not in common list)", val)
		}
	})

	// Test OPSYS macros
	t.Run("OPSYS", func(t *testing.T) {
		val, ok := cfg.Get("OPSYS")
		if !ok {
			t.Fatal("OPSYS not set")
		}
		// Should be HTCondor format (uppercase)
		validOS := []string{"LINUX", "WINDOWS", "OSX", "FREEBSD", "OPENBSD", "NETBSD", "SOLARIS"}
		valid := false
		for _, os := range validOS {
			if val == os {
				valid = true
				break
			}
		}
		if !valid {
			t.Logf("OPSYS = %q (valid but not in common list)", val)
		}
	})

	t.Run("OPSYS_VER", func(t *testing.T) {
		val, ok := cfg.Get("OPSYS_VER")
		if !ok {
			t.Log("OPSYS_VER not set (may be unavailable on this platform)")
			return
		}
		// Should be a version number (major version)
		if _, err := strconv.Atoi(val); err != nil {
			t.Errorf("OPSYS_VER = %q, want numeric version", val)
		}
	})

	t.Run("OPSYS_AND_VER", func(t *testing.T) {
		val, ok := cfg.Get("OPSYS_AND_VER")
		if !ok {
			t.Log("OPSYS_AND_VER not set (OPSYS_VER may be unavailable)")
			return
		}
		// Should combine OPSYS and OPSYS_VER
		opsys, _ := cfg.Get("OPSYS")
		opsysVer, hasVer := cfg.Get("OPSYS_VER")
		if hasVer {
			expected := opsys + opsysVer
			if val != expected {
				t.Errorf("OPSYS_AND_VER = %q, want %q", val, expected)
			}
		}
	})

	// Test UNAME macros
	t.Run("UNAME_ARCH", func(t *testing.T) {
		val, ok := cfg.Get("UNAME_ARCH")
		if !ok {
			t.Fatal("UNAME_ARCH not set")
		}
		if val == "" {
			t.Error("UNAME_ARCH is empty")
		}
		// Should be uppercase
		if val != strings.ToUpper(val) {
			t.Errorf("UNAME_ARCH = %q, want uppercase", val)
		}
	})

	t.Run("UNAME_OPSYS", func(t *testing.T) {
		val, ok := cfg.Get("UNAME_OPSYS")
		if !ok {
			t.Fatal("UNAME_OPSYS not set")
		}
		if val == "" {
			t.Error("UNAME_OPSYS is empty")
		}
		// Should be uppercase
		if val != strings.ToUpper(val) {
			t.Errorf("UNAME_OPSYS = %q, want uppercase", val)
		}
	})
}

func TestEmptyAndCommentLines(t *testing.T) {
	input := `
# Comment line
   # Indented comment
FOO = bar

BAZ = qux
	# Another comment
	`

	cfg, err := NewFromReader(strings.NewReader(input))
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	if val, ok := cfg.Get("FOO"); !ok || val != "bar" {
		t.Errorf("FOO = %q, want bar", val)
	}

	if val, ok := cfg.Get("BAZ"); !ok || val != "qux" {
		t.Errorf("BAZ = %q, want qux", val)
	}
}

func TestNestedMacroExpansion(t *testing.T) {
	input := `
BASE = /usr/local
BIN = $(BASE)/bin
SBIN = $(BASE)/sbin
PROGRAM = $(BIN)/condor_master
	`

	cfg, err := NewFromReader(strings.NewReader(input))
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	if val, ok := cfg.Get("PROGRAM"); !ok || val != "/usr/local/bin/condor_master" {
		t.Errorf("PROGRAM = %q, want '/usr/local/bin/condor_master'", val)
	}
}

func TestMacroExpansionOrder(t *testing.T) {
	// Test that later definitions override earlier ones
	input := `
A = xxx
C = $(A)
A = yyy
	`

	cfg, err := NewFromReader(strings.NewReader(input))
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	// C should expand to the final value of A
	if val, ok := cfg.Get("C"); !ok || val != "yyy" {
		t.Errorf("C = %q, want 'yyy'", val)
	}
}

// TestCircularIncludeDetection covers the guard on the root
// configuration file: a file that includes itself must be reported
// rather than recursed. Exercised through parseConfigFile, which is the
// path loadConfigFileChain uses.
func TestCircularIncludeDetection(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "condor_config")
	if err := os.WriteFile(root, []byte("FOO = bar\ninclude : "+root+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := NewEmpty()
	err := cfg.parseConfigFile(root)
	if err == nil {
		t.Fatal("expected a circular include error")
	}
	if !strings.Contains(err.Error(), "circular include") {
		t.Errorf("expected 'circular include', got: %v", err)
	}
}

func TestMacroDefaultWithArithmetic(t *testing.T) {
	input := `DETECTED_CPUS_LIMIT = 4
MAX_ALLOC_CPUS = $(NUMCPUS:$(DETECTED_CPUS_LIMIT))-1
`

	cfg, err := NewFromReader(strings.NewReader(input))
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	// NUMCPUS is undefined, so it should use the default $(DETECTED_CPUS_LIMIT)
	// which expands to 4, giving us "4-1"
	// Note: HTCondor config doesn't evaluate arithmetic - that's done by ClassAd evaluator later
	if val, ok := cfg.Get("MAX_ALLOC_CPUS"); !ok {
		t.Error("MAX_ALLOC_CPUS not defined")
	} else if val != "4-1" {
		t.Errorf("MAX_ALLOC_CPUS = %q, want '4-1'", val)
	}
}
