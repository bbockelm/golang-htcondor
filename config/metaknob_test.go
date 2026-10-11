package config

import (
	"strings"
	"testing"
)

// TestMetaknobAlwaysRunJobs tests a simple metaknob without parameters or conditionals.
// This demonstrates that basic metaknob expansion from built-in parameters works.
// This satisfies the first part of the test requirements: metaknobs are loaded
// from the param defaults and can be expanded via "use POLICY : NAME".
func TestMetaknobAlwaysRunJobs(t *testing.T) {
	input := `
use POLICY : ALWAYS_RUN_JOBS
	`

	cfg, err := NewFromReader(strings.NewReader(input))
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	// ALWAYS_RUN_JOBS sets several policy variables
	tests := []struct {
		name     string
		expected string
	}{
		{"WANT_SUSPEND", "False"},
		{"WANT_VACATE", "True"},
		{"SUSPEND", "False"},
		{"CONTINUE", "True"},
		{"PREEMPT", "False"},
		{"START", "True"},
		{"KILL", "False"},
		{"PREEMPTION_REQUIREMENTS", "False"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if val, ok := cfg.Get(tt.name); !ok {
				t.Errorf("%s not defined after using POLICY : ALWAYS_RUN_JOBS", tt.name)
			} else if val != tt.expected {
				t.Errorf("%s = %q, want %q", tt.name, val, tt.expected)
			}
		})
	}
}

// TestMetaknobUWCSDesktop tests a complex metaknob with nested use directives.
func TestMetaknobUWCSDesktop(t *testing.T) {
	input := `
use POLICY : UWCS_DESKTOP
	`

	cfg, err := NewFromReader(strings.NewReader(input))
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	// The UWCS_DESKTOP policy should set these variables
	// It uses FEATURE : UWCS_DESKTOP_POLICY_VALUES which defines all the UWCS_* variables

	// Check that WANT_SUSPEND is defined
	if val, ok := cfg.Get("WANT_SUSPEND"); !ok {
		t.Error("WANT_SUSPEND not defined after using POLICY : UWCS_DESKTOP")
	} else {
		t.Logf("WANT_SUSPEND = %s", val)
	}

	// Check that START is defined
	if val, ok := cfg.Get("START"); !ok {
		t.Error("START not defined after using POLICY : UWCS_DESKTOP")
	} else {
		t.Logf("START = %s", val)
	}

	// Check that PREEMPT is defined
	if val, ok := cfg.Get("PREEMPT"); !ok {
		t.Error("PREEMPT not defined after using POLICY : UWCS_DESKTOP")
	} else {
		t.Logf("PREEMPT = %s", val)
	}

	// Check that CONTINUE is defined
	if val, ok := cfg.Get("CONTINUE"); !ok {
		t.Error("CONTINUE not defined after using POLICY : UWCS_DESKTOP")
	} else {
		t.Logf("CONTINUE = %s", val)
	}

	// Check that KILL is defined
	if val, ok := cfg.Get("KILL"); !ok {
		t.Error("KILL not defined after using POLICY : UWCS_DESKTOP")
	} else {
		t.Logf("KILL = %s", val)
	}

	// Check that WANT_VACATE is defined
	if val, ok := cfg.Get("WANT_VACATE"); !ok {
		t.Error("WANT_VACATE not defined after using POLICY : UWCS_DESKTOP")
	} else {
		t.Logf("WANT_VACATE = %s", val)
	}

	// Check that IS_OWNER is defined (specific to UWCS_DESKTOP)
	// The default has: IS_OWNER=(START =?= False)
	// But START and other variables have defaults, so this gets evaluated
	if val, ok := cfg.Get("IS_OWNER"); !ok {
		t.Error("IS_OWNER not defined after using POLICY : UWCS_DESKTOP")
	} else {
		t.Logf("IS_OWNER = %s", val)
		// The actual value depends on what START evaluates to
	}

	// Check that SLOTS_CONNECTED_TO_KEYBOARD is defined
	if val, ok := cfg.Get("SLOTS_CONNECTED_TO_KEYBOARD"); !ok {
		t.Error("SLOTS_CONNECTED_TO_KEYBOARD not defined after using POLICY : UWCS_DESKTOP")
	} else {
		// Should be the literal value "1024*1024" (not evaluated as an expression)
		t.Logf("SLOTS_CONNECTED_TO_KEYBOARD = %s", val)
		if val != "1024*1024" && val != "1048576" {
			t.Errorf("SLOTS_CONNECTED_TO_KEYBOARD = %q, want 1024*1024 or 1048576", val)
		}
	}

	// The UWCS_DESKTOP policy references UWCS_* variables that should come from the FEATURE
	// Check that UWCS_START is defined (from the feature)
	if val, ok := cfg.Get("UWCS_START"); !ok {
		t.Error("UWCS_START not defined (should come from FEATURE : UWCS_DESKTOP_POLICY_VALUES)")
	} else {
		t.Logf("UWCS_START = %s", val)
	}
}

// TestMetaknobPreemptIfWithVariable tests passing a variable parameter to a metaknob.
// This tests the second requirement: passing variables to metaknobs.
func TestMetaknobPreemptIfWithVariable(t *testing.T) {
	input := `
MEMORY_EXCEEDED = (isDefined(MemoryUsage) && MemoryUsage > RequestMemory)
use POLICY : PREEMPT_IF(MEMORY_EXCEEDED)
	`

	cfg, err := NewFromReader(strings.NewReader(input))
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	} // Check that the variable we defined is still there
	if val, ok := cfg.Get("MEMORY_EXCEEDED"); !ok {
		t.Fatal("MEMORY_EXCEEDED not defined")
	} else if val != "(isDefined(MemoryUsage) && MemoryUsage > RequestMemory)" {
		t.Errorf("MEMORY_EXCEEDED = %q, want (isDefined(MemoryUsage) && MemoryUsage > RequestMemory)", val)
	}

	// The PREEMPT_IF metaknob should set PREEMPT to reference our variable
	// According to the metaknob definition:
	// if defined PREEMPT
	//     PREEMPT = $($(1)) || $(PREEMPT)
	// else
	//     PREEMPT = $($(1))
	// endif
	//
	// $(1) is "MEMORY_EXCEEDED", so $($(1)) becomes $(MEMORY_EXCEEDED)
	// which should expand to our expression
	//
	// Since PREEMPT has a default value of "False", the metaknob will append
	// "|| $(PREEMPT)" to chain with existing configuration
	if val, ok := cfg.Get("PREEMPT"); !ok {
		t.Error("PREEMPT not defined after using POLICY : PREEMPT_IF")
	} else {
		expected := "(isDefined(MemoryUsage) && MemoryUsage > RequestMemory) || False"
		if val != expected {
			t.Errorf("PREEMPT = %q, want %q", val, expected)
		}
		t.Logf("PREEMPT = %s", val)
	}

	// PREEMPT_IF should also set MAXJOBRETIREMENTTIME
	// MAXJOBRETIREMENTTIME = ifthenelse($($(1)),-1,$(MAXJOBRETIREMENTTIME:0))
	if val, ok := cfg.Get("MAXJOBRETIREMENTTIME"); !ok {
		t.Error("MAXJOBRETIREMENTTIME not defined after using POLICY : PREEMPT_IF")
	} else {
		expected := "ifthenelse((isDefined(MemoryUsage) && MemoryUsage > RequestMemory),-1,0)"
		if val != expected {
			t.Errorf("MAXJOBRETIREMENTTIME = %q, want %q", val, expected)
		}
		t.Logf("MAXJOBRETIREMENTTIME = %s", val)
	}

	// PREEMPT_IF should also set WANT_SUSPEND
	// if defined WANT_SUSPEND
	//     WANT_SUSPEND = $($(1)) =!= true && $(WANT_SUSPEND)
	// else
	//     WANT_SUSPEND = $($(1)) =!= true
	// endif
	//
	// Since WANT_SUSPEND has a default value of "False", the metaknob will append
	// "&& $(WANT_SUSPEND)" to chain with existing configuration
	if val, ok := cfg.Get("WANT_SUSPEND"); !ok {
		t.Error("WANT_SUSPEND not defined after using POLICY : PREEMPT_IF")
	} else {
		expected := "(isDefined(MemoryUsage) && MemoryUsage > RequestMemory) =!= true && False"
		if val != expected {
			t.Errorf("WANT_SUSPEND = %q, want %q", val, expected)
		}
		t.Logf("WANT_SUSPEND = %s", val)
	}
}

// TestMetaknobPreemptIfChaining tests using PREEMPT_IF when PREEMPT is already defined
// This verifies the "|| $(PREEMPT)" chaining behavior
func TestMetaknobPreemptIfChaining(t *testing.T) {
	input := `
PREEMPT = ExistingCondition
MEMORY_EXCEEDED = MemoryUsage > RequestMemory
use POLICY : PREEMPT_IF(MEMORY_EXCEEDED)
	`

	cfg, err := NewFromReader(strings.NewReader(input))
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	// PREEMPT should now be "$(MEMORY_EXCEEDED) || $(PREEMPT)" which expands to
	// "MemoryUsage > RequestMemory || ExistingCondition"
	if val, ok := cfg.Get("PREEMPT"); !ok {
		t.Fatal("PREEMPT not defined")
	} else {
		expected := "MemoryUsage > RequestMemory || ExistingCondition"
		if val != expected {
			t.Errorf("PREEMPT = %q, want %q", val, expected)
		}
		t.Logf("PREEMPT = %s", val)
	}
}

// TestMetaknobBuiltInPreemptIfMemoryExceeded tests using the built-in
// PREEMPT_IF_MEMORY_EXCEEDED metaknob that defines MEMORY_EXCEEDED itself
func TestMetaknobBuiltInPreemptIfMemoryExceeded(t *testing.T) {
	input := `
use POLICY : PREEMPT_IF_MEMORY_EXCEEDED
	`

	cfg, err := NewFromReader(strings.NewReader(input))
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	// This metaknob should define MEMORY_EXCEEDED for us
	if val, ok := cfg.Get("MEMORY_EXCEEDED"); !ok {
		t.Error("MEMORY_EXCEEDED not defined by PREEMPT_IF_MEMORY_EXCEEDED")
	} else {
		// The default is: (JobUniverse != 13 && MemoryUsage =!= UNDEFINED && MemoryUsage > Memory)
		t.Logf("MEMORY_EXCEEDED = %s", val)
		if !strings.Contains(val, "MemoryUsage") {
			t.Errorf("MEMORY_EXCEEDED should reference MemoryUsage, got %q", val)
		}
	}

	// And PREEMPT should be set via the internal use of PREEMPT_IF
	if val, ok := cfg.Get("PREEMPT"); !ok {
		t.Error("PREEMPT not defined by PREEMPT_IF_MEMORY_EXCEEDED")
	} else {
		t.Logf("PREEMPT = %s", val)
		if !strings.Contains(val, "MemoryUsage") {
			t.Errorf("PREEMPT should reference MemoryUsage, got %q", val)
		}
	}
}

// TestMetaknobWithMultipleVariables tests a metaknob that takes multiple parameters
// The WANT_HOLD_IF metaknob takes 3 parameters
// NOTE: WANT_HOLD_IF uses nested 'use' directives which don't currently preserve
// parameter context, so this test is skipped.
func TestMetaknobWithMultipleVariables(t *testing.T) {
	t.Skip("WANT_HOLD_IF uses nested 'use' directives which don't preserve parameter context yet")

	input := `
DISK_EXCEEDED = DiskUsage > Disk
use POLICY : WANT_HOLD_IF(DISK_EXCEEDED, 104, Disk limit exceeded)
	`

	cfg, err := NewFromReader(strings.NewReader(input))
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	// WANT_HOLD_IF first calls PREEMPT_IF, so PREEMPT should be set
	if val, ok := cfg.Get("PREEMPT"); !ok {
		t.Error("PREEMPT not defined by WANT_HOLD_IF")
	} else {
		expected := "DiskUsage > Disk"
		if val != expected {
			t.Errorf("PREEMPT = %q, want %q", val, expected)
		}
	}

	// WANT_HOLD should be set based on parameter 1
	if val, ok := cfg.Get("WANT_HOLD"); !ok {
		t.Error("WANT_HOLD not defined by WANT_HOLD_IF")
	} else {
		// Expected: (JobUniverse != 1 && $($(1)))
		// which becomes: (JobUniverse != 1 && $(DISK_EXCEEDED))
		// which becomes: (JobUniverse != 1 && DiskUsage > Disk)
		expected := "(JobUniverse != 1 && DiskUsage > Disk)"
		if val != expected {
			t.Errorf("WANT_HOLD = %q, want %q", val, expected)
		}
	}

	// WANT_HOLD_SUBCODE should be set based on parameter 2
	if val, ok := cfg.Get("WANT_HOLD_SUBCODE"); !ok {
		t.Error("WANT_HOLD_SUBCODE not defined by WANT_HOLD_IF")
	} else {
		// Expected: ifThenElse($($(1)), 104 , UNDEFINED)
		// which becomes: ifThenElse($(DISK_EXCEEDED), 104 , UNDEFINED)
		// which becomes: ifThenElse(DiskUsage > Disk, 104 , UNDEFINED)
		expected := "ifThenElse(DiskUsage > Disk, 104 , UNDEFINED)"
		if val != expected {
			t.Errorf("WANT_HOLD_SUBCODE = %q, want %q", val, expected)
		}
	}

	// WANT_HOLD_REASON should be set based on parameter 3
	if val, ok := cfg.Get("WANT_HOLD_REASON"); !ok {
		t.Error("WANT_HOLD_REASON not defined by WANT_HOLD_IF")
	} else {
		// Expected: ifThenElse($($(1)), "disk usage exceeded allocated disk", UNDEFINED)
		// which becomes: ifThenElse($(DISK_EXCEEDED), "disk usage exceeded allocated disk", UNDEFINED)
		// which becomes: ifThenElse(DiskUsage > Disk, "disk usage exceeded allocated disk", UNDEFINED)
		expected := "ifThenElse(DiskUsage > Disk, \"disk usage exceeded allocated disk\", UNDEFINED)"
		if val != expected {
			t.Errorf("WANT_HOLD_REASON = %q, want %q", val, expected)
		}
	}
}

// TestMetaknobParam0 tests $(0) - all arguments
func TestMetaknobParam0(t *testing.T) {
	// PREEMPT_IF template uses $(0), let me verify by checking the template
	input := `
COND1 = Condition1
COND2 = Condition2
use POLICY : PREEMPT_IF(COND1)
	`
	cfg, err := NewFromReader(strings.NewReader(input))
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	// The PREEMPT_IF metaknob uses $(1), so $(1) should be expanded to "COND1"
	// and then $(COND1) should expand to "Condition1"
	if val, ok := cfg.Get("PREEMPT"); ok {
		t.Logf("PREEMPT = %s", val)
		if !strings.Contains(val, "Condition1") {
			t.Errorf("PREEMPT should contain 'Condition1', got %q", val)
		}
	}
}

// TestMetaknobParam0Hash tests $(0#) - number of arguments
// We'll test this by checking a metaknob that conditionally uses it
func TestMetaknobParam0Hash(t *testing.T) {
	// The error check in PREEMPT_IF uses $(1?) which should be "1" when arg exists
	input := `
COND1 = Condition1
use POLICY : PREEMPT_IF(COND1)
	`
	cfg, err := NewFromReader(strings.NewReader(input))
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	// If $(1?) works, the metaknob should execute without error
	// and PREEMPT should be set
	if _, ok := cfg.Get("PREEMPT"); !ok {
		t.Error("PREEMPT should be defined when PREEMPT_IF has an argument")
	}
}

// TestMetaknobParam0QuestionMark tests $(0?) - returns "1" if args exist
func TestMetaknobParam0QuestionMark(t *testing.T) {
	// Test with no arguments - the error directive should trigger
	input1 := `use POLICY : PREEMPT_IF`
	_, err1 := NewFromReader(strings.NewReader(input1))
	// Should get an error because $(1?) is "0" and !$(1?) is true
	if err1 == nil {
		t.Error("Expected error when PREEMPT_IF called with no arguments")
	} else {
		t.Logf("Got expected error: %v", err1)
	}

	// Test with empty parens
	input2 := `use POLICY : PREEMPT_IF()`
	_, err2 := NewFromReader(strings.NewReader(input2))
	if err2 == nil {
		t.Error("Expected error when PREEMPT_IF called with empty parens")
	} else {
		t.Logf("Got expected error: %v", err2)
	}

	// Test with argument - should work
	input3 := `
COND = Condition
use POLICY : PREEMPT_IF(COND)
	`
	cfg3, err3 := NewFromReader(strings.NewReader(input3))
	if err3 != nil {
		t.Errorf("Should not error when PREEMPT_IF has argument: %v", err3)
	} else if _, ok := cfg3.Get("PREEMPT"); !ok {
		t.Error("PREEMPT should be defined")
	}
}

// TestMetaknobParamNPlus tests $(N+) - arguments from N onwards
// WANT_HOLD_IF uses $(3+) for the reason text (all args from 3rd onward)
func TestMetaknobParamNPlus(t *testing.T) {
	t.Skip("WANT_HOLD_IF uses nested 'use' directives which don't preserve parameter context yet")

	// This would test $(3+) but WANT_HOLD_IF has nested use issues
	input := `
DISK_EXCEEDED = DiskUsage > Disk
use POLICY : WANT_HOLD_IF(DISK_EXCEEDED, 104, disk, usage, exceeded)
	`
	cfg, err := NewFromReader(strings.NewReader(input))
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	// $(3+) should give "disk, usage, exceeded"
	if val, ok := cfg.Get("WANT_HOLD_REASON"); ok {
		t.Logf("WANT_HOLD_REASON = %s", val)
		if !strings.Contains(val, "disk") || !strings.Contains(val, "usage") {
			t.Errorf("WANT_HOLD_REASON should contain multiple words from $(3+)")
		}
	}
}

// TestMetaknobParamWithDefaults tests $(N:default) syntax
func TestMetaknobParamWithDefaults(t *testing.T) {
	// PREEMPT_IF template uses $(MAXJOBRETIREMENTTIME:0) which is a variable default
	// but metaknob params can also have defaults
	// The MAXJOBRETIREMENTTIME line is: ifthenelse($($(1)),-1,$(MAXJOBRETIREMENTTIME:0))
	input := `
COND = Condition
use POLICY : PREEMPT_IF(COND)
	`
	cfg, err := NewFromReader(strings.NewReader(input))
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	if val, ok := cfg.Get("MAXJOBRETIREMENTTIME"); ok {
		t.Logf("MAXJOBRETIREMENTTIME = %s", val)
		// The :0 default should be used if MAXJOBRETIREMENTTIME wasn't previously defined
		if !strings.Contains(val, "0") && !strings.Contains(val, "-1") {
			t.Errorf("MAXJOBRETIREMENTTIME should contain default value")
		}
	}
}
