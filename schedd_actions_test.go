package htcondor

import (
	"context"
	"testing"

	"github.com/PelicanPlatform/classad/classad"
)

// TestJobActionConstants verifies job action constants have the exact wire
// values of the C++ JobAction enum (src/condor_utils/enum_utils.h:106-116).
// These integers go on the wire as ATTR_JOB_ACTION and are matched by the
// schedd's switch statement, so any drift silently mis-dispatches actions.
func TestJobActionConstants(t *testing.T) {
	expected := map[string]struct {
		action JobAction
		value  int
	}{
		"ERROR":               {JA_ERROR, 0},
		"HOLD":                {JA_HOLD_JOBS, 1},
		"RELEASE":             {JA_RELEASE_JOBS, 2},
		"REMOVE":              {JA_REMOVE_JOBS, 3},
		"REMOVE_X":            {JA_REMOVE_X_JOBS, 4},
		"VACATE":              {JA_VACATE_JOBS, 5},
		"VACATE_FAST":         {JA_VACATE_FAST_JOBS, 6},
		"CLEAR_DIRTY":         {JA_CLEAR_DIRTY_JOB_ATTRS, 7},
		"SUSPEND":             {JA_SUSPEND_JOBS, 8},
		"CONTINUE":            {JA_CONTINUE_JOBS, 9},
		"TRANSFER_AND_REMOVE": {JA_TRANSFER_AND_REMOVE_JOBS, 10},
	}

	for name, e := range expected {
		if int(e.action) != e.value {
			t.Errorf("Action %s = %d, want %d (must match C++ enum_utils.h)", name, int(e.action), e.value)
		}
	}
}

// TestActionResultTypes verifies result type constants match the C++
// action_result_type_t enum (src/condor_daemon_client/dc_schedd.h:63-67).
func TestActionResultTypes(t *testing.T) {
	if int(AR_NONE) != 0 {
		t.Errorf("AR_NONE = %d, want 0", int(AR_NONE))
	}
	if int(AR_LONG) != 1 {
		t.Errorf("AR_LONG = %d, want 1", int(AR_LONG))
	}
	if int(AR_TOTALS) != 2 {
		t.Errorf("AR_TOTALS = %d, want 2", int(AR_TOTALS))
	}
}

// TestActionResultConstants verifies per-job result codes match the C++
// action_result_t enum (src/condor_daemon_client/dc_schedd.h:52-60).
func TestActionResultConstants(t *testing.T) {
	cases := map[string]struct {
		result ActionResult
		value  int
	}{
		"ERROR":             {AR_ERROR, 0},
		"SUCCESS":           {AR_SUCCESS, 1},
		"NOT_FOUND":         {AR_NOT_FOUND, 2},
		"BAD_STATUS":        {AR_BAD_STATUS, 3},
		"ALREADY_DONE":      {AR_ALREADY_DONE, 4},
		"PERMISSION_DENIED": {AR_PERMISSION_DENIED, 5},
		"LIMIT_EXCEEDED":    {AR_LIMIT_EXCEEDED, 6},
	}
	for name, c := range cases {
		if int(c.result) != c.value {
			t.Errorf("AR_%s = %d, want %d", name, int(c.result), c.value)
		}
	}
}

// TestParseJobActionResults verifies parsing of result ClassAds
func TestParseJobActionResults(t *testing.T) {
	// Create a result ad with some totals
	// Test with actual indexed results format (result_total_N)
	ad := classad.New()
	_ = ad.Set("TotalJobAds", int64(10))
	_ = ad.Set("result_total_0", int64(0)) // Error
	_ = ad.Set("result_total_1", int64(8)) // Success
	_ = ad.Set("result_total_2", int64(1)) // NotFound
	_ = ad.Set("result_total_3", int64(0)) // BadStatus
	_ = ad.Set("result_total_4", int64(0)) // AlreadyDone
	_ = ad.Set("result_total_5", int64(1)) // PermissionDenied
	_ = ad.Set("result_total_6", int64(2)) // LimitExceeded

	results := parseJobActionResults(ad)

	// TotalJobs is the sum of all AR_* result counts:
	// 8 (success) + 1 (not found) + 1 (permission denied) + 2 (limit exceeded) = 12.
	if results.TotalJobs != 12 {
		t.Errorf("Expected TotalJobs=12, got %d", results.TotalJobs)
	}
	if results.LimitExceeded != 2 {
		t.Errorf("Expected LimitExceeded=2, got %d", results.LimitExceeded)
	}
	if results.Success != 8 {
		t.Errorf("Expected Success=8, got %d", results.Success)
	}
	if results.NotFound != 1 {
		t.Errorf("Expected NotFound=1, got %d", results.NotFound)
	}
	if results.PermissionDenied != 1 {
		t.Errorf("Expected PermissionDenied=1, got %d", results.PermissionDenied)
	}
	if results.BadStatus != 0 {
		t.Errorf("Expected BadStatus=0, got %d", results.BadStatus)
	}
	if results.Error != 0 {
		t.Errorf("Expected Error=0, got %d", results.Error)
	}
}

// TestRemoveJobsValidation verifies parameter validation
func TestRemoveJobsValidation(t *testing.T) {
	schedd := NewSchedd("test", "localhost:9618")
	ctx := context.Background()

	// Test empty constraint
	_, err := schedd.RemoveJobs(ctx, "", "reason")
	if err == nil {
		t.Error("Expected error for empty constraint")
	}

	// Test empty IDs
	_, err = schedd.RemoveJobsByID(ctx, []string{}, "reason")
	if err == nil {
		t.Error("Expected error for empty IDs")
	}
}

// TestActOnJobsValidation verifies actOnJobs parameter validation
func TestActOnJobsValidation(t *testing.T) {
	schedd := NewSchedd("test", "localhost:9618")
	ctx := context.Background()

	// Test both constraint and IDs specified (should fail)
	_, err := schedd.actOnJobs(ctx, JA_REMOVE_JOBS, "true", []string{"1.0"}, "", "", "", "", AR_TOTALS)
	if err == nil {
		t.Error("Expected error when both constraint and IDs are specified")
	}
	if err.Error() != "cannot specify both constraint and ids" {
		t.Errorf("Unexpected error message: %v", err)
	}

	// Test neither constraint nor IDs specified (should fail)
	_, err = schedd.actOnJobs(ctx, JA_REMOVE_JOBS, "", nil, "", "", "", "", AR_TOTALS)
	if err == nil {
		t.Error("Expected error when neither constraint nor IDs are specified")
	}
	if err.Error() != "must specify either constraint or ids" {
		t.Errorf("Unexpected error message: %v", err)
	}
}
