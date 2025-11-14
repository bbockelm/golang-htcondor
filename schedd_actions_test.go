package htcondor

import (
	"context"
	"testing"

	"github.com/PelicanPlatform/classad/classad"
)

// TestJobActionConstants verifies job action constants are defined
func TestJobActionConstants(t *testing.T) {
	actions := map[string]JobAction{
		"ERROR":       JA_ERROR,
		"HOLD":        JA_HOLD_JOBS,
		"RELEASE":     JA_RELEASE_JOBS,
		"REMOVE":      JA_REMOVE_JOBS,
		"REMOVE_X":    JA_REMOVE_X_JOBS,
		"VACATE":      JA_VACATE_JOBS,
		"VACATE_FAST": JA_VACATE_FAST_JOBS,
		"SUSPEND":     JA_SUSPEND_JOBS,
		"CONTINUE":    JA_CONTINUE_JOBS,
	}

	for name, action := range actions {
		if action < 0 {
			t.Errorf("Action %s has invalid value: %d", name, action)
		}
	}
}

// TestActionResultTypes verifies result type constants
func TestActionResultTypes(t *testing.T) {
	if AR_TOTALS < 0 || AR_LONG < 0 {
		t.Error("Invalid action result types")
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

	results := parseJobActionResults(ad)

	if results.TotalJobs != 10 {
		t.Errorf("Expected TotalJobs=10, got %d", results.TotalJobs)
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
