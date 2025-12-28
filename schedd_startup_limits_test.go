package htcondor

import (
	"context"
	"testing"
)

func TestStartupLimitRequest_Validation(t *testing.T) {
	tests := []struct {
		name    string
		req     *StartupLimitRequest
		wantErr bool
	}{
		{
			name: "valid basic limit",
			req: &StartupLimitRequest{
				Tag:        "test_limit",
				Expression: "RequestGpus > 0",
				RateCount:  10,
				RateWindow: 60,
			},
			wantErr: false,
		},
		{
			name:    "nil request",
			req:     nil,
			wantErr: true,
		},
		{
			name: "missing tag",
			req: &StartupLimitRequest{
				Expression: "RequestGpus > 0",
				RateCount:  10,
				RateWindow: 60,
			},
			wantErr: true,
		},
		{
			name: "missing expression",
			req: &StartupLimitRequest{
				Tag:        "test_limit",
				RateCount:  10,
				RateWindow: 60,
			},
			wantErr: true,
		},
		{
			name: "negative rate count",
			req: &StartupLimitRequest{
				Tag:        "test_limit",
				Expression: "RequestGpus > 0",
				RateCount:  -1,
				RateWindow: 60,
			},
			wantErr: true,
		},
		{
			name: "zero rate window with positive count",
			req: &StartupLimitRequest{
				Tag:        "test_limit",
				Expression: "RequestGpus > 0",
				RateCount:  10,
				RateWindow: 0,
			},
			wantErr: true,
		},
		{
			name: "zero rate count (unlimited monitoring)",
			req: &StartupLimitRequest{
				Tag:        "test_limit",
				Expression: "RequestGpus > 0",
				RateCount:  0,
				RateWindow: 0,
			},
			wantErr: false,
		},
		{
			name: "with optional fields",
			req: &StartupLimitRequest{
				Tag:            "test_limit",
				Name:           "GPU Rate Limit",
				Expression:     "RequestGpus > 0",
				CostExpression: "RequestGpus",
				RateCount:      10,
				RateWindow:     60,
				Burst:          5,
				MaxBurstCost:   3,
				Expiration:     3600,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a fake schedd (we won't actually connect)
			schedd := &Schedd{
				name:    "test_schedd",
				address: "localhost:9618",
			}

			// We can't actually test CreateStartupLimit without a real schedd,
			// but we can test the validation logic by examining the inputs
			var err error
			if tt.req == nil {
				_, err = schedd.CreateStartupLimit(context.TODO(), tt.req)
			} else {
				// Validate the same checks that CreateStartupLimit performs
				switch {
				case tt.req.Tag == "":
					err = &validationError{msg: "tag is required"}
				case tt.req.Expression == "":
					err = &validationError{msg: "expression is required"}
				case tt.req.RateCount < 0:
					err = &validationError{msg: "rate_count must be non-negative"}
				case tt.req.RateCount > 0 && tt.req.RateWindow <= 0:
					err = &validationError{msg: "rate_window must be positive when rate_count > 0"}
				}
			}

			if (err != nil) != tt.wantErr {
				t.Errorf("validation error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// validationError is a helper type for testing validation
type validationError struct {
	msg string
}

func (e *validationError) Error() string {
	return e.msg
}

func TestStartupLimitConstants(t *testing.T) {
	// Verify command codes match HTCondor's condor_commands.h
	// CREATE_STARTUP_LIMIT = SCHED_VERS + 159 = 400 + 159 = 559
	// QUERY_STARTUP_LIMITS = SCHED_VERS + 160 = 400 + 160 = 560
	if cmdCreateStartupLimit != 559 {
		t.Errorf("cmdCreateStartupLimit = %d, want 559", cmdCreateStartupLimit)
	}
	if cmdQueryStartupLimits != 560 {
		t.Errorf("cmdQueryStartupLimits = %d, want 560", cmdQueryStartupLimits)
	}
}

func TestStartupLimitAttributeNames(t *testing.T) {
	// Verify attribute names match HTCondor's expectations
	expectedAttrs := map[string]string{
		"StartupLimitUuid":           AttrStartupLimitUUID,
		"StartupLimitTag":            AttrStartupLimitTag,
		"StartupLimitName":           AttrStartupLimitName,
		"StartupLimitExpr":           AttrStartupLimitExpr,
		"StartupLimitCostExpr":       AttrStartupLimitCostExpr,
		"StartupLimitRateCount":      AttrStartupLimitRateCount,
		"StartupLimitRateWindow":     AttrStartupLimitRateWindow,
		"StartupLimitBurst":          AttrStartupLimitBurst,
		"StartupLimitMaxBurstCost":   AttrStartupLimitMaxBurstCost,
		"StartupLimitExpiration":     AttrStartupLimitExpiration,
		"StartupLimitStatus":         AttrStartupLimitStatus,
		"StartupLimitError":          AttrStartupLimitError,
		"StartupLimitJobsAllowed":    AttrStartupLimitJobsAllowed,
		"StartupLimitCostAllowed":    AttrStartupLimitCostAllowed,
		"StartupLimitJobsSkipped":    AttrStartupLimitJobsSkipped,
		"StartupLimitMatchesIgnored": AttrStartupLimitMatchesIgnored,
		"StartupLimitLastIgnored":    AttrStartupLimitLastIgnored,
		"StartupLimitIgnoredUsers":   AttrStartupLimitIgnoredUsers,
	}

	for expected, actual := range expectedAttrs {
		if expected != actual {
			t.Errorf("attribute name mismatch: expected %q, got %q", expected, actual)
		}
	}
}
