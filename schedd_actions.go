package htcondor

import (
	"context"
	"fmt"
	"strings"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/client"
	"github.com/bbockelm/cedar/commands"
	"github.com/bbockelm/cedar/message"
	"github.com/bbockelm/cedar/security"
)

// JobAction represents an action to perform on jobs
type JobAction int

// Job action constants based on HTCondor's JobAction enum
//
//nolint:revive // Constant names match HTCondor's C++ enum naming convention
const (
	JA_ERROR            JobAction = iota // Error/invalid action
	JA_HOLD_JOBS                         // Hold jobs
	JA_RELEASE_JOBS                      // Release held jobs
	JA_REMOVE_JOBS                       // Remove jobs
	JA_REMOVE_X_JOBS                     // Remove jobs with force (X = extended/force)
	JA_VACATE_JOBS                       // Vacate jobs (gentle)
	JA_VACATE_FAST_JOBS                  // Vacate jobs (fast/hard kill)
	JA_SUSPEND_JOBS                      // Suspend jobs
	JA_CONTINUE_JOBS                     // Continue suspended jobs
)

// ActionResultType specifies what kind of result information to return
type ActionResultType int

// Action result type constants
//
//nolint:revive // Constant names match HTCondor's C++ enum naming convention
const (
	AR_TOTALS ActionResultType = iota // Return only totals (default)
	AR_LONG                           // Return detailed per-job results
)

// ActionResult represents the result of an action on a single job
type ActionResult int

// Action result constants
//
//nolint:revive // Constant names match HTCondor's C++ enum naming convention
const (
	AR_ERROR             ActionResult = iota // Error occurred
	AR_SUCCESS                               // Action succeeded
	AR_NOT_FOUND                             // Job not found
	AR_BAD_STATUS                            // Job in wrong status for action
	AR_ALREADY_DONE                          // Action already performed
	AR_PERMISSION_DENIED                     // Permission denied
)

// JobActionResults contains the results of a job action
type JobActionResults struct {
	// Total count of each result type
	TotalJobs        int
	Success          int
	NotFound         int
	PermissionDenied int
	BadStatus        int
	AlreadyDone      int
	Error            int

	// The result ClassAd from the schedd (may contain per-job details)
	ResultAd *classad.ClassAd
}

// RemoveJobs removes jobs matching the constraint
// constraint is a ClassAd constraint expression
// reason is an optional reason for the removal (can be empty string)
func (s *Schedd) RemoveJobs(ctx context.Context, constraint string, reason string) (*JobActionResults, error) {
	if constraint == "" {
		return nil, fmt.Errorf("constraint cannot be empty")
	}

	return s.actOnJobs(ctx, JA_REMOVE_JOBS, constraint, nil, reason, "RemoveReason", "", "", AR_TOTALS)
}

// RemoveJobsByID removes specific jobs by their cluster.proc IDs
// ids is a slice of job IDs in "cluster.proc" format (e.g., []string{"123.0", "123.1"})
// reason is an optional reason for the removal (can be empty string)
func (s *Schedd) RemoveJobsByID(ctx context.Context, ids []string, reason string) (*JobActionResults, error) {
	if len(ids) == 0 {
		return nil, fmt.Errorf("ids cannot be empty")
	}

	return s.actOnJobs(ctx, JA_REMOVE_JOBS, "", ids, reason, "RemoveReason", "", "", AR_TOTALS)
}

// HoldJobs holds jobs matching the constraint
func (s *Schedd) HoldJobs(ctx context.Context, constraint string, reason string) (*JobActionResults, error) {
	if constraint == "" {
		return nil, fmt.Errorf("constraint cannot be empty")
	}

	return s.actOnJobs(ctx, JA_HOLD_JOBS, constraint, nil, reason, "HoldReason", "", "", AR_TOTALS)
}

// ReleaseJobs releases held jobs matching the constraint
func (s *Schedd) ReleaseJobs(ctx context.Context, constraint string, reason string) (*JobActionResults, error) {
	if constraint == "" {
		return nil, fmt.Errorf("constraint cannot be empty")
	}

	return s.actOnJobs(ctx, JA_RELEASE_JOBS, constraint, nil, reason, "ReleaseReason", "", "", AR_TOTALS)
}

// actOnJobs implements the ACT_ON_JOBS protocol
// This is based on DCSchedd::actOnJobs in HTCondor
//
//nolint:unparam // Parameters reserved for future actions and result types
func (s *Schedd) actOnJobs(
	ctx context.Context,
	action JobAction,
	constraint string,
	ids []string,
	reason string,
	reasonAttr string,
	reasonCode string,
	reasonCodeAttr string,
	resultType ActionResultType,
) (*JobActionResults, error) {
	// Validate parameters
	if constraint != "" && len(ids) > 0 {
		return nil, fmt.Errorf("cannot specify both constraint and ids")
	}
	if constraint == "" && len(ids) == 0 {
		return nil, fmt.Errorf("must specify either constraint or ids")
	}

	// Connect to schedd using cedar client
	htcondorClient, err := client.ConnectToAddress(ctx, s.address)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to schedd: %w", err)
	}
	defer func() {
		_ = htcondorClient.Close()
	}()

	// Get CEDAR stream from client
	cedarStream := htcondorClient.GetStream()

	// Get SecurityConfig from context, HTCondor config, or defaults
	secConfig, err := GetSecurityConfigOrDefault(ctx, nil, commands.ACT_ON_JOBS, "CLIENT", s.address)
	if err != nil {
		return nil, fmt.Errorf("failed to create security config: %w", err)
	}

	// Perform security handshake
	auth := security.NewAuthenticator(secConfig, cedarStream)
	_, err = auth.ClientHandshake(ctx)
	if err != nil {
		return nil, fmt.Errorf("security handshake failed: %w", err)
	}

	// Build command ClassAd
	cmdAd := classad.New()
	_ = cmdAd.Set("JobAction", int64(action))
	_ = cmdAd.Set("ActionResultType", int64(resultType))

	if constraint != "" {
		// Insert constraint as an expression
		constraintExpr, err := classad.ParseExpr(constraint)
		if err != nil {
			return nil, fmt.Errorf("invalid constraint expression: %w", err)
		}
		_ = cmdAd.Set("ActionConstraint", constraintExpr)
	} else if len(ids) > 0 {
		// Join IDs as comma-separated string
		idsStr := strings.Join(ids, ",")
		_ = cmdAd.Set("ActionIds", idsStr)
	}

	if reasonAttr != "" && reason != "" {
		_ = cmdAd.Set(reasonAttr, reason)
	}

	if reasonCodeAttr != "" && reasonCode != "" {
		// Reason code is an expression
		codeExpr, err := classad.ParseExpr(reasonCode)
		if err != nil {
			return nil, fmt.Errorf("invalid reason code expression: %w", err)
		}
		_ = cmdAd.Set(reasonCodeAttr, codeExpr)
	}

	// Send command ClassAd
	msg := message.NewMessageForStream(cedarStream)
	if err := msg.PutClassAd(ctx, cmdAd); err != nil {
		return nil, fmt.Errorf("failed to send command ad: %w", err)
	}
	if err := msg.FinishMessage(ctx); err != nil {
		return nil, fmt.Errorf("failed to finish message: %w", err)
	}

	// Read response ClassAd
	responseMsg := message.NewMessageFromStream(cedarStream)
	resultAd, err := responseMsg.GetClassAd(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to read response ad: %w", err)
	}

	// Check if action failed
	actionResult, ok := resultAd.EvaluateAttrInt("ActionResult")
	if !ok || actionResult != 1 { // OK = 1
		// Action failed, return results anyway so caller can see what went wrong
		return parseJobActionResults(resultAd), fmt.Errorf("action failed: result=%d", actionResult)
	}

	// Send acknowledgment that we're ready to proceed
	ackMsg := message.NewMessageForStream(cedarStream)
	if err := ackMsg.PutInt32(ctx, 1); err != nil { // OK = 1
		return nil, fmt.Errorf("failed to send acknowledgment: %w", err)
	}
	if err := ackMsg.FinishMessage(ctx); err != nil {
		return nil, fmt.Errorf("failed to finish acknowledgment: %w", err)
	}

	// Read final confirmation
	confirmMsg := message.NewMessageFromStream(cedarStream)
	confirmation, err := confirmMsg.GetInt32(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to read confirmation: %w", err)
	}
	if confirmation != 1 { // OK = 1
		return parseJobActionResults(resultAd), fmt.Errorf("schedd failed to commit changes: result=%d", confirmation)
	}

	// Parse and return results
	return parseJobActionResults(resultAd), nil
}

// parseJobActionResults extracts job action results from the result ClassAd
func parseJobActionResults(resultAd *classad.ClassAd) *JobActionResults {
	results := &JobActionResults{
		ResultAd: resultAd,
	}

	// HTCondor uses indexed result attributes: result_total_0, result_total_1, etc.
	// where the index corresponds to the ActionResult enum value:
	// AR_ERROR = 0, AR_SUCCESS = 1, AR_NOT_FOUND = 2, AR_BAD_STATUS = 3,
	// AR_ALREADY_DONE = 4, AR_PERMISSION_DENIED = 5

	// Extract indexed results
	if val, ok := resultAd.EvaluateAttrInt("result_total_0"); ok {
		results.Error = int(val)
	}
	if val, ok := resultAd.EvaluateAttrInt("result_total_1"); ok {
		results.Success = int(val)
	}
	if val, ok := resultAd.EvaluateAttrInt("result_total_2"); ok {
		results.NotFound = int(val)
	}
	if val, ok := resultAd.EvaluateAttrInt("result_total_3"); ok {
		results.BadStatus = int(val)
	}
	if val, ok := resultAd.EvaluateAttrInt("result_total_4"); ok {
		results.AlreadyDone = int(val)
	}
	if val, ok := resultAd.EvaluateAttrInt("result_total_5"); ok {
		results.PermissionDenied = int(val)
	}

	// Calculate total jobs acted on
	results.TotalJobs = results.Error + results.Success + results.NotFound +
		results.BadStatus + results.AlreadyDone + results.PermissionDenied

	// Also check for TotalJobAds attribute which gives total jobs considered
	if val, ok := resultAd.EvaluateAttrInt("TotalJobAds"); ok {
		// Use this as the total if it's available and larger
		if int(val) > results.TotalJobs {
			results.TotalJobs = int(val)
		}
	}

	return results
}
