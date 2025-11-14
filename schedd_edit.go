package htcondor

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/PelicanPlatform/classad/classad"
)

// Common immutable attributes that cannot be changed after job submission
// Based on HTCondor's SYSTEM_IMMUTABLE_JOB_ATTRS configuration
var defaultImmutableAttrs = map[string]bool{
	"ClusterId":            true,
	"ProcId":               true,
	"Owner":                true,
	"User":                 true,
	"QDate":                true,
	"CompletionDate":       true,
	"JobStartDate":         true,
	"JobCurrentStartDate":  true,
	"EnteredCurrentStatus": true,
	"GlobalJobId":          true,
	"Submitter":            true,
}

// Common protected attributes that can only be changed by queue superusers
// Based on HTCondor's PROTECTED_JOB_ATTRS configuration
var defaultProtectedAttrs = map[string]bool{
	"AccountingGroup":       true,
	"AcctGroup":             true,
	"AcctGroupUser":         true,
	"NiceUser":              true,
	"ConcurrencyLimits":     true,
	"JobPrio":               true,
	"PostJobPrio1":          true,
	"PostJobPrio2":          true,
	"JobStatus":             true,
	"HoldReason":            true,
	"HoldReasonCode":        true,
	"HoldReasonSubCode":     true,
	"LastHoldReason":        true,
	"LastHoldReasonCode":    true,
	"LastHoldReasonSubCode": true,
	"ReleaseReason":         true,
	"RemoveReason":          true,
	"NumJobStarts":          true,
	"NumShadowStarts":       true,
}

// EditJobOptions contains options for editing jobs
type EditJobOptions struct {
	// AllowProtectedAttrs allows editing of protected attributes (requires superuser privileges)
	AllowProtectedAttrs bool

	// Force allows editing even if some validations fail (use with caution)
	Force bool
}

// ValidateAttributeForEdit checks if an attribute can be edited
// Returns an error if the attribute is immutable or protected (when not allowed)
func ValidateAttributeForEdit(attrName string, opts *EditJobOptions) error {
	if opts == nil {
		opts = &EditJobOptions{}
	}

	// Check if attribute is immutable
	if defaultImmutableAttrs[attrName] {
		return fmt.Errorf("attribute %s is immutable and cannot be changed", attrName)
	}

	// Check if attribute is protected and we're not allowing protected changes
	if !opts.AllowProtectedAttrs && defaultProtectedAttrs[attrName] {
		return fmt.Errorf("attribute %s is protected and can only be changed by queue superusers", attrName)
	}

	return nil
}

// EditJob edits attributes of an existing job
// This opens a QMGMT connection, edits the specified attributes, and commits the changes
func (s *Schedd) EditJob(ctx context.Context, clusterID, procID int, attributes map[string]string, opts *EditJobOptions) error {
	if opts == nil {
		opts = &EditJobOptions{}
	}

	// Validate all attributes before making changes
	if !opts.Force {
		for attrName := range attributes {
			if err := ValidateAttributeForEdit(attrName, opts); err != nil {
				return err
			}
		}
	}

	// Open QMGMT connection
	qmgmt, err := NewQmgmtConnection(ctx, s.address)
	if err != nil {
		return fmt.Errorf("failed to open QMGMT connection: %w", err)
	}
	defer func() {
		if err := qmgmt.Close(); err != nil {
			log.Printf("Failed to close QMGMT connection: %v", err)
		}
	}()

	// Begin transaction
	if err := qmgmt.BeginTransaction(ctx); err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	// Set attributes
	for attrName, attrValue := range attributes {
		if err := qmgmt.SetAttribute(ctx, clusterID, procID, attrName, attrValue, 0); err != nil {
			// Try to abort transaction on error
			_ = qmgmt.AbortTransaction(ctx)
			return fmt.Errorf("failed to set attribute %s: %w", attrName, err)
		}
	}

	// Commit transaction
	if err := qmgmt.CommitTransaction(ctx); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// EditJobByID is a convenience method that parses a job ID string (e.g., "123.0")
// and calls EditJob
func (s *Schedd) EditJobByID(ctx context.Context, jobID string, attributes map[string]string, opts *EditJobOptions) error {
	parts := strings.Split(jobID, ".")
	if len(parts) != 2 {
		return fmt.Errorf("invalid job ID format: %s (expected cluster.proc)", jobID)
	}

	var clusterID, procID int
	if _, err := fmt.Sscanf(parts[0], "%d", &clusterID); err != nil {
		return fmt.Errorf("invalid cluster ID: %s", parts[0])
	}
	if _, err := fmt.Sscanf(parts[1], "%d", &procID); err != nil {
		return fmt.Errorf("invalid proc ID: %s", parts[1])
	}

	return s.EditJob(ctx, clusterID, procID, attributes, opts)
}

// EditJobs edits attributes for multiple jobs matching a constraint
// This is more efficient than calling EditJob multiple times as it uses a single transaction
func (s *Schedd) EditJobs(ctx context.Context, constraint string, attributes map[string]string, opts *EditJobOptions) (int, error) {
	if opts == nil {
		opts = &EditJobOptions{}
	}

	// Validate all attributes before making changes
	if !opts.Force {
		for attrName := range attributes {
			if err := ValidateAttributeForEdit(attrName, opts); err != nil {
				return 0, err
			}
		}
	}

	// Query jobs matching the constraint to get their IDs
	projection := []string{"ClusterId", "ProcId"}
	ads, err := s.Query(ctx, constraint, projection)
	if err != nil {
		return 0, fmt.Errorf("failed to query jobs: %w", err)
	}

	if len(ads) == 0 {
		return 0, nil
	}

	// Open QMGMT connection
	qmgmt, err := NewQmgmtConnection(ctx, s.address)
	if err != nil {
		return 0, fmt.Errorf("failed to open QMGMT connection: %w", err)
	}
	defer func() {
		if err := qmgmt.Close(); err != nil {
			log.Printf("Failed to close QMGMT connection: %v", err)
		}
	}()

	// Begin transaction
	if err := qmgmt.BeginTransaction(ctx); err != nil {
		return 0, fmt.Errorf("failed to begin transaction: %w", err)
	}

	// Edit each job
	jobsEdited := 0
	for _, ad := range ads {
		// Use EvaluateAttrInt to get attribute values
		clusterInt, ok := ad.EvaluateAttrInt("ClusterId")
		if !ok {
			_ = qmgmt.AbortTransaction(ctx)
			return jobsEdited, fmt.Errorf("failed to get ClusterId from job ad")
		}

		procInt, ok := ad.EvaluateAttrInt("ProcId")
		if !ok {
			_ = qmgmt.AbortTransaction(ctx)
			return jobsEdited, fmt.Errorf("failed to get ProcId from job ad")
		}

		// Set attributes for this job
		for attrName, attrValue := range attributes {
			if err := qmgmt.SetAttribute(ctx, int(clusterInt), int(procInt), attrName, attrValue, 0); err != nil {
				_ = qmgmt.AbortTransaction(ctx)
				return jobsEdited, fmt.Errorf("failed to set attribute %s for job %d.%d: %w",
					attrName, clusterInt, procInt, err)
			}
		}
		jobsEdited++
	}

	// Commit transaction
	if err := qmgmt.CommitTransaction(ctx); err != nil {
		return jobsEdited, fmt.Errorf("failed to commit transaction: %w", err)
	}

	return jobsEdited, nil
}

// EditJobAttributes edits attributes using ClassAd values instead of strings
// This is useful when you need to set complex ClassAd expressions or values
func (s *Schedd) EditJobAttributes(ctx context.Context, clusterID, procID int, attributes *classad.ClassAd, opts *EditJobOptions) error {
	if opts == nil {
		opts = &EditJobOptions{}
	}

	// Convert ClassAd to string map for validation and setting
	attrMap := make(map[string]string)
	for _, attrName := range attributes.GetAttributes() {
		// Validate before adding
		if !opts.Force {
			if err := ValidateAttributeForEdit(attrName, opts); err != nil {
				return err
			}
		}

		// Get the value and convert to string representation
		val := attributes.EvaluateAttr(attrName)

		// Convert value to ClassAd string representation
		var valueStr string
		//nolint:gocritic // if-else chain is clearer than switch for type checking
		if val.IsString() {
			str, _ := val.StringValue()
			// Quote string values
			valueStr = fmt.Sprintf("%q", str)
		} else if val.IsInteger() {
			i, _ := val.IntValue()
			valueStr = fmt.Sprintf("%d", i)
		} else if val.IsReal() {
			r, _ := val.RealValue()
			valueStr = fmt.Sprintf("%f", r)
		} else if val.IsBool() {
			b, _ := val.BoolValue()
			valueStr = fmt.Sprintf("%t", b)
		} else {
			// For complex types, convert to string
			valueStr = fmt.Sprintf("%v", val)
		}

		attrMap[attrName] = valueStr
	}

	return s.EditJob(ctx, clusterID, procID, attrMap, opts)
}
