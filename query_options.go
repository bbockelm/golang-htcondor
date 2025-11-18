package htcondor

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
)

// QueryOptions contains options for querying jobs and collector ads
type QueryOptions struct {
	// Limit specifies the maximum number of results to return.
	// Use 0 or negative value for unlimited results (opt-in with "*" in API).
	// Default is 50 if not specified.
	Limit int

	// Projection is a list of attributes to include in results.
	// Use nil or empty slice for default projections.
	// Use []string{"*"} to include all attributes.
	Projection []string

	// PageToken is used for pagination. Empty string for first page.
	// The token identifies where to continue fetching results.
	PageToken string
}

// DefaultJobProjection returns the default list of job attributes to include in query results
func DefaultJobProjection() []string {
	return []string{
		"ClusterId",
		"ProcId",
		"Owner",
		"JobStatus",
		"Cmd",
		"Args",
	}
}

// DefaultCollectorProjection returns the default list of collector ad attributes
func DefaultCollectorProjection() []string {
	return []string{
		"Name",
		"Machine",
		"MyType",
		"State",
		"Activity",
		"MyAddress",
	}
}

// ApplyDefaults applies default values to QueryOptions
func (opts *QueryOptions) ApplyDefaults() QueryOptions {
	result := QueryOptions{
		Limit:      opts.Limit,
		Projection: opts.Projection,
		PageToken:  opts.PageToken,
	}

	// Apply default limit if not set
	if result.Limit == 0 {
		result.Limit = 50
	}

	return result
}

// IsUnlimited returns true if the query should return unlimited results
func (opts *QueryOptions) IsUnlimited() bool {
	return opts.Limit < 0
}

// ShouldUseDefaultProjection returns true if default projection should be used
func (opts *QueryOptions) ShouldUseDefaultProjection() bool {
	return len(opts.Projection) == 0
}

// ShouldUseAllAttributes returns true if all attributes should be returned
func (opts *QueryOptions) ShouldUseAllAttributes() bool {
	return len(opts.Projection) == 1 && opts.Projection[0] == "*"
}

// GetEffectiveProjection returns the projection to use, applying defaults if needed
func (opts *QueryOptions) GetEffectiveProjection(defaultProj []string) []string {
	if opts.ShouldUseAllAttributes() {
		return nil // nil means all attributes
	}
	if opts.ShouldUseDefaultProjection() {
		return defaultProj
	}
	return opts.Projection
}

// PageInfo contains pagination metadata
type PageInfo struct {
	// NextPageToken is the token to use for fetching the next page of results.
	// Empty string if there are no more results.
	NextPageToken string

	// HasMoreResults indicates whether there are more results available
	HasMoreResults bool

	// TotalReturned is the number of results in the current response
	TotalReturned int
}

// EncodePageToken encodes a cluster.proc identifier as a base64 page token
func EncodePageToken(clusterID, procID int64) string {
	jobID := fmt.Sprintf("%d.%d", clusterID, procID)
	return base64.StdEncoding.EncodeToString([]byte(jobID))
}

// DecodePageToken decodes a base64 page token to cluster and proc IDs
// Returns cluster ID, proc ID, and error if decoding fails
func DecodePageToken(token string) (int64, int64, error) {
	if token == "" {
		return 0, 0, fmt.Errorf("empty page token")
	}

	decoded, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid page token: %w", err)
	}

	jobID := string(decoded)
	parts := strings.Split(jobID, ".")
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("invalid job ID format in page token: %s", jobID)
	}

	clusterID, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid cluster ID in page token: %w", err)
	}

	procID, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid proc ID in page token: %w", err)
	}

	return clusterID, procID, nil
}
