package htcondor

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
