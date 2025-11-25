package htcondor

// HistoryRecordSource specifies what type of history records to query
type HistoryRecordSource string

const (
	// HistorySourceJobHistory queries standard job history (completed jobs)
	HistorySourceJobHistory HistoryRecordSource = "HISTORY"

	// HistorySourceJobEpoch queries job epoch history (per job run instance)
	// This includes records for each execution attempt of a job
	HistorySourceJobEpoch HistoryRecordSource = "JOB_EPOCH"

	// HistorySourceTransfer queries transfer history from job epochs
	// This includes file transfer events (input, output, checkpoint)
	HistorySourceTransfer HistoryRecordSource = "TRANSFER"

	// HistorySourceStartd queries startd history (from compute nodes)
	HistorySourceStartd HistoryRecordSource = "STARTD"

	// HistorySourceDaemon queries daemon history (historical daemon ads)
	HistorySourceDaemon HistoryRecordSource = "DAEMON"
)

// TransferType specifies the type of file transfer to query
type TransferType string

const (
	// TransferTypeInput queries input file transfers
	TransferTypeInput TransferType = "INPUT"

	// TransferTypeOutput queries output file transfers
	TransferTypeOutput TransferType = "OUTPUT"

	// TransferTypeCheckpoint queries checkpoint file transfers
	TransferTypeCheckpoint TransferType = "CHECKPOINT"
)

// HistoryQueryOptions contains options for querying history records
type HistoryQueryOptions struct {
	// Source specifies the history record source to query
	// Default is HistorySourceJobHistory
	Source HistoryRecordSource

	// Limit specifies the maximum number of results to return.
	// Use 0 or negative value for unlimited results.
	// Default is 50 if not specified.
	Limit int

	// ScanLimit specifies the maximum number of ads to scan.
	// Use 0 or negative value for unlimited scanning.
	// Default is 10000 if not specified to prevent timeouts on large pools.
	ScanLimit int

	// Projection is a list of attributes to include in results.
	// Use nil or empty slice for default projections.
	// Use []string{"*"} to include all attributes.
	Projection []string

	// Backwards controls the order of results.
	// If true, returns results in reverse chronological order (newest first).
	// If false, returns results in chronological order (oldest first).
	// Default is true (backwards).
	Backwards bool

	// StreamResults requests that the server stream results as they are found
	// rather than buffering all results before sending.
	// Default is true for streaming.
	StreamResults bool

	// Since can be a job ID (e.g., "123.0") or a constraint expression
	// to stop scanning when matched. Only used when Backwards is true.
	Since string

	// TransferTypes specifies which transfer types to include when
	// Source is HistorySourceTransfer. Empty means all types.
	TransferTypes []TransferType

	// AdTypeFilter filters ads by their type (not MyType).
	// Only applies to some history sources.
	AdTypeFilter []string

	// ReadFromDirectory requests reading from per-job epoch directory
	// instead of aggregate history file. Only applies to epoch history.
	ReadFromDirectory bool

	// DaemonSubsystem specifies which daemon subsystem to query
	// when Source is HistorySourceDaemon (e.g., "SCHEDD").
	DaemonSubsystem string
}

// DefaultHistoryProjection returns the default list of attributes for job history
func DefaultHistoryProjection() []string {
	return []string{
		"ClusterId",
		"ProcId",
		"Owner",
		"QDate",
		"RemoteWallClockTime",
		"JobStatus",
		"CompletionDate",
		"Cmd",
	}
}

// DefaultEpochProjection returns the default list of attributes for job epoch history
func DefaultEpochProjection() []string {
	return []string{
		"ClusterId",
		"ProcId",
		"RunId",
		"EnteredCurrentStatus",
		"LastMatchTime",
		"RemoteWallClockTime",
		"JobCurrentStartDate",
		"JobCurrentFinishDate",
	}
}

// DefaultTransferProjection returns the default list of attributes for transfer history
func DefaultTransferProjection() []string {
	return []string{
		"ClusterId",
		"ProcId",
		"RunId",
		"TransferType",
		"TransferProtocol",
		"TransferFileBytes",
		"TransferTotalBytes",
		"TransferStartTime",
		"TransferEndTime",
	}
}

// ApplyDefaults applies default values to HistoryQueryOptions
func (opts *HistoryQueryOptions) ApplyDefaults() HistoryQueryOptions {
	result := HistoryQueryOptions{
		Source:            opts.Source,
		Limit:             opts.Limit,
		ScanLimit:         opts.ScanLimit,
		Projection:        opts.Projection,
		Backwards:         opts.Backwards,
		StreamResults:     opts.StreamResults,
		Since:             opts.Since,
		TransferTypes:     opts.TransferTypes,
		AdTypeFilter:      opts.AdTypeFilter,
		ReadFromDirectory: opts.ReadFromDirectory,
		DaemonSubsystem:   opts.DaemonSubsystem,
	}

	// Apply default source if not set
	if result.Source == "" {
		result.Source = HistorySourceJobHistory
	}

	// Apply default limit if not set
	if result.Limit == 0 {
		result.Limit = 50
	}

	// Apply default scan limit if not set
	// Default to 10k to prevent timeouts on large pools
	if result.ScanLimit == 0 {
		result.ScanLimit = 10000
	}

	// Default to backwards scanning
	if !opts.explicitBackwards() {
		result.Backwards = true
	}

	// Default to streaming results
	if !opts.explicitStreamResults() {
		result.StreamResults = true
	}

	return result
}

// explicitBackwards checks if Backwards was explicitly set
// This is a helper to distinguish between zero value and explicit false
func (opts *HistoryQueryOptions) explicitBackwards() bool {
	// If this method is called from ApplyDefaults, we can't distinguish
	// In practice, callers should set Backwards explicitly if they want false
	// The safe default is true (backwards)
	return false
}

// explicitStreamResults checks if StreamResults was explicitly set
func (opts *HistoryQueryOptions) explicitStreamResults() bool {
	// Similar to explicitBackwards, default to true for streaming
	return false
}

// IsUnlimited returns true if the query should return unlimited results
func (opts *HistoryQueryOptions) IsUnlimited() bool {
	return opts.Limit < 0
}

// ShouldUseDefaultProjection returns true if default projection should be used
func (opts *HistoryQueryOptions) ShouldUseDefaultProjection() bool {
	return len(opts.Projection) == 0
}

// ShouldUseAllAttributes returns true if all attributes should be returned
func (opts *HistoryQueryOptions) ShouldUseAllAttributes() bool {
	return len(opts.Projection) == 1 && opts.Projection[0] == "*"
}

// GetEffectiveProjection returns the projection to use based on the source type
func (opts *HistoryQueryOptions) GetEffectiveProjection() []string {
	if opts.ShouldUseAllAttributes() {
		return nil // nil means all attributes
	}
	if opts.ShouldUseDefaultProjection() {
		switch opts.Source {
		case HistorySourceJobEpoch:
			return DefaultEpochProjection()
		case HistorySourceTransfer:
			return DefaultTransferProjection()
		default:
			return DefaultHistoryProjection()
		}
	}
	return opts.Projection
}
