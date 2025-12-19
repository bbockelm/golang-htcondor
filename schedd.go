package htcondor

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/client"
	"github.com/bbockelm/cedar/commands"
	"github.com/bbockelm/cedar/message"
	"github.com/bbockelm/cedar/security"
)

// securityConfigContextKey is the type for the security configuration context key
type securityConfigContextKey struct{}

// authenticatedUserContextKey is the type for the authenticated user context key
type authenticatedUserContextKey struct{}

// WithSecurityConfig creates a context that includes security configuration
// This allows passing authentication information (like tokens) from HTTP handlers to Schedd methods
func WithSecurityConfig(ctx context.Context, secConfig *security.SecurityConfig) context.Context {
	return context.WithValue(ctx, securityConfigContextKey{}, secConfig)
}

// GetSecurityConfigFromContext retrieves the security configuration from the context
func GetSecurityConfigFromContext(ctx context.Context) (security.SecurityConfig, bool) {
	secConfig, ok := ctx.Value(securityConfigContextKey{}).(*security.SecurityConfig)
	if !ok || secConfig == nil {
		return security.SecurityConfig{}, false
	}
	return *secConfig, true
}

// WithAuthenticatedUser creates a context that includes the authenticated username
// This is used for rate limiting purposes
func WithAuthenticatedUser(ctx context.Context, username string) context.Context {
	return context.WithValue(ctx, authenticatedUserContextKey{}, username)
}

// GetAuthenticatedUserFromContext retrieves the authenticated username from the context
// Returns empty string if not found, which will be treated as "unauthenticated"
func GetAuthenticatedUserFromContext(ctx context.Context) string {
	username, ok := ctx.Value(authenticatedUserContextKey{}).(string)
	if !ok {
		return ""
	}
	return username
}

// Schedd represents an HTCondor schedd daemon
type Schedd struct {
	name    string
	address string
}

// NewSchedd creates a new Schedd instance
// address can be a hostname:port or a sinful string like "<IP:PORT?addrs=...>"
func NewSchedd(name string, address string) *Schedd {
	return &Schedd{
		name:    name,
		address: address,
	}
}

// Name returns the schedd's name
func (s *Schedd) Name() string {
	return s.name
}

// Address returns the schedd's address
func (s *Schedd) Address() string {
	return s.address
}

// Query queries the schedd for job advertisements
// constraint is a ClassAd constraint expression (use "true" to get all jobs)
// projection is a list of attributes to return (use nil to get all attributes)
//
// Deprecated: Use QueryWithOptions for pagination and default limits/projections
func (s *Schedd) Query(ctx context.Context, constraint string, projection []string) ([]*classad.ClassAd, error) {
	// Build opts with projection
	opts := &QueryOptions{
		Projection: projection,
	}
	return s.queryWithAuth(ctx, constraint, false, opts)
}

// QueryWithOptions queries the schedd for job advertisements with pagination and limits
// opts specifies query options including limit, projection, and pagination
// Returns the matching job ads and pagination info
func (s *Schedd) QueryWithOptions(ctx context.Context, constraint string, opts *QueryOptions) ([]*classad.ClassAd, *PageInfo, error) {
	// Apply defaults if opts is nil
	if opts == nil {
		opts = &QueryOptions{}
	}
	effectiveOpts := opts.ApplyDefaults()

	// If a page token is provided, modify the constraint to skip earlier jobs
	effectiveConstraint := constraint
	if effectiveOpts.PageToken != "" {
		clusterID, procID, err := DecodePageToken(effectiveOpts.PageToken)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid page token: %w", err)
		}

		// Add constraint to select jobs after the page token
		// Jobs come in ClusterId.ProcId order, so we want:
		// (ClusterId > pageClusterId) OR (ClusterId == pageClusterId AND ProcId > pageProcId)
		pageConstraint := fmt.Sprintf("(ClusterId > %d || (ClusterId == %d && ProcId > %d))",
			clusterID, clusterID, procID)

		if constraint == "" || constraint == "true" {
			effectiveConstraint = pageConstraint
		} else {
			effectiveConstraint = fmt.Sprintf("(%s) && (%s)", constraint, pageConstraint)
		}
	}

	// Query with the effective options
	jobAds, err := s.queryWithAuth(ctx, effectiveConstraint, false, &effectiveOpts)
	if err != nil {
		return nil, nil, err
	}

	// Build pagination info
	pageInfo := &PageInfo{
		TotalReturned:  len(jobAds),
		HasMoreResults: false,
		NextPageToken:  "",
	}

	// If we got the limit or more results, there might be more available
	if !effectiveOpts.IsUnlimited() && len(jobAds) >= effectiveOpts.Limit {
		// Generate page token from the last job's ClusterId and ProcId
		if len(jobAds) > 0 {
			lastJob := jobAds[len(jobAds)-1]
			if clusterID, ok := lastJob.EvaluateAttrInt("ClusterId"); ok {
				if procID, ok := lastJob.EvaluateAttrInt("ProcId"); ok {
					pageInfo.NextPageToken = EncodePageToken(clusterID, procID)
					pageInfo.HasMoreResults = true
				}
			}
		}
	}

	return jobAds, pageInfo, nil
}

// JobAdResult represents a single job ad or error from a streaming query
type JobAdResult struct {
	Ad  *classad.ClassAd
	Err error
}

// QueryStream queries the schedd and streams job ads through a channel
// Returns a channel and an error. If the error is non-nil, it indicates a problem
// before the request was sent (e.g., invalid parameters, connection failure).
// The channel will be closed when all ads have been sent or an error occurs during streaming.
// If cumulative time blocking on channel writes exceeds StreamOptions.WriteTimeout, an error is sent through the channel.
//
// Deprecated: Use QueryStreamWithOptions for pagination and limit support
func (s *Schedd) QueryStream(ctx context.Context, constraint string, projection []string, streamOpts *StreamOptions) (<-chan JobAdResult, error) {
	return s.QueryStreamWithOptions(ctx, constraint, &QueryOptions{Projection: projection}, streamOpts)
}

// QueryStreamWithOptions queries the schedd with QueryOptions and streams job ads through a channel
// Returns a channel and an error. If the error is non-nil, it indicates a problem
// before the request was sent (e.g., invalid parameters, rate limit exceeded).
// This method supports server-side limits for better performance
func (s *Schedd) QueryStreamWithOptions(ctx context.Context, constraint string, opts *QueryOptions, streamOpts *StreamOptions) (<-chan JobAdResult, error) {
	// Apply stream defaults
	streamOptsApplied := streamOpts.ApplyStreamDefaults()

	// Apply rate limiting if configured
	username := GetAuthenticatedUserFromContext(ctx)
	rateLimitManager := getRateLimitManager()
	if rateLimitManager != nil {
		rateLimitCtx, cancelRateLimit := context.WithTimeout(ctx, 1000*time.Millisecond)
		defer cancelRateLimit()
		if err := rateLimitManager.WaitSchedd(rateLimitCtx, username); err != nil {
			return nil, fmt.Errorf("rate limit exceeded: %w", err)
		}
	}

	// Apply defaults to opts if needed
	effectiveOpts := &QueryOptions{}
	if opts != nil {
		effectiveOpts = opts
	}
	effectiveOptsValue := effectiveOpts.ApplyDefaults()
	effectiveOpts = &effectiveOptsValue

	// Create channel for results
	ch := make(chan JobAdResult, streamOptsApplied.BufferSize)

	go func() {
		defer close(ch)

		// Determine command
		cmd := commands.QUERY_JOB_ADS

		// Get security config
		secConfig, err := GetSecurityConfigOrDefault(ctx, nil, cmd, "CLIENT", s.address)
		if err != nil {
			ch <- JobAdResult{Err: fmt.Errorf("failed to create security config: %w", err)}
			return
		}

		// Establish connection and authenticate
		htcondorClient, err := client.ConnectAndAuthenticate(ctx, s.address, secConfig)
		if err != nil {
			ch <- JobAdResult{Err: fmt.Errorf("failed to connect and authenticate to schedd at %s: %w", s.address, err)}
			return
		}
		defer func() { _ = htcondorClient.Close() }()

		// Get CEDAR stream
		cedarStream := htcondorClient.GetStream()

		// Get security negotiation details to extract authenticated user
		negotiation := htcondorClient.GetSecurityNegotiation()

		// Update context with authenticated user if needed
		if username == "" && negotiation != nil && negotiation.User != "" {
			ctx = WithAuthenticatedUser(ctx, negotiation.User)
		}

		// Create query request ClassAd with options
		requestAd := createJobQueryAd(constraint, effectiveOpts)

		// Send query
		queryMsg := message.NewMessageForStream(cedarStream)
		if err := queryMsg.PutClassAd(ctx, requestAd); err != nil {
			ch <- JobAdResult{Err: fmt.Errorf("failed to serialize query ClassAd: %w", err)}
			return
		}
		if err := queryMsg.FinishMessage(ctx); err != nil {
			ch <- JobAdResult{Err: fmt.Errorf("failed to send query: %w", err)}
			return
		}

		// Stream response ads
		totalBlockTime := time.Duration(0)

		// Create timer that wakes up periodically to check timeout
		checkInterval := 100 * time.Millisecond
		timer := time.NewTimer(checkInterval)
		defer timer.Stop()

		for {
			// Create a new message for each response ClassAd
			responseMsg := message.NewMessageFromStream(cedarStream)

			// Read ClassAd
			ad, err := responseMsg.GetClassAd(ctx)
			if err != nil {
				ch <- JobAdResult{Err: fmt.Errorf("failed to read ClassAd: %w", err)}
				return
			}

			// Check if this is the final ad (Owner == 0)
			if ownerVal, ok := ad.EvaluateAttrInt("Owner"); ok && ownerVal == 0 {
				// This is the final ad - check for errors
				if errCode, ok := ad.EvaluateAttrInt("ErrorCode"); ok && errCode != 0 {
					errMsg := "unknown error"
					if errStr, ok := ad.EvaluateAttrString("ErrorString"); ok {
						errMsg = errStr
					}
					ch <- JobAdResult{Err: fmt.Errorf("schedd query error %d: %s", errCode, errMsg)}
				}
				// Success - final ad received
				return
			}

			// Send job ad to channel with timeout tracking using a timer
			// Calculate how much time we have left
			timeLeft := streamOptsApplied.WriteTimeout - totalBlockTime
			if timeLeft < checkInterval {
				checkInterval = timeLeft
			}
			if checkInterval <= 0 {
				ch <- JobAdResult{Err: fmt.Errorf("write timeout exceeded: blocked for %v (limit: %v)", totalBlockTime, streamOptsApplied.WriteTimeout)}
				return
			}
			timer.Reset(checkInterval)

			startWrite := time.Now()
			for {
				select {
				case ch <- JobAdResult{Ad: ad}:
					blockTime := time.Since(startWrite)
					totalBlockTime += blockTime
					goto nextAd
				case <-timer.C:
					// Timer expired - check if we've exceeded total timeout
					blockTime := time.Since(startWrite)
					totalBlockTime += blockTime
					if totalBlockTime >= streamOptsApplied.WriteTimeout {
						ch <- JobAdResult{Err: fmt.Errorf("write timeout exceeded: blocked for %v (limit: %v)", totalBlockTime, streamOptsApplied.WriteTimeout)}
						return
					}
					// Continue retrying in the loop
					timer.Reset(checkInterval)
				case <-ctx.Done():
					ch <- JobAdResult{Err: ctx.Err()}
					return
				}
			}
		nextAd:
		}
	}()

	return ch, nil
}

// queryWithAuth performs the actual query with optional authentication and query options
func (s *Schedd) queryWithAuth(ctx context.Context, constraint string, useAuth bool, opts *QueryOptions) ([]*classad.ClassAd, error) {
	// Apply rate limiting if configured
	// Use a short timeout context for rate limiting to avoid blocking HTTP requests
	// If rate limit is exceeded, we want to return 429 immediately, not block
	username := GetAuthenticatedUserFromContext(ctx)
	rateLimitManager := getRateLimitManager()
	if rateLimitManager != nil {
		rateLimitCtx, cancelRateLimit := context.WithTimeout(ctx, 1000*time.Millisecond)
		defer cancelRateLimit()
		if err := rateLimitManager.WaitSchedd(rateLimitCtx, username); err != nil {
			return nil, fmt.Errorf("rate limit exceeded: %w", err)
		}
	}

	// Determine command
	cmd := commands.QUERY_JOB_ADS
	if useAuth {
		cmd = commands.QUERY_JOB_ADS_WITH_AUTH
	}

	// Get SecurityConfig from context, HTCondor config, or defaults
	secConfig, err := GetSecurityConfigOrDefault(ctx, nil, cmd, "CLIENT", s.address)
	if err != nil {
		return nil, fmt.Errorf("failed to create security config: %w", err)
	}

	// Establish connection and authenticate using cedar client
	// This handles session resumption failures automatically
	htcondorClient, err := client.ConnectAndAuthenticate(ctx, s.address, secConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to connect and authenticate to schedd at %s: %w", s.address, err)
	}
	defer func() {
		if cerr := htcondorClient.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("failed to close connection: %w", cerr)
		}
	}()

	// Get CEDAR stream from client
	cedarStream := htcondorClient.GetStream()

	// Note: ConnectAndAuthenticate doesn't expose negotiation details, so we can't get
	// the authenticated user here. Username should be provided in the context if needed.

	// Create query request ClassAd with options
	requestAd := createJobQueryAd(constraint, opts)

	// Send query
	queryMsg := message.NewMessageForStream(cedarStream)
	err = queryMsg.PutClassAd(ctx, requestAd)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize query ClassAd: %w", err)
	}

	err = queryMsg.FinishMessage(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to send query: %w", err)
	}

	// Receive response ads
	var jobAds []*classad.ClassAd

	// Determine the limit to apply
	limit := -1 // unlimited by default
	if opts != nil && !opts.IsUnlimited() {
		limit = opts.Limit
	}

	for {
		// Check for context cancellation
		select {
		case <-ctx.Done():
			return jobAds, ctx.Err()
		default:
		}

		// Check if we've reached the limit
		if limit > 0 && len(jobAds) >= limit {
			break
		}

		// Create a new message for each response ClassAd
		responseMsg := message.NewMessageFromStream(cedarStream)

		// Read ClassAd
		ad, err := responseMsg.GetClassAd(ctx)
		if err != nil {
			return jobAds, fmt.Errorf("failed to read ClassAd: %w", err)
		}

		// Check if this is the final ad (Owner == 0)
		if ownerVal, ok := ad.EvaluateAttrInt("Owner"); ok && ownerVal == 0 {
			// This is the final ad - check for errors
			if errCode, ok := ad.EvaluateAttrInt("ErrorCode"); ok && errCode != 0 {
				errMsg := "unknown error"
				if errStr, ok := ad.EvaluateAttrString("ErrorString"); ok {
					errMsg = errStr
				}
				return jobAds, fmt.Errorf("schedd query error %d: %s", errCode, errMsg)
			}
			// Success - final ad received (may contain summary information)
			break
		}

		// This is a job ad - append to results
		jobAds = append(jobAds, ad)
	}

	return jobAds, nil
}

// createJobQueryAd creates a request ClassAd for querying jobs with options
func createJobQueryAd(constraint string, opts *QueryOptions) *classad.ClassAd {
	ad := classad.New()

	// Set constraint (use "true" if empty)
	if constraint == "" {
		constraint = "true"
	}
	// Parse constraint as an expression
	constraintExpr, err := classad.ParseExpr(constraint)
	if err != nil {
		// If parsing fails, use a simple "true" expression
		constraintExpr, _ = classad.ParseExpr("true")
	}
	ad.InsertExpr("Requirements", constraintExpr)

	// Set projection if provided
	if opts != nil && len(opts.Projection) > 0 {
		projectionStr := strings.Join(opts.Projection, ",")
		_ = ad.Set("Projection", projectionStr)
	}

	// Set LimitResults for server-side limit enforcement
	if opts != nil && opts.Limit > 0 {
		_ = ad.Set("LimitResults", int64(opts.Limit))
	}

	// Handle fetch options
	if opts != nil && opts.FetchOpts != FetchNormal {
		// FetchMyJobs: Filter to jobs owned by user
		if opts.FetchOpts&FetchMyJobs != 0 {
			if opts.Owner != "" {
				_ = ad.Set("Me", opts.Owner)
			}
			// MyJobs constraint filters to Owner == Me (or true if no Me attribute)
			myJobsConstraint := "true"
			if opts.Owner != "" {
				myJobsConstraint = "(Owner == Me)"
			}
			myJobsExpr, err := classad.ParseExpr(myJobsConstraint)
			if err == nil {
				_ = ad.Set("MyJobs", myJobsExpr)
			}
		}

		// FetchSummaryOnly: Return summary instead of individual ads
		if opts.FetchOpts&FetchSummaryOnly != 0 {
			_ = ad.Set("SummaryOnly", true)
		}

		// FetchIncludeClusterAd: Include cluster ads in results
		if opts.FetchOpts&FetchIncludeClusterAd != 0 {
			_ = ad.Set("IncludeClusterAd", true)
		}

		// FetchIncludeJobsetAds: Include jobset ads in results
		if opts.FetchOpts&FetchIncludeJobsetAds != 0 {
			_ = ad.Set("IncludeJobsetAds", true)
		}

		// FetchNoProcAds: Exclude proc ads, only cluster/jobset
		if opts.FetchOpts&FetchNoProcAds != 0 {
			_ = ad.Set("NoProcAds", true)
		}
	}

	return ad
}

// Submit submits a job to the schedd using an HTCondor submit file
// submitFileContent is the content of an HTCondor submit file
// Returns the cluster ID as a string
func (s *Schedd) Submit(ctx context.Context, submitFileContent string) (string, error) {
	// Parse the submit file
	submitFile, err := ParseSubmitFile(strings.NewReader(submitFileContent))
	if err != nil {
		return "", fmt.Errorf("failed to parse submit file: %w", err)
	}

	// Create QMGMT connection
	qmgmt, err := NewQmgmtConnection(ctx, s.address)
	if err != nil {
		return "", fmt.Errorf("failed to connect to schedd at %s: %w", s.address, err)
	}
	defer func() {
		if cerr := qmgmt.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("failed to close connection: %w", cerr)
		}
	}()

	// Set up error handling to abort transaction on failure
	var submissionErr error
	defer func() {
		if submissionErr != nil {
			_ = qmgmt.AbortTransaction(ctx)
		}
	}()

	// Get authenticated user from the QMGMT connection
	owner := qmgmt.authenticatedUser
	if owner == "" {
		submissionErr = fmt.Errorf("no authenticated user")
		return "", submissionErr
	}

	// Set effective owner
	if err := qmgmt.SetEffectiveOwner(ctx, owner); err != nil {
		submissionErr = fmt.Errorf("failed to set effective owner: %w", err)
		return "", submissionErr
	}

	// Create new cluster
	clusterID, err := qmgmt.NewCluster(ctx)
	if err != nil {
		submissionErr = fmt.Errorf("failed to create cluster: %w", err)
		return "", submissionErr
	}

	// Generate job ads from the submit file
	submitResult, err := submitFile.Submit(clusterID)
	if err != nil {
		submissionErr = fmt.Errorf("failed to generate job ads: %w", err)
		return "", submissionErr
	}

	// Submit each proc
	for i, procAd := range submitResult.ProcAds {
		procID, err := qmgmt.NewProc(ctx, clusterID)
		if err != nil {
			submissionErr = fmt.Errorf("failed to create proc %d: %w", i, err)
			return "", submissionErr
		}

		// Send job attributes
		if err := qmgmt.SendJobAttributes(ctx, clusterID, procID, procAd); err != nil {
			submissionErr = fmt.Errorf("failed to set attributes for proc %d: %w", i, err)
			return "", submissionErr
		}
	}

	// Commit transaction
	if err := qmgmt.CommitTransaction(ctx); err != nil {
		submissionErr = fmt.Errorf("failed to commit transaction: %w", err)
		return "", submissionErr
	}

	return fmt.Sprintf("%d", clusterID), nil
}

// SubmitRemote submits jobs to the schedd with remote submission semantics.
// This method is designed for remote job submission with file spooling support.
//
// Remote submission behavior:
// 1. Parses the submit file
// 2. Ensures ShouldTransferFiles is set to YES
// 3. Jobs start in HELD status with SpoolingInput hold reason (code 16)
// 4. Sets LeaveJobInQueue to keep completed jobs for 10 days for output retrieval
// 5. Submits the job to the schedd
// 6. Returns the cluster ID and proc ads for subsequent file spooling
//
// The caller should then use SpoolJobFilesFromFS or SpoolJobFilesFromTar to upload input files.
func (s *Schedd) SubmitRemote(ctx context.Context, submitFileContent string) (clusterID int, procAds []*classad.ClassAd, err error) {
	// Parse the submit file
	submitFile, err := ParseSubmitFile(strings.NewReader(submitFileContent))
	if err != nil {
		return 0, nil, fmt.Errorf("failed to parse submit file: %w", err)
	}

	// Connect to schedd's queue management interface
	qmgmt, err := NewQmgmtConnection(ctx, s.address)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to connect to schedd at %s: %w", s.address, err)
	}
	defer func() {
		if cerr := qmgmt.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("failed to close qmgmt connection: %w", cerr)
		}
	}()

	// Set up error handling to abort transaction on failure
	var submissionErr error
	defer func() {
		if submissionErr != nil {
			_ = qmgmt.AbortTransaction(ctx)
		}
	}()

	// Get authenticated user from the QMGMT connection
	owner := qmgmt.authenticatedUser
	if owner == "" {
		submissionErr = fmt.Errorf("no authenticated user")
		return 0, nil, submissionErr
	}

	// Set effective owner
	if err := qmgmt.SetEffectiveOwner(ctx, owner); err != nil {
		submissionErr = fmt.Errorf("failed to set effective owner: %w", err)
		return 0, nil, submissionErr
	}

	// Create new cluster
	clusterIDInt, err := qmgmt.NewCluster(ctx)
	if err != nil {
		submissionErr = fmt.Errorf("failed to create cluster: %w", err)
		return 0, nil, submissionErr
	}

	// Generate job ads from the submit file
	submitResult, err := submitFile.Submit(clusterIDInt)
	if err != nil {
		submissionErr = fmt.Errorf("failed to generate job ads: %w", err)
		return 0, nil, submissionErr
	}

	var jobsWithoutSpooling []*classad.ClassAd

	// For remote submission, configure job attributes similar to HTCondor's behavior
	// This mimics what condor_submit does when using the -name option (remote submission)
	for _, procAd := range submitResult.ProcAds {
		needsSpooling := configureRemoteJobAd(procAd)
		if !needsSpooling {
			jobsWithoutSpooling = append(jobsWithoutSpooling, procAd)
		}
	}

	// Submit each proc
	resultProcAds := make([]*classad.ClassAd, len(submitResult.ProcAds))
	for i, procAd := range submitResult.ProcAds {
		procID, err := qmgmt.NewProc(ctx, clusterIDInt)
		if err != nil {
			submissionErr = fmt.Errorf("failed to create proc %d: %w", i, err)
			return 0, nil, submissionErr
		}

		// Set ClusterId and ProcId in the ad for later use with file spooling
		_ = procAd.Set("ClusterId", int64(clusterIDInt))
		_ = procAd.Set("ProcId", int64(procID))

		// Send job attributes
		if err := qmgmt.SendJobAttributes(ctx, clusterIDInt, procID, procAd); err != nil {
			submissionErr = fmt.Errorf("failed to set attributes for proc %d: %w", i, err)
			return 0, nil, submissionErr
		}

		// Store the proc ad with ClusterId and ProcId set
		resultProcAds[i] = procAd
	}

	// Commit transaction
	if err := qmgmt.CommitTransaction(ctx); err != nil {
		submissionErr = fmt.Errorf("failed to commit transaction: %w", err)
		return 0, nil, submissionErr
	}

	// Close qmgmt connection to free up resources before spooling
	// This is important because SpoolJobFilesFromTar creates a new connection
	// and we want to avoid holding multiple connections/sessions open if possible.
	_ = qmgmt.Close()
	qmgmt = nil // Prevent double close in defer

	// If we don't need input spooling, release the hold immediately.
	// Note: the hold + release triggers schedd logic that sets the Iwd to
	// be the spool directory. Without that, the shadow doesn't know where
	// to place output files and will fail to start.
	if len(jobsWithoutSpooling) > 0 {
		if err := s.releaseJobsWithEmptySpool(ctx, jobsWithoutSpooling); err != nil {
			return clusterIDInt, resultProcAds, fmt.Errorf("failed to release jobs without input files: %w", err)
		}
	}

	return clusterIDInt, resultProcAds, nil
}

// configureRemoteJobAd sets up job attributes for remote submission and determines if spooling is needed.
func configureRemoteJobAd(procAd *classad.ClassAd) bool {
	// Set ShouldTransferFiles to YES if not already set
	if expr, ok := procAd.Lookup("ShouldTransferFiles"); !ok || expr == nil {
		_ = procAd.Set("ShouldTransferFiles", "YES")
	}

	// Ensure WhenToTransferOutput is set
	if expr, ok := procAd.Lookup("WhenToTransferOutput"); !ok || expr == nil {
		_ = procAd.Set("WhenToTransferOutput", "ON_EXIT")
	}

	// Check if we need to spool input files
	needsSpooling := false

	// Check TransferExecutable (default is true)
	transferExe := true
	if val, ok := procAd.EvaluateAttrBool("TransferExecutable"); ok {
		transferExe = val
	}
	if transferExe {
		needsSpooling = true
	}

	// Check Input (stdin)
	if !needsSpooling {
		if val, ok := procAd.EvaluateAttrString("Input"); ok && val != "" {
			needsSpooling = true
		}
	}

	// Check TransferInput
	if !needsSpooling {
		if val, ok := procAd.EvaluateAttrString("TransferInput"); ok && val != "" {
			needsSpooling = true
		}
	}

	// Remote jobs start in HELD status with SpoolingInput hold reason
	// JobStatus: 5 = HELD
	_ = procAd.Set("JobStatus", int64(5))
	// HoldReasonCode: 16 = SpoolingInput
	_ = procAd.Set("HoldReasonCode", int64(16))
	_ = procAd.Set("HoldReason", "Spooling input data files")

	// Set LeaveJobInQueue expression for remote jobs
	// Keep job in queue for 10 days after completion to allow output retrieval
	if expr, ok := procAd.Lookup("LeaveJobInQueue"); !ok || expr == nil {
		leaveInQueueExpr, _ := classad.ParseExpr("JobStatus == 4 && (CompletionDate =?= UNDEFINED || CompletionDate == 0 || ((time() - CompletionDate) < 864000))")
		_ = procAd.Set("LeaveJobInQueue", leaveInQueueExpr)
	}

	return needsSpooling
}
