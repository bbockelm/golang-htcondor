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
// Deprecated: Use QueryWithOptions for pagination and default limits/projections
func (s *Schedd) Query(ctx context.Context, constraint string, projection []string) ([]*classad.ClassAd, error) {
	return s.queryWithAuth(ctx, constraint, projection, false, nil)
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

	// Get effective projection
	projection := effectiveOpts.GetEffectiveProjection(DefaultJobProjection())

	// Query with the effective options
	jobAds, err := s.queryWithAuth(ctx, constraint, projection, false, &effectiveOpts)
	if err != nil {
		return nil, nil, err
	}

	// Build pagination info
	pageInfo := &PageInfo{
		TotalReturned:  len(jobAds),
		HasMoreResults: false,
		NextPageToken:  "",
	}

	// If we got exactly the limit, there might be more results
	// In a real implementation, we'd need the schedd to tell us if there are more
	// For now, we'll assume no pagination beyond the limit
	if !effectiveOpts.IsUnlimited() && len(jobAds) >= effectiveOpts.Limit {
		// There might be more results, but we can't know for sure without schedd support
		// Leave HasMoreResults as false for now
	}

	return jobAds, pageInfo, nil
}

// queryWithAuth performs the actual query with optional authentication and query options
func (s *Schedd) queryWithAuth(ctx context.Context, constraint string, projection []string, useAuth bool, opts *QueryOptions) ([]*classad.ClassAd, error) {
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

	// Establish connection using cedar client
	htcondorClient, err := client.ConnectToAddress(ctx, s.address)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to schedd at %s: %w", s.address, err)
	}
	defer func() {
		if cerr := htcondorClient.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("failed to close connection: %w", cerr)
		}
	}()

	// Get CEDAR stream from client
	cedarStream := htcondorClient.GetStream()

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

	auth := security.NewAuthenticator(secConfig, cedarStream)
	negotiation, err := auth.ClientHandshake(ctx)
	if err != nil {
		return nil, fmt.Errorf("security handshake failed: %w", err)
	}

	// If username not already set in context, use the authenticated user from handshake
	if username == "" && negotiation.User != "" {
		// Update context with authenticated user for potential future use
		// Note: This doesn't affect rate limiting for this call since we already checked it
		ctx = WithAuthenticatedUser(ctx, negotiation.User)
	}

	// Create query request ClassAd
	requestAd := createJobQueryAd(constraint, projection)

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

// createJobQueryAd creates a request ClassAd for querying jobs
func createJobQueryAd(constraint string, projection []string) *classad.ClassAd {
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

	// Set projection (newline-separated list of attributes)
	if len(projection) > 0 {
		projectionStr := strings.Join(projection, " ")
		_ = ad.Set("Projection", projectionStr)
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

	// For remote submission, configure job attributes similar to HTCondor's behavior
	// This mimics what condor_submit does when using the -name option (remote submission)
	for _, procAd := range submitResult.ProcAds {
		// Set ShouldTransferFiles to YES if not already set
		if expr, ok := procAd.Lookup("ShouldTransferFiles"); !ok || expr == nil {
			_ = procAd.Set("ShouldTransferFiles", "YES")
		}

		// Ensure WhenToTransferOutput is set
		if expr, ok := procAd.Lookup("WhenToTransferOutput"); !ok || expr == nil {
			_ = procAd.Set("WhenToTransferOutput", "ON_EXIT")
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

	return clusterIDInt, resultProcAds, nil
}

// Edit modifies job attributes
func (s *Schedd) Edit(_ context.Context, _ string, _ string, _ string) error {
	// TODO: Implement job edit using cedar protocol
	return fmt.Errorf("not implemented")
}
