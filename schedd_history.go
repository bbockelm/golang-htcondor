package htcondor

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/client"
	"github.com/bbockelm/cedar/commands"
	"github.com/bbockelm/cedar/message"
)

// QueryHistory queries the schedd for job history records
// constraint is a ClassAd constraint expression (use "true" to get all records)
// projection is a list of attributes to return (use nil to get all attributes)
//
// This method queries standard job history (completed jobs) by default.
// For epoch or transfer history, use QueryHistoryWithOptions.
func (s *Schedd) QueryHistory(ctx context.Context, constraint string, projection []string) ([]*classad.ClassAd, error) {
	opts := &HistoryQueryOptions{
		Source:     HistorySourceJobHistory,
		Projection: projection,
	}
	return s.QueryHistoryWithOptions(ctx, constraint, opts)
}

// QueryHistoryWithOptions queries the schedd for history records with options
// opts specifies query options including source type, limit, and projection
// Returns the matching history ads
func (s *Schedd) QueryHistoryWithOptions(ctx context.Context, constraint string, opts *HistoryQueryOptions) ([]*classad.ClassAd, error) {
	// Apply defaults if opts is nil
	if opts == nil {
		opts = &HistoryQueryOptions{}
	}
	effectiveOpts := opts.ApplyDefaults()

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

	// Build the request ClassAd
	requestAd, err := s.createHistoryQueryAd(constraint, &effectiveOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to create history query ad: %w", err)
	}

	// Connect and query
	ads, err := s.queryHistory(ctx, requestAd, &effectiveOpts)
	if err != nil {
		return nil, err
	}

	return ads, nil
}

// HistoryAdResult represents a single history ad or error from a streaming query
type HistoryAdResult struct {
	Ad  *classad.ClassAd
	Err error
}

// QueryHistoryStream queries the schedd for history and streams ads through a channel
// Returns a channel and an error. If the error is non-nil, it indicates a problem
// before the request was sent (e.g., invalid parameters, connection failure).
// The channel will be closed when all ads have been sent or an error occurs during streaming.
func (s *Schedd) QueryHistoryStream(ctx context.Context, constraint string, opts *HistoryQueryOptions, streamOpts *StreamOptions) (<-chan HistoryAdResult, error) {
	// Apply defaults
	if opts == nil {
		opts = &HistoryQueryOptions{}
	}
	effectiveOpts := opts.ApplyDefaults()

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

	// Build the request ClassAd
	requestAd, err := s.createHistoryQueryAd(constraint, &effectiveOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to create history query ad: %w", err)
	}

	// Create channel for streaming results
	ch := make(chan HistoryAdResult, streamOptsApplied.BufferSize)

	// Start goroutine to perform the query and stream results
	go func() {
		defer close(ch)

		// Perform query with streaming
		ads, err := s.queryHistoryStreaming(ctx, requestAd, &effectiveOpts, ch, &streamOptsApplied)
		if err != nil {
			ch <- HistoryAdResult{Err: err}
			return
		}

		// If not using server-side streaming, send all ads through channel
		if !effectiveOpts.StreamResults {
			totalBlockTime := time.Duration(0)
			for _, ad := range ads {
				// Check for context cancellation
				select {
				case <-ctx.Done():
					ch <- HistoryAdResult{Err: ctx.Err()}
					return
				default:
				}

				// Send ad with timeout tracking
				startTime := time.Now()
				select {
				case ch <- HistoryAdResult{Ad: ad}:
					blockTime := time.Since(startTime)
					totalBlockTime += blockTime
					if blockTime > 100*time.Millisecond {
						// Log slow write
						fmt.Printf("Warning: Blocked %v writing to history stream channel\n", blockTime)
					}
					if streamOptsApplied.WriteTimeout > 0 && totalBlockTime > streamOptsApplied.WriteTimeout {
						ch <- HistoryAdResult{Err: fmt.Errorf("cumulative write timeout exceeded: %v > %v", totalBlockTime, streamOptsApplied.WriteTimeout)}
						return
					}
				case <-ctx.Done():
					ch <- HistoryAdResult{Err: ctx.Err()}
					return
				}
			}
		}
	}()

	return ch, nil
}

// createHistoryQueryAd creates the request ClassAd for a history query
func (s *Schedd) createHistoryQueryAd(constraint string, opts *HistoryQueryOptions) (*classad.ClassAd, error) {
	ad := classad.New()

	// Set constraint
	if constraint != "" && constraint != "true" {
		// Parse constraint as expression
		constraintExpr, err := classad.ParseExpr(constraint)
		if err != nil {
			return nil, fmt.Errorf("failed to parse constraint: %w", err)
		}
		_ = ad.Set("Requirements", constraintExpr)
	}

	// Set match limit
	matchLimit := -1
	if !opts.IsUnlimited() {
		matchLimit = opts.Limit
	}
	_ = ad.Set("NumJobMatches", matchLimit)

	// Set scan limit
	if opts.ScanLimit > 0 {
		_ = ad.Set("ScanLimit", opts.ScanLimit)
	}

	// Set streaming preference
	_ = ad.Set("StreamResults", opts.StreamResults)

	// Set direction (backwards/forwards)
	if !opts.Backwards {
		_ = ad.Set("HistoryReadForwards", true)
	}

	// Set history record source
	switch opts.Source {
	case HistorySourceJobHistory:
		// Default, no extra attribute needed
	case HistorySourceJobEpoch:
		_ = ad.Set("HistoryRecordSource", "JOB_EPOCH")
		if opts.ReadFromDirectory {
			_ = ad.Set("HistoryFromDir", true)
		}
	case HistorySourceTransfer:
		// Transfer history is read from JOB_EPOCH with ad type filter
		_ = ad.Set("HistoryRecordSource", "JOB_EPOCH")
		// Build transfer type filter
		var transferTypes []string
		if len(opts.TransferTypes) > 0 {
			for _, tt := range opts.TransferTypes {
				transferTypes = append(transferTypes, string(tt))
			}
		} else {
			// Default to all transfer types
			transferTypes = []string{"INPUT", "OUTPUT", "CHECKPOINT"}
		}
		_ = ad.Set("HistoryAdTypeFilter", strings.Join(transferTypes, ","))
	case HistorySourceStartd:
		_ = ad.Set("HistoryRecordSource", "STARTD")
	case HistorySourceDaemon:
		_ = ad.Set("HistoryRecordSource", "DAEMON")
		if opts.DaemonSubsystem != "" {
			_ = ad.Set("DaemonHistorySubsys", opts.DaemonSubsystem)
		}
	default:
		return nil, fmt.Errorf("unsupported history source: %s", opts.Source)
	}

	// Set ad type filter if specified
	if len(opts.AdTypeFilter) > 0 {
		_ = ad.Set("HistoryAdTypeFilter", strings.Join(opts.AdTypeFilter, ","))
	}

	// Set since expression if specified
	if opts.Since != "" {
		// Parse as expression
		sinceExpr, err := classad.ParseExpr(opts.Since)
		if err != nil {
			// Try parsing as job ID (e.g., "123.0")
			parts := strings.Split(opts.Since, ".")
			switch len(parts) {
			case 2:
				cluster, err1 := strconv.Atoi(parts[0])
				proc, err2 := strconv.Atoi(parts[1])
				if err1 == nil && err2 == nil {
					sinceStr := fmt.Sprintf("ClusterId == %d && ProcId == %d", cluster, proc)
					sinceExpr, err = classad.ParseExpr(sinceStr)
					if err != nil {
						return nil, fmt.Errorf("failed to parse since job ID: %w", err)
					}
				} else {
					return nil, fmt.Errorf("invalid since parameter: %s (not a valid expression or job ID)", opts.Since)
				}
			case 1:
				// Just cluster ID
				cluster, err1 := strconv.Atoi(parts[0])
				if err1 == nil {
					sinceStr := fmt.Sprintf("ClusterId == %d", cluster)
					sinceExpr, err = classad.ParseExpr(sinceStr)
					if err != nil {
						return nil, fmt.Errorf("failed to parse since cluster ID: %w", err)
					}
				} else {
					return nil, fmt.Errorf("invalid since parameter: %s", opts.Since)
				}
			default:
				return nil, fmt.Errorf("invalid since parameter: %s", opts.Since)
			}
		}
		_ = ad.Set("Since", sinceExpr)
	}

	// Set projection if specified
	projection := opts.GetEffectiveProjection()
	if len(projection) > 0 {
		_ = ad.Set("Projection", strings.Join(projection, ","))
	}

	return ad, nil
}

// queryHistory performs the actual history query without streaming
func (s *Schedd) queryHistory(ctx context.Context, requestAd *classad.ClassAd, _ *HistoryQueryOptions) ([]*classad.ClassAd, error) {
	// Get SecurityConfig from context or defaults
	secConfig, err := GetSecurityConfigOrDefault(ctx, nil, commands.QUERY_SCHEDD_HISTORY, "CLIENT", s.address)
	if err != nil {
		return nil, fmt.Errorf("failed to create security config: %w", err)
	}

	// Connect to schedd and authenticate using cedar client
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

	// Send query request
	queryMsg := message.NewMessageForStream(cedarStream)
	if err := queryMsg.PutClassAd(ctx, requestAd); err != nil {
		return nil, fmt.Errorf("failed to serialize history query ClassAd: %w", err)
	}

	if err := queryMsg.FinishMessage(ctx); err != nil {
		return nil, fmt.Errorf("failed to send history query: %w", err)
	}

	// Receive response ads
	var ads []*classad.ClassAd
	matchCount := 0

	for {
		// Check for context cancellation
		select {
		case <-ctx.Done():
			return ads, ctx.Err()
		default:
		}

		// Receive next ad
		responseMsg := message.NewMessageFromStream(cedarStream)
		ad, err := responseMsg.GetClassAd(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to receive history ad: %w", err)
		}

		// Check if this is a control ad (Owner attribute indicates protocol state)
		if ownerVal, ok := ad.EvaluateAttrInt("Owner"); ok {
			if ownerVal == 1 {
				// First ad - check if server supports streaming
				// We can ignore this for now
				continue
			} else if ownerVal == 0 {
				// Last ad - check for errors
				if errCode, ok := ad.EvaluateAttrInt("ErrorCode"); ok && errCode != 0 {
					errMsg, _ := ad.EvaluateAttrString("ErrorString")
					return nil, fmt.Errorf("history query error %d: %s", errCode, errMsg)
				}
				// Verify match count
				if serverMatchCount, ok := ad.EvaluateAttrInt("NumMatches"); ok && int(serverMatchCount) != matchCount {
					return nil, fmt.Errorf("client and server match count mismatch: %d != %d", matchCount, serverMatchCount)
				}
				break
			}
		}

		// This is a history ad
		ads = append(ads, ad)
		matchCount++
	}

	return ads, nil
}

// queryHistoryStreaming performs the history query with streaming to a channel
func (s *Schedd) queryHistoryStreaming(ctx context.Context, requestAd *classad.ClassAd, opts *HistoryQueryOptions, ch chan<- HistoryAdResult, streamOpts *StreamOptions) ([]*classad.ClassAd, error) {
	// Get SecurityConfig from context or defaults
	secConfig, err := GetSecurityConfigOrDefault(ctx, nil, commands.QUERY_SCHEDD_HISTORY, "CLIENT", s.address)
	if err != nil {
		return nil, fmt.Errorf("failed to create security config: %w", err)
	}

	// Connect to schedd and authenticate using cedar client
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

	// Send query request
	queryMsg := message.NewMessageForStream(cedarStream)
	if err := queryMsg.PutClassAd(ctx, requestAd); err != nil {
		return nil, fmt.Errorf("failed to serialize history query ClassAd: %w", err)
	}

	if err := queryMsg.FinishMessage(ctx); err != nil {
		return nil, fmt.Errorf("failed to send history query: %w", err)
	}

	// Stream response ads
	var ads []*classad.ClassAd
	matchCount := 0
	totalBlockTime := time.Duration(0)

	for {
		// Check for context cancellation
		select {
		case <-ctx.Done():
			return ads, ctx.Err()
		default:
		}

		// Receive next ad
		responseMsg := message.NewMessageFromStream(cedarStream)
		ad, err := responseMsg.GetClassAd(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to receive history ad: %w", err)
		}

		// Check if this is a control ad
		if ownerVal, ok := ad.EvaluateAttrInt("Owner"); ok {
			if ownerVal == 1 {
				// First ad - check if server supports streaming
				continue
			} else if ownerVal == 0 {
				// Last ad - check for errors
				if errCode, ok := ad.EvaluateAttrInt("ErrorCode"); ok && errCode != 0 {
					errMsg, _ := ad.EvaluateAttrString("ErrorString")
					return nil, fmt.Errorf("history query error %d: %s", errCode, errMsg)
				}
				// Verify match count
				if serverMatchCount, ok := ad.EvaluateAttrInt("NumMatches"); ok && int(serverMatchCount) != matchCount {
					return nil, fmt.Errorf("client and server match count mismatch: %d != %d", matchCount, serverMatchCount)
				}
				break
			}
		}

		// This is a history ad
		matchCount++

		// If server is streaming, send ad to channel immediately
		if opts.StreamResults {
			startTime := time.Now()
			select {
			case ch <- HistoryAdResult{Ad: ad}:
				blockTime := time.Since(startTime)
				totalBlockTime += blockTime
				if streamOpts.WriteTimeout > 0 && totalBlockTime > streamOpts.WriteTimeout {
					return nil, fmt.Errorf("cumulative write timeout exceeded: %v > %v", totalBlockTime, streamOpts.WriteTimeout)
				}
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		} else {
			// Buffer ads for later sending
			ads = append(ads, ad)
		}
	}

	return ads, nil
}
