package htcondor

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/client"
	"github.com/bbockelm/cedar/message"
	"github.com/bbockelm/golang-htcondor/config"
)

// historyEndpoint is the daemon a history query is sent to. The schedd and the startd speak the
// same history protocol -- a query ClassAd in, a stream of record ads out, framed by the two
// control ads -- but on different commands (QUERY_SCHEDD_HISTORY vs GET_HISTORY), so the wire
// work below is shared and only the endpoint differs.
type historyEndpoint struct {
	address string
	// cfg is the owning client's HTCondor configuration (nil: the
	// process-wide default).
	cfg     *config.Config
	command int
	// daemon names the peer in errors ("schedd", "startd").
	daemon string
	// rateLimit, when non-nil, gates the query through the process's rate limiter. Only the
	// schedd has one: there is no startd limiter, and borrowing the schedd's would throttle a
	// fan-out across a pool's execution points on a knob that means something else.
	rateLimit func(ctx context.Context, username string) error
}

// await applies the endpoint's rate limit, if it has one.
func (e historyEndpoint) await(ctx context.Context) error {
	if e.rateLimit == nil {
		return nil
	}
	username := GetAuthenticatedUserFromContext(ctx)
	rateLimitCtx, cancel := context.WithTimeout(ctx, 1000*time.Millisecond)
	defer cancel()
	if err := e.rateLimit(rateLimitCtx, username); err != nil {
		return fmt.Errorf("rate limit exceeded: %w", err)
	}
	return nil
}

// connect dials the endpoint, authenticates, and sends the query ad. It returns the authenticated
// client (the caller closes it) ready to be read for response ads.
func (e historyEndpoint) connect(ctx context.Context, requestAd *classad.ClassAd) (*client.HTCondorClient, error) {
	secConfig, err := GetSecurityConfigOrDefault(ctx, e.cfg, e.command, "CLIENT", e.address)
	if err != nil {
		return nil, fmt.Errorf("failed to create security config: %w", err)
	}

	htcondorClient, err := client.ConnectAndAuthenticate(ctx, e.address, secConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to connect and authenticate to %s at %s: %w", e.daemon, e.address, err)
	}

	queryMsg := message.NewMessageForStream(htcondorClient.GetStream())
	if err := queryMsg.PutClassAd(ctx, requestAd); err != nil {
		_ = htcondorClient.Close()
		return nil, fmt.Errorf("failed to serialize history query ClassAd: %w", err)
	}
	if err := queryMsg.FinishMessage(ctx); err != nil {
		_ = htcondorClient.Close()
		return nil, fmt.Errorf("failed to send history query: %w", err)
	}
	return htcondorClient, nil
}

// queryWithOptions runs a non-streaming history query against the endpoint.
func (e historyEndpoint) queryWithOptions(ctx context.Context, constraint string, opts *HistoryQueryOptions) ([]*classad.ClassAd, error) {
	if opts == nil {
		opts = &HistoryQueryOptions{}
	}
	effectiveOpts := opts.ApplyDefaults()

	if err := e.await(ctx); err != nil {
		return nil, err
	}

	requestAd, err := createHistoryQueryAd(constraint, &effectiveOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to create history query ad: %w", err)
	}
	return e.queryHistory(ctx, requestAd)
}

// queryStream runs a history query against the endpoint and streams the record ads through the
// returned channel, which is closed when the query finishes or fails.
func (e historyEndpoint) queryStream(ctx context.Context, constraint string, opts *HistoryQueryOptions, streamOpts *StreamOptions) (<-chan HistoryAdResult, error) {
	if opts == nil {
		opts = &HistoryQueryOptions{}
	}
	effectiveOpts := opts.ApplyDefaults()
	streamOptsApplied := streamOpts.ApplyStreamDefaults()

	if err := e.await(ctx); err != nil {
		return nil, err
	}

	requestAd, err := createHistoryQueryAd(constraint, &effectiveOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to create history query ad: %w", err)
	}

	ch := make(chan HistoryAdResult, streamOptsApplied.BufferSize)

	go func() {
		defer close(ch)

		ads, err := e.queryHistoryStreaming(ctx, requestAd, &effectiveOpts, ch, &streamOptsApplied)
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
func createHistoryQueryAd(constraint string, opts *HistoryQueryOptions) (*classad.ClassAd, error) {
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
		sinceExpr, err := parseSinceExpr(opts.Since)
		if err != nil {
			return nil, err
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

// parseSinceExpr turns the Since option into the expression the daemon stops its backward scan on.
// It is either a ClassAd expression or a job id ("123.0" / "123").
func parseSinceExpr(since string) (*classad.Expr, error) {
	sinceExpr, err := classad.ParseExpr(since)
	if err == nil {
		return sinceExpr, nil
	}
	// Not an expression: try parsing as a job ID (e.g., "123.0")
	parts := strings.Split(since, ".")
	switch len(parts) {
	case 2:
		cluster, err1 := strconv.Atoi(parts[0])
		proc, err2 := strconv.Atoi(parts[1])
		if err1 != nil || err2 != nil {
			return nil, fmt.Errorf("invalid since parameter: %s (not a valid expression or job ID)", since)
		}
		sinceExpr, err := classad.ParseExpr(fmt.Sprintf("ClusterId == %d && ProcId == %d", cluster, proc))
		if err != nil {
			return nil, fmt.Errorf("failed to parse since job ID: %w", err)
		}
		return sinceExpr, nil
	case 1:
		cluster, err1 := strconv.Atoi(parts[0])
		if err1 != nil {
			return nil, fmt.Errorf("invalid since parameter: %s", since)
		}
		sinceExpr, err := classad.ParseExpr(fmt.Sprintf("ClusterId == %d", cluster))
		if err != nil {
			return nil, fmt.Errorf("failed to parse since cluster ID: %w", err)
		}
		return sinceExpr, nil
	default:
		return nil, fmt.Errorf("invalid since parameter: %s", since)
	}
}

// queryHistory performs the actual history query without streaming
func (e historyEndpoint) queryHistory(ctx context.Context, requestAd *classad.ClassAd) (_ []*classad.ClassAd, err error) {
	htcondorClient, err := e.connect(ctx, requestAd)
	if err != nil {
		return nil, err
	}
	defer func() {
		if cerr := htcondorClient.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("failed to close connection: %w", cerr)
		}
	}()
	cedarStream := htcondorClient.GetStream()

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
func (e historyEndpoint) queryHistoryStreaming(ctx context.Context, requestAd *classad.ClassAd, opts *HistoryQueryOptions, ch chan<- HistoryAdResult, streamOpts *StreamOptions) (_ []*classad.ClassAd, err error) {
	htcondorClient, err := e.connect(ctx, requestAd)
	if err != nil {
		return nil, err
	}
	defer func() {
		if cerr := htcondorClient.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("failed to close connection: %w", cerr)
		}
	}()
	cedarStream := htcondorClient.GetStream()

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
