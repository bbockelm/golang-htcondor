package htcondor

import (
	"context"
	"fmt"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/client"
	"github.com/bbockelm/cedar/commands"
	"github.com/bbockelm/cedar/message"
)

// Collector represents an HTCondor collector daemon
type Collector struct {
	address string
}

// NewCollector creates a new Collector instance
func NewCollector(address string) *Collector {
	return &Collector{
		address: address,
	}
}

// QueryAds queries the collector for daemon advertisements
// adType specifies the type of ads to query (e.g., "StartdAd", "ScheddAd")
// constraint is a ClassAd constraint expression string (pass empty string for no constraint)
//
// Deprecated: Use QueryAdsWithOptions for pagination and default limits/projections
func (c *Collector) QueryAds(ctx context.Context, adType string, constraint string) ([]*classad.ClassAd, error) {
	return c.QueryAdsWithProjection(ctx, adType, constraint, nil)
}

// QueryAdsWithProjection queries the collector for daemon advertisements with optional projection
// adType specifies the type of ads to query (e.g., "StartdAd", "ScheddAd")
// constraint is a ClassAd constraint expression string (pass empty string for no constraint)
// projection is an optional list of attribute names to return (pass nil for all attributes)
//
// Deprecated: Use QueryAdsWithOptions for pagination and default limits/projections
func (c *Collector) QueryAdsWithProjection(ctx context.Context, adType string, constraint string, projection []string) ([]*classad.ClassAd, error) {
	return c.queryAdsInternal(ctx, adType, constraint, projection, nil)
}

// QueryAdsWithOptions queries the collector for daemon advertisements with pagination and limits
// opts specifies query options including limit, projection, and pagination
// Returns the matching ads and pagination info
func (c *Collector) QueryAdsWithOptions(ctx context.Context, adType string, constraint string, opts *QueryOptions) ([]*classad.ClassAd, *PageInfo, error) {
	// Apply defaults if opts is nil
	if opts == nil {
		opts = &QueryOptions{}
	}
	effectiveOpts := opts.ApplyDefaults()

	// Get effective projection
	projection := effectiveOpts.GetEffectiveProjection(DefaultCollectorProjection())

	// Query with the effective options
	ads, err := c.queryAdsInternal(ctx, adType, constraint, projection, &effectiveOpts)
	if err != nil {
		return nil, nil, err
	}

	// Build pagination info
	pageInfo := &PageInfo{
		TotalReturned:  len(ads),
		HasMoreResults: false,
		NextPageToken:  "",
	}

	// If we got exactly the limit, there might be more results
	// However, we can't know for sure without collector support, so leave HasMoreResults as false
	// Future enhancement: collector could support pagination hints

	return ads, pageInfo, nil
}

// StreamOptions configures streaming query behavior
type StreamOptions struct {
	// BufferSize is the number of ads to buffer in the channel (default: 100)
	BufferSize int
	// WriteTimeout is the maximum cumulative time spent blocking on channel writes (default: 5s)
	WriteTimeout time.Duration
}

// ApplyStreamDefaults returns StreamOptions with defaults applied
func (o *StreamOptions) ApplyStreamDefaults() StreamOptions {
	opts := StreamOptions{
		BufferSize:   100,
		WriteTimeout: 5 * time.Second,
	}
	if o != nil {
		if o.BufferSize > 0 {
			opts.BufferSize = o.BufferSize
		}
		if o.WriteTimeout > 0 {
			opts.WriteTimeout = o.WriteTimeout
		}
	}
	return opts
}

// AdResult represents a single ad or error from a streaming query
type AdResult struct {
	Ad  *classad.ClassAd
	Err error
}

// QueryAdsStream queries the collector and streams results through a channel
// The channel is returned immediately once the first ad is ready or an error occurs
// The channel will be closed when all ads have been sent or an error occurs
// If cumulative time blocking on channel writes exceeds StreamOptions.WriteTimeout, an error is sent
func (c *Collector) QueryAdsStream(ctx context.Context, adType string, constraint string, projection []string, streamOpts *StreamOptions) <-chan AdResult {
	ch := make(chan AdResult, streamOpts.ApplyStreamDefaults().BufferSize)

	go func() {
		defer close(ch)

		// Apply rate limiting if configured
		username := GetAuthenticatedUserFromContext(ctx)
		rateLimitManager := getRateLimitManager()
		if rateLimitManager != nil {
			if err := rateLimitManager.WaitCollector(ctx, username); err != nil {
				ch <- AdResult{Err: fmt.Errorf("rate limit exceeded: %w", err)}
				return
			}
		}

		// Establish connection
		htcondorClient, err := client.ConnectToAddress(ctx, c.address)
		if err != nil {
			ch <- AdResult{Err: fmt.Errorf("failed to connect to collector: %w", err)}
			return
		}
		defer htcondorClient.Close()

		// Get CEDAR stream
		cedarStream := htcondorClient.GetStream()

		// Determine command
		cmd, err := getCommandForAdType(adType)
		if err != nil {
			ch <- AdResult{Err: err}
			return
		}

		// Get security config
		secConfig, err := GetSecurityConfigOrDefault(ctx, nil, int(cmd), "CLIENT", c.address)
		if err != nil {
			ch <- AdResult{Err: fmt.Errorf("failed to create security config: %w", err)}
			return
		}

		// Perform security handshake
		auth := security.NewAuthenticator(secConfig, cedarStream)
		negotiation, err := auth.ClientHandshake(ctx)
		if err != nil {
			ch <- AdResult{Err: fmt.Errorf("security handshake failed: %w", err)}
			return
		}

		// Update context with authenticated user if needed
		if username == "" && negotiation.User != "" {
			ctx = WithAuthenticatedUser(ctx, negotiation.User)
		}

		// Create query ClassAd
		var constraintExpr *classad.Expr
		if constraint != "" {
			constraintExpr, err = classad.ParseExpr(constraint)
			if err != nil {
				ch <- AdResult{Err: fmt.Errorf("failed to parse constraint expression: %w", err)}
				return
			}
		}
		queryAd := createQueryAd(adType, constraintExpr, projection)

		// Send query
		queryMsg := message.NewMessageForStream(cedarStream)
		if err := queryMsg.PutClassAd(ctx, queryAd); err != nil {
			ch <- AdResult{Err: fmt.Errorf("failed to add query ClassAd to message: %w", err)}
			return
		}
		if err := queryMsg.FlushFrame(ctx, true); err != nil {
			ch <- AdResult{Err: fmt.Errorf("failed to send query message: %w", err)}
			return
		}

		// Stream response ads
		streamOptsApplied := streamOpts.ApplyStreamDefaults()
		totalBlockTime := time.Duration(0)

		// Create timer that wakes up periodically to check timeout
		checkInterval := 100 * time.Millisecond
		timer := time.NewTimer(checkInterval)
		defer timer.Stop()

		for {
			// Read "more" flag
			responseMsg := message.NewMessageFromStream(cedarStream)
			more, err := responseMsg.GetInt32(ctx)
			if err != nil {
				ch <- AdResult{Err: fmt.Errorf("failed to read 'more' flag: %w", err)}
				return
			}

			if more == 0 {
				// End of results
				return
			}

			// Read ClassAd
			ad, err := responseMsg.GetClassAd(ctx)
			if err != nil {
				ch <- AdResult{Err: fmt.Errorf("failed to read ClassAd: %w", err)}
				return
			}

			// Send ad to channel with timeout tracking using a timer
			// Calculate how much time we have left
			timeLeft := streamOptsApplied.WriteTimeout - totalBlockTime
			if timeLeft < checkInterval {
				checkInterval = timeLeft
			}
			if checkInterval <= 0 {
				ch <- AdResult{Err: fmt.Errorf("write timeout exceeded: blocked for %v (limit: %v)", totalBlockTime, streamOptsApplied.WriteTimeout)}
				return
			}
			timer.Reset(checkInterval)

			startWrite := time.Now()
			select {
			case ch <- AdResult{Ad: ad}:
				blockTime := time.Since(startWrite)
				totalBlockTime += blockTime
			case <-timer.C:
				// Timer expired - check if we've exceeded total timeout
				blockTime := time.Since(startWrite)
				totalBlockTime += blockTime
				if totalBlockTime >= streamOptsApplied.WriteTimeout {
					ch <- AdResult{Err: fmt.Errorf("write timeout exceeded: blocked for %v (limit: %v)", totalBlockTime, streamOptsApplied.WriteTimeout)}
					return
				}
				// Otherwise, retry the write
				select {
				case ch <- AdResult{Ad: ad}:
					// Success on retry
				case <-ctx.Done():
					ch <- AdResult{Err: ctx.Err()}
					return
				}
			case <-ctx.Done():
				ch <- AdResult{Err: ctx.Err()}
				return
			}
		}
	}()

	return ch
}

// queryAdsInternal performs the actual collector query
func (c *Collector) queryAdsInternal(ctx context.Context, adType string, constraint string, projection []string, opts *QueryOptions) ([]*classad.ClassAd, error) {
	// Apply rate limiting if configured
	username := GetAuthenticatedUserFromContext(ctx)
	rateLimitManager := getRateLimitManager()
	if rateLimitManager != nil {
		if err := rateLimitManager.WaitCollector(ctx, username); err != nil {
			return nil, fmt.Errorf("rate limit exceeded: %w", err)
		}
	}

	// Determine the command based on ad type
	cmd, err := getCommandForAdType(adType)
	if err != nil {
		return nil, err
	}

	// Get SecurityConfig from context, HTCondor config, or defaults
	secConfig, err := GetSecurityConfigOrDefault(ctx, nil, int(cmd), "CLIENT", c.address)
	if err != nil {
		return nil, fmt.Errorf("failed to create security config: %w", err)
	}

	// Establish connection and authenticate using cedar client
	// This handles session resumption failures automatically
	htcondorClient, err := client.ConnectAndAuthenticate(ctx, c.address, secConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to connect and authenticate to collector: %w", err)
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

	// Create query ClassAd
	var constraintExpr *classad.Expr
	if constraint != "" {
		var err error
		constraintExpr, err = classad.ParseExpr(constraint)
		if err != nil {
			return nil, fmt.Errorf("failed to parse constraint expression: %w", err)
		}
	}
	queryAd := createQueryAd(adType, constraintExpr, projection)

	// Create message and send query
	queryMsg := message.NewMessageForStream(cedarStream)
	err = queryMsg.PutClassAd(ctx, queryAd)
	if err != nil {
		return nil, fmt.Errorf("failed to add query ClassAd to message: %w", err)
	}

	err = queryMsg.FlushFrame(ctx, true)
	if err != nil {
		return nil, fmt.Errorf("failed to send query message: %w", err)
	}

	// Process response ads
	responseMsg := message.NewMessageFromStream(cedarStream)
	var ads []*classad.ClassAd

	// Determine the limit to apply
	limit := -1 // unlimited by default
	if opts != nil && !opts.IsUnlimited() {
		limit = opts.Limit
	}

	for {
		// Check for context cancellation
		select {
		case <-ctx.Done():
			return ads, ctx.Err()
		default:
		}

		// Check if we've reached the limit
		if limit > 0 && len(ads) >= limit {
			break
		}

		// Read "more" flag
		more, err := responseMsg.GetInt32(ctx)
		if err != nil {
			return ads, fmt.Errorf("failed to read 'more' flag: %w", err)
		}

		if more == 0 {
			break
		}

		// Read ClassAd
		ad, err := responseMsg.GetClassAd(ctx)
		if err != nil {
			return ads, fmt.Errorf("failed to read ClassAd: %w", err)
		}

		ads = append(ads, ad)
	}

	return ads, nil
}

// getCommandForAdType maps ad type to HTCondor command
func getCommandForAdType(adType string) (commands.CommandType, error) {
	switch adType {
	case "StartdAd", "Machine", "Startd":
		return commands.QUERY_STARTD_ADS, nil
	case "ScheddAd", "Schedd":
		return commands.QUERY_SCHEDD_ADS, nil
	case "MasterAd", "Master":
		return commands.QUERY_MASTER_ADS, nil
	case "SubmitterAd", "Submitter":
		return commands.QUERY_SUBMITTOR_ADS, nil
	case "LicenseAd", "License":
		return commands.QUERY_LICENSE_ADS, nil
	case "CollectorAd", "Collector":
		return commands.QUERY_COLLECTOR_ADS, nil
	case "NegotiatorAd", "Negotiator":
		return commands.QUERY_NEGOTIATOR_ADS, nil
	default:
		return 0, fmt.Errorf("unknown ad type: %s", adType)
	}
}

// createQueryAd creates a ClassAd for querying ads
func createQueryAd(adType string, constraint *classad.Expr, projection []string) *classad.ClassAd {
	ad := classad.New()

	// Set MyType and TargetType as required by HTCondor query protocol
	_ = ad.Set("MyType", "Query")

	// Set TargetType based on ad type
	targetType := getTargetTypeForAdType(adType)
	_ = ad.Set("TargetType", targetType)

	// Set Requirements
	if constraint == nil {
		_ = ad.Set("Requirements", true)
	} else {
		_ = ad.Set("Requirements", constraint)
	}

	// Set ProjectionAttributes if projection is specified
	if len(projection) > 0 {
		projectionStr := ""
		for i, attr := range projection {
			if i > 0 {
				projectionStr += ","
			}
			projectionStr += attr
		}
		_ = ad.Set("ProjectionAttributes", projectionStr)
	}

	return ad
}

// getTargetTypeForAdType maps ad type to TargetType
func getTargetTypeForAdType(adType string) string {
	switch adType {
	case "StartdAd", "Machine":
		return "Machine"
	case "ScheddAd", "Schedd":
		return "Scheduler"
	case "MasterAd", "Master":
		return "DaemonMaster"
	case "SubmitterAd", "Submitter":
		return "Submitter"
	case "NegotiatorAd", "Negotiator":
		return "Negotiator"
	case "CollectorAd", "Collector":
		return "Collector"
	default:
		return adType
	}
}

// Advertise sends an advertisement to the collector
func (c *Collector) Advertise(_ context.Context, _ *classad.ClassAd, _ string) error {
	// TODO: Implement advertisement using cedar protocol
	return fmt.Errorf("not implemented")
}

// LocateDaemon locates a daemon by querying the collector
func (c *Collector) LocateDaemon(_ context.Context, _ string, _ string) (*DaemonLocation, error) {
	// TODO: Implement daemon location logic
	return nil, fmt.Errorf("not implemented")
}

// DaemonLocation represents the location information for a daemon
type DaemonLocation struct {
	Name    string
	Address string
	Pool    string
}
