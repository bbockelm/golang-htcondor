package htcondor

import (
	"context"
	"fmt"
	"math/rand/v2"
	"strings"
	"sync"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/commands"
	"github.com/bbockelm/cedar/message"
	"github.com/bbockelm/cedar/stream"
)

const (
	// MaxAdvertiseBufferSize is the maximum buffer size for multiple ad advertisements (1MB)
	MaxAdvertiseBufferSize = 1024 * 1024

	// DefaultMyAddress is the default MyAddress value for ads without one set
	DefaultMyAddress = "<127.0.0.1:0>"

	// AvgBytesPerAttribute is the estimated average size per ClassAd attribute for buffer management
	AvgBytesPerAttribute = 100
)

// Collector represents an HTCondor collector daemon.
//
// The configured address may be a single host:port / sinful string
// or a comma-separated list ("host1:9618,host2:9618") matching the
// HTCondor COLLECTOR_HOST convention. With a list, every operation
// races against the entries with a small stagger so a stalled
// primary collector falls over to the secondary quickly. See
// collector_race.go for the protocol; `raceStagger == 0` (the
// default) means DefaultCollectorRaceStagger.
//
// Address ordering inside a list follows two principles, matching
// the C++ HTCondor client:
//
//  1. At construction, the address list is shuffled. A fleet of
//     identically-configured clients would otherwise pile onto the
//     same primary collector; shuffling spreads load.
//  2. After a successful dial, the winning address becomes "sticky"
//     and is moved to position 0 for subsequent dials. Sustained
//     traffic from one client therefore lands on a single collector
//     until that collector fails, at which point the race naturally
//     promotes whichever address won the failover.
type Collector struct {
	// address is the raw, user-supplied string (preserved for
	// Address() so logs match what the user actually configured).
	address string
	// addresses is the parsed list of collector addresses. Shuffled
	// at construction (single-entry lists are left alone). The
	// preferred-address override below is applied per-dial without
	// mutating this slice, so the shuffle remains the steady-state
	// fallback order.
	addresses []string
	// raceStagger overrides the default per-attempt delay between
	// concurrent connects. Zero = use DefaultCollectorRaceStagger.
	raceStagger time.Duration

	// mu guards the sticky-winner state below. dialAndAuthenticate
	// reads `preferred` while building the per-attempt order and
	// writes it on success; concurrent callers are common (every
	// QueryAds/Advertise can happen in parallel), so the lock is
	// load-bearing.
	mu        sync.Mutex
	preferred string // last-successful address; "" before first dial
}

// NewCollector creates a new Collector instance. address may be a
// single host:port (or sinful string) or a comma-separated list:
//
//	NewCollector("cm-1.ospool.osg-htc.org,cm-2.ospool.osg-htc.org")
//
// With a list, attempts are raced with a 150 ms stagger and the
// first that returns an authenticated CEDAR stream wins. The list
// is shuffled at construction; see the Collector type comment for
// the ordering policy.
func NewCollector(address string) *Collector {
	addrs := splitCollectorList(address)
	if len(addrs) > 1 {
		// rand/v2 is auto-seeded — no global rand.Seed needed and the
		// result varies per process, which is exactly what we want
		// for fleet-wide load spreading.
		rand.Shuffle(len(addrs), func(i, j int) {
			addrs[i], addrs[j] = addrs[j], addrs[i]
		})
	}
	return &Collector{
		address:   address,
		addresses: addrs,
	}
}

// WithRaceStagger returns a Collector with the inter-attempt
// delay overridden. Setting stagger == 0 disables the stagger
// (every address attempts in parallel from t=0). Negative values
// are clamped to the default.
//
// This is a fluent-style modifier so it composes with NewCollector:
//
//	c := htcondor.NewCollector(addrs).WithRaceStagger(200 * time.Millisecond)
func (c *Collector) WithRaceStagger(stagger time.Duration) *Collector {
	if stagger < 0 {
		stagger = DefaultCollectorRaceStagger
	}
	c.raceStagger = stagger
	return c
}

// Address returns the address the collector is configured against. Useful
// for logging and diagnostics; never returns the empty string for a Collector
// constructed via NewCollector. For a comma-separated list, returns the
// raw list string the caller passed in.
func (c *Collector) Address() string {
	if c == nil {
		return ""
	}
	return c.address
}

// Addresses returns the parsed list of collector addresses in the
// Collector's current dial-order: the last-successful address (if
// any) first, then the post-shuffle remainder. For a single-
// collector setup this returns a one-element slice. Never returns
// nil for a Collector built via NewCollector with a non-empty
// address.
//
// The returned slice is a defensive copy; mutating it has no
// effect on the Collector.
func (c *Collector) Addresses() []string {
	if c == nil {
		return nil
	}
	if len(c.addresses) > 0 {
		return c.orderedAddrs()
	}
	if c.address != "" {
		return []string{c.address}
	}
	return nil
}

// orderedAddrs returns the address list with the sticky-preferred
// entry pulled to position 0, leaving the rest in their construction
// (shuffled) order. The returned slice is freshly allocated so
// concurrent callers can mutate or hand it to raceDial without
// disturbing each other.
func (c *Collector) orderedAddrs() []string {
	c.mu.Lock()
	pref := c.preferred
	c.mu.Unlock()

	if pref == "" || len(c.addresses) <= 1 {
		return append([]string(nil), c.addresses...)
	}
	out := make([]string, 0, len(c.addresses))
	// Keep the preferred entry only if it's still in the list.
	// Hand-built &Collector{} with an out-of-list preferred isn't
	// expected, but defensively skip it if so.
	found := false
	for _, a := range c.addresses {
		if a == pref {
			found = true
		}
	}
	if found {
		out = append(out, pref)
	}
	for _, a := range c.addresses {
		if a != pref {
			out = append(out, a)
		}
	}
	return out
}

// notePreferred records `addr` as the last-successful collector.
// Subsequent dials will try it first. Pass "" to clear the sticky
// state (e.g., on a hard reconfigure).
func (c *Collector) notePreferred(addr string) {
	c.mu.Lock()
	c.preferred = addr
	c.mu.Unlock()
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
// Returns a channel and an error. If the error is non-nil, it indicates a problem
// before the request was sent (e.g., invalid parameters, connection failure).
// The channel will be closed when all ads have been sent or an error occurs during streaming.
// If cumulative time blocking on channel writes exceeds StreamOptions.WriteTimeout, an error is sent through the channel.
// The limit parameter controls the maximum number of ads to return (-1 for unlimited).
func (c *Collector) QueryAdsStream(ctx context.Context, adType string, constraint string, projection []string, limit int, streamOpts *StreamOptions) (<-chan AdResult, error) {
	// Apply stream defaults
	streamOptsApplied := streamOpts.ApplyStreamDefaults()

	// Apply rate limiting if configured
	username := GetAuthenticatedUserFromContext(ctx)
	rateLimitManager := getRateLimitManager()
	if rateLimitManager != nil {
		if err := rateLimitManager.WaitCollector(ctx, username); err != nil {
			return nil, fmt.Errorf("rate limit exceeded: %w", err)
		}
	}

	// Determine command
	cmd := getCommandForAdType(adType)

	// Parse constraint expression if provided
	var constraintExpr *classad.Expr
	var err error
	if constraint != "" {
		constraintExpr, err = classad.ParseExpr(constraint)
		if err != nil {
			return nil, fmt.Errorf("failed to parse constraint expression: %w", err)
		}
	}

	// Create channel for results
	ch := make(chan AdResult, streamOptsApplied.BufferSize)

	go func() {
		defer close(ch)

		// Race connect+authenticate across all configured addresses;
		// the security config is built per-address inside the helper.
		htcondorClient, err := c.dialAndAuthenticate(ctx, cmd)
		if err != nil {
			ch <- AdResult{Err: fmt.Errorf("failed to connect and authenticate to collector: %w", err)}
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

		// Create query ClassAd with limit
		queryAd := createQueryAd(adType, constraintExpr, projection, limit)

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
		adCount := 0

		// Create timer that wakes up periodically to check timeout
		checkInterval := 100 * time.Millisecond
		timer := time.NewTimer(checkInterval)
		defer timer.Stop()

		for {
			// Check if we've reached the limit
			if limit > 0 && adCount >= limit {
				return
			}

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
			for {
				select {
				case ch <- AdResult{Ad: ad}:
					blockTime := time.Since(startWrite)
					totalBlockTime += blockTime
					adCount++
					goto nextAd
				case <-timer.C:
					// Timer expired - check if we've exceeded total timeout
					blockTime := time.Since(startWrite)
					totalBlockTime += blockTime
					if totalBlockTime >= streamOptsApplied.WriteTimeout {
						ch <- AdResult{Err: fmt.Errorf("write timeout exceeded: blocked for %v (limit: %v)", totalBlockTime, streamOptsApplied.WriteTimeout)}
						return
					}
					// Continue retrying in the loop
					timer.Reset(checkInterval)
				case <-ctx.Done():
					ch <- AdResult{Err: ctx.Err()}
					return
				}
			}
		nextAd:
		}
	}()

	return ch, nil
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
	cmd := getCommandForAdType(adType)

	// Race connect+authenticate across configured collector addresses.
	// Single-address callers are unaffected (the helper short-circuits).
	htcondorClient, err := c.dialAndAuthenticate(ctx, cmd)
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

	// Get limit from options
	limit := -1
	if opts != nil && !opts.IsUnlimited() {
		limit = opts.Limit
	}
	queryAd := createQueryAd(adType, constraintExpr, projection, limit)

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

	// The limit is already enforced server-side via LimitResults, but keep client-side check as safety
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
func getCommandForAdType(adType string) commands.CommandType {
	switch adType {
	case "StartdAd", "Machine", "Startd":
		return commands.QUERY_STARTD_ADS
	case "ScheddAd", "Schedd":
		return commands.QUERY_SCHEDD_ADS
	case "MasterAd", "Master":
		return commands.QUERY_MASTER_ADS
	case "SubmitterAd", "Submitter":
		return commands.QUERY_SUBMITTOR_ADS
	case "LicenseAd", "License":
		return commands.QUERY_LICENSE_ADS
	case "CollectorAd", "Collector":
		return commands.QUERY_COLLECTOR_ADS
	case "NegotiatorAd", "Negotiator":
		return commands.QUERY_NEGOTIATOR_ADS
	default:
		// Unknown/custom ad type - use QUERY_GENERIC_ADS
		return commands.QUERY_GENERIC_ADS
	}
}

// createQueryAd creates a ClassAd for querying ads
func createQueryAd(adType string, constraint *classad.Expr, projection []string, limit int) *classad.ClassAd {
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

	// Set LimitResults for server-side limit enforcement
	if limit > 0 {
		_ = ad.Set("LimitResults", int64(limit))
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

// AdvertiseOptions configures advertisement behavior
type AdvertiseOptions struct {
	// Command specifies the UPDATE command to use (e.g., UPDATE_STARTD_AD)
	// If not specified, it will be determined from the ad's MyType attribute
	Command commands.CommandType
	// WithAck requests acknowledgment from the collector (forces TCP)
	WithAck bool
	// UseTCP forces TCP connection (default: true)
	UseTCP bool
}

// Advertise sends an advertisement to the collector
// The command type is determined from the ad's MyType attribute if not specified in opts
// Returns error if advertisement fails
func (c *Collector) Advertise(ctx context.Context, ad *classad.ClassAd, opts *AdvertiseOptions) error {
	if ad == nil {
		return fmt.Errorf("ad cannot be nil")
	}

	// Apply defaults
	if opts == nil {
		opts = &AdvertiseOptions{}
	}
	if !opts.WithAck && !opts.UseTCP {
		// Default to TCP for reliability
		opts.UseTCP = true
	}
	if opts.WithAck {
		// WithAck requires TCP
		opts.UseTCP = true
	}

	// Determine command if not specified
	cmd := opts.Command
	if cmd == 0 {
		cmd = getCommandForAdvertise(ad)
	}

	// Apply rate limiting if configured
	username := GetAuthenticatedUserFromContext(ctx)
	rateLimitManager := getRateLimitManager()
	if rateLimitManager != nil {
		if err := rateLimitManager.WaitCollector(ctx, username); err != nil {
			return fmt.Errorf("rate limit exceeded: %w", err)
		}
	}

	// Race connect+authenticate across configured collector addresses.
	htcondorClient, err := c.dialAndAuthenticate(ctx, cmd)
	if err != nil {
		return fmt.Errorf("failed to connect and authenticate to collector: %w", err)
	}
	defer func() { _ = htcondorClient.Close() }()

	// Get CEDAR stream
	cedarStream := htcondorClient.GetStream()

	// Ensure MyAddress is set in the ad
	if err := ensureMyAddress(ad); err != nil {
		return err
	}

	// Send the ad
	msg := message.NewMessageForStream(cedarStream)
	if err := msg.PutClassAd(ctx, ad); err != nil {
		return fmt.Errorf("failed to send ClassAd: %w", err)
	}
	if err := msg.FinishMessage(ctx); err != nil {
		return fmt.Errorf("failed to finish message: %w", err)
	}

	// Wait for acknowledgment if requested
	if opts.WithAck {
		responseMsg := message.NewMessageFromStream(cedarStream)
		ok, err := responseMsg.GetInt32(ctx)
		if err != nil {
			return fmt.Errorf("failed to read acknowledgment: %w", err)
		}
		if ok == 0 {
			return fmt.Errorf("collector rejected advertisement")
		}
	}

	return nil
}

// AdvertiseMultiple sends multiple advertisements to the collector efficiently
// Uses the multi-sending protocol to reuse the connection
// If ads exceed maxBufferSize (default 1MB), they are sent in batches
// Returns a slice of errors (one per ad), or nil if all succeeded
func (c *Collector) AdvertiseMultiple(ctx context.Context, ads []*classad.ClassAd, opts *AdvertiseOptions) []error {
	if len(ads) == 0 {
		return nil
	}

	// Apply defaults
	if opts == nil {
		opts = &AdvertiseOptions{}
	}
	if !opts.WithAck && !opts.UseTCP {
		opts.UseTCP = true
	}
	if opts.WithAck {
		opts.UseTCP = true
	}

	// WithAck doesn't support multiple ads in one connection
	if opts.WithAck {
		errors := make([]error, len(ads))
		for i, ad := range ads {
			errors[i] = c.Advertise(ctx, ad, opts)
		}
		return errors
	}

	// Determine command from first ad if not specified
	cmd := opts.Command
	if cmd == 0 {
		cmd = getCommandForAdvertise(ads[0])
	}

	// Apply rate limiting
	username := GetAuthenticatedUserFromContext(ctx)
	rateLimitManager := getRateLimitManager()
	if rateLimitManager != nil {
		if err := rateLimitManager.WaitCollector(ctx, username); err != nil {
			errors := make([]error, len(ads))
			rateLimitErr := fmt.Errorf("rate limit exceeded: %w", err)
			for i := range errors {
				errors[i] = rateLimitErr
			}
			return errors
		}
	}

	// Race connect+authenticate across configured collector addresses.
	htcondorClient, err := c.dialAndAuthenticate(ctx, cmd)
	if err != nil {
		errors := make([]error, len(ads))
		connErr := fmt.Errorf("failed to connect and authenticate to collector: %w", err)
		for i := range errors {
			errors[i] = connErr
		}
		return errors
	}
	defer func() { _ = htcondorClient.Close() }()

	// Get CEDAR stream
	cedarStream := htcondorClient.GetStream()

	// Send all ads using the multi-sending protocol
	errors := make([]error, len(ads))

	bufferSize := 0
	for i, ad := range ads {
		// Check context cancellation
		select {
		case <-ctx.Done():
			for j := i; j < len(ads); j++ {
				errors[j] = ctx.Err()
			}
			return errors
		default:
		}

		// Ensure MyAddress is set
		if err := ensureMyAddress(ad); err != nil {
			errors[i] = err
			continue
		}

		// Estimate ad size (rough approximation)
		adSize := estimateClassAdSize(ad)
		// HTCondor's multi-sending protocol has buffer limits. When buffer exceeds MaxAdvertiseBufferSize,
		// we need to flush and reconnect to avoid protocol violations and memory issues on the collector side.
		if bufferSize+adSize > MaxAdvertiseBufferSize && bufferSize > 0 {
			// Flush buffer by sending DC_NOP and reconnecting
			_ = sendGracefulHangup(ctx, cedarStream)

			// Close and reconnect — race again across the configured
			// addresses so a mid-batch failover stays cheap.
			_ = htcondorClient.Close()
			htcondorClient, err = c.dialAndAuthenticate(ctx, cmd)
			if err != nil {
				connErr := fmt.Errorf("failed to reconnect to collector: %w", err)
				for j := i; j < len(ads); j++ {
					errors[j] = connErr
				}
				return errors
			}
			cedarStream = htcondorClient.GetStream()
			bufferSize = 0
		}

		// Send the ad
		msg := message.NewMessageForStream(cedarStream)
		if err := msg.PutClassAd(ctx, ad); err != nil {
			errors[i] = fmt.Errorf("failed to send ClassAd: %w", err)
			continue
		}
		if err := msg.FlushFrame(ctx, true); err != nil {
			errors[i] = fmt.Errorf("failed to flush message: %w", err)
			continue
		}

		bufferSize += adSize
	}

	// Send graceful hangup (DC_NOP) for collector v7.7.3+
	_ = sendGracefulHangup(ctx, cedarStream)

	return errors
}

// getCommandForAdvertise determines the UPDATE command based on ad's MyType
func getCommandForAdvertise(ad *classad.ClassAd) commands.CommandType {
	_, ok := ad.Lookup("MyType")
	if !ok {
		// Default to UPDATE_AD_GENERIC if no MyType
		return commands.UPDATE_AD_GENERIC
	}

	myTypeStr, ok := ad.EvaluateAttrString("MyType")
	if !ok {
		return commands.UPDATE_AD_GENERIC
	}

	// Map MyType to UPDATE command
	// Based on HTCondor's advertise.cpp logic
	switch strings.ToUpper(myTypeStr) {
	case "MACHINE", "STARTD":
		return commands.UPDATE_STARTD_AD
	case "SCHEDULER", "SCHEDD":
		return commands.UPDATE_SCHEDD_AD
	case "DAEMONMASTER", "MASTER":
		return commands.UPDATE_MASTER_AD
	case "SUBMITTER":
		return commands.UPDATE_SUBMITTOR_AD
	case "COLLECTOR":
		return commands.UPDATE_COLLECTOR_AD
	case "NEGOTIATOR":
		return commands.UPDATE_NEGOTIATOR_AD
	case "LICENSE":
		return commands.UPDATE_LICENSE_AD
	case "STORAGE":
		return commands.UPDATE_STORAGE_AD
	case "ACCOUNTING":
		return commands.UPDATE_ACCOUNTING_AD
	case "GRID":
		return commands.UPDATE_GRID_AD
	case "HAD":
		return commands.UPDATE_HAD_AD
	case "GENERIC":
		return commands.UPDATE_AD_GENERIC
	default:
		// Unknown type, use GENERIC
		return commands.UPDATE_AD_GENERIC
	}
}

// ensureMyAddress ensures the ad has a MyAddress attribute
func ensureMyAddress(ad *classad.ClassAd) error {
	_, ok := ad.Lookup("MyAddress")
	if ok {
		return nil // MyAddress already set
	}

	// Generate a MyAddress using local IP
	// TODO: Use proper IP detection (IPv4/IPv6)
	// LIMITATION: The default address <127.0.0.1:0> may not work in distributed environments
	// where the collector needs to contact the advertising daemon. Users should set
	// MyAddress explicitly in the ad for production use.
	if err := ad.Set("MyAddress", DefaultMyAddress); err != nil {
		return fmt.Errorf("failed to set MyAddress: %w", err)
	}

	return nil
}

// estimateClassAdSize estimates the serialized size of a ClassAd
func estimateClassAdSize(ad *classad.ClassAd) int {
	// Rough estimation: assume average bytes per attribute
	// This is conservative to avoid buffer overflow
	attrs := ad.GetAttributes()
	return len(attrs) * AvgBytesPerAttribute
}

// sendGracefulHangup sends DC_NOP command for graceful connection closure
func sendGracefulHangup(ctx context.Context, cedarStream *stream.Stream) error {
	msg := message.NewMessageForStream(cedarStream)
	// Send DC_NOP (1) as hangup signal
	if err := msg.PutInt32(ctx, int32(commands.DC_NOP)); err != nil {
		return err
	}
	return msg.FlushFrame(ctx, true)
}

// LocateDaemon locates a daemon by querying the collector
// daemonType specifies the type of daemon to locate (e.g., "Schedd", "Startd", "Master")
// name is the name of the daemon to locate (optional, pass empty string to find any)
func (c *Collector) LocateDaemon(ctx context.Context, daemonType string, name string) (*DaemonLocation, error) {
	// Construct constraint to match the daemon name if provided
	constraint := ""
	if name != "" {
		constraint = fmt.Sprintf("Name == %s", classad.Quote(name))
	}

	// Query for at most one result with projection on Name and MyAddress
	projection := []string{"Name", "MyAddress"}
	opts := &QueryOptions{
		Limit:      1,
		Projection: projection,
	}

	ads, _, err := c.QueryAdsWithOptions(ctx, daemonType, constraint, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to query collector for %s daemon: %w", daemonType, err)
	}

	if len(ads) == 0 {
		if name != "" {
			return nil, fmt.Errorf("daemon %s of type %s not found", name, daemonType)
		}
		return nil, fmt.Errorf("no daemon of type %s found", daemonType)
	}

	ad := ads[0]

	// Extract Name attribute
	daemonName := ""
	if nameExpr, ok := ad.Lookup("Name"); ok {
		nameStr := nameExpr.String()
		// Remove quotes if present
		daemonName = strings.Trim(nameStr, "\"")
	}

	// Extract MyAddress attribute
	address := ""
	if addrExpr, ok := ad.Lookup("MyAddress"); ok {
		addrStr := addrExpr.String()
		// Remove quotes if present
		address = strings.Trim(addrStr, "\"")
	}

	if address == "" {
		return nil, fmt.Errorf("daemon ad missing MyAddress attribute")
	}

	return &DaemonLocation{
		Name:    daemonName,
		Address: address,
		Pool:    c.address,
	}, nil
}

// DaemonLocation represents the location information for a daemon
type DaemonLocation struct {
	Name    string
	Address string
	Pool    string
}
