package htcondor

import (
	"context"
	"fmt"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/client"
	"github.com/bbockelm/cedar/message"
)

// Command codes for startup limits (from condor_commands.h)
// CREATE_STARTUP_LIMIT = SCHED_VERS + 159 = 400 + 159 = 559
// QUERY_STARTUP_LIMITS = SCHED_VERS + 160 = 400 + 160 = 560
const (
	cmdCreateStartupLimit = 559
	cmdQueryStartupLimits = 560
)

// StartupLimit represents a startup rate limit in the schedd
type StartupLimit struct {
	UUID           string  `json:"uuid"`
	Tag            string  `json:"tag"`
	Name           string  `json:"name,omitempty"`
	Expression     string  `json:"expression"`
	CostExpression string  `json:"cost_expression,omitempty"`
	RateCount      int     `json:"rate_count"`
	RateWindow     int     `json:"rate_window"` // seconds
	Burst          int     `json:"burst,omitempty"`
	MaxBurstCost   int     `json:"max_burst_cost,omitempty"`
	Expiration     int     `json:"expiration,omitempty"`      // seconds from creation
	ExpiresAt      int64   `json:"expires_at,omitempty"`      // Unix timestamp
	JobsAllowed    int64   `json:"jobs_allowed,omitempty"`    // Stats: jobs allowed
	CostAllowed    float64 `json:"cost_allowed,omitempty"`    // Stats: cost allowed
	JobsSkipped    int64   `json:"jobs_skipped,omitempty"`    // Stats: jobs skipped
	MatchesIgnored int64   `json:"matches_ignored,omitempty"` // Stats: matches ignored
	LastIgnored    int64   `json:"last_ignored,omitempty"`    // Stats: last time match ignored
	IgnoredUsers   string  `json:"ignored_users,omitempty"`   // Stats: comma-separated list
}

// StartupLimitRequest represents parameters for creating a startup limit
type StartupLimitRequest struct {
	UUID           string `json:"uuid,omitempty"`            // If provided, updates existing limit
	Tag            string `json:"tag"`                       // Required: unique tag identifier
	Name           string `json:"name,omitempty"`            // Optional: human-friendly name
	Expression     string `json:"expression"`                // Required: ClassAd expression to match jobs
	CostExpression string `json:"cost_expression,omitempty"` // Optional: expression for variable cost (default: 1)
	RateCount      int    `json:"rate_count"`                // Required: max jobs per window (0 = unlimited monitoring)
	RateWindow     int    `json:"rate_window"`               // Required: time window in seconds
	Burst          int    `json:"burst,omitempty"`           // Optional: extra capacity below zero
	MaxBurstCost   int    `json:"max_burst_cost,omitempty"`  // Optional: cap on single cost
	Expiration     int    `json:"expiration,omitempty"`      // Optional: expiration in seconds
}

// StartupLimitResponse represents the response from creating a startup limit
type StartupLimitResponse struct {
	Status int    `json:"status"`          // 0 = success, -1 = error
	UUID   string `json:"uuid,omitempty"`  // UUID of created/updated limit
	Error  string `json:"error,omitempty"` // Error message if status != 0
}

// ClassAd attribute names for startup limits
const (
	AttrStartupLimitUUID           = "StartupLimitUuid"
	AttrStartupLimitTag            = "StartupLimitTag"
	AttrStartupLimitName           = "StartupLimitName"
	AttrStartupLimitExpr           = "StartupLimitExpr"
	AttrStartupLimitCostExpr       = "StartupLimitCostExpr"
	AttrStartupLimitRateCount      = "StartupLimitRateCount"
	AttrStartupLimitRateWindow     = "StartupLimitRateWindow"
	AttrStartupLimitBurst          = "StartupLimitBurst"
	AttrStartupLimitMaxBurstCost   = "StartupLimitMaxBurstCost"
	AttrStartupLimitExpiration     = "StartupLimitExpiration"
	AttrStartupLimitStatus         = "StartupLimitStatus"
	AttrStartupLimitError          = "StartupLimitError"
	AttrStartupLimitJobsAllowed    = "StartupLimitJobsAllowed"
	AttrStartupLimitCostAllowed    = "StartupLimitCostAllowed"
	AttrStartupLimitJobsSkipped    = "StartupLimitJobsSkipped"
	AttrStartupLimitMatchesIgnored = "StartupLimitMatchesIgnored"
	AttrStartupLimitLastIgnored    = "StartupLimitLastIgnored"
	AttrStartupLimitIgnoredUsers   = "StartupLimitIgnoredUsers"
)

// CreateStartupLimit creates or updates a startup rate limit in the schedd
//
// Parameters:
//   - ctx: Context for the operation (can include security config via WithSecurityConfig)
//   - req: Startup limit parameters
//
// Returns:
//   - UUID of the created/updated limit
//   - Error if the operation fails
//
// Example:
//
//	req := &htcondor.StartupLimitRequest{
//	    Tag:        "gpu_limit",
//	    Name:       "GPU Job Rate Limit",
//	    Expression: "RequestGpus > 0",
//	    RateCount:  10,
//	    RateWindow: 60,  // 10 GPU jobs per minute
//	    Expiration: 3600, // expires in 1 hour
//	}
//	uuid, err := schedd.CreateStartupLimit(ctx, req)
func (s *Schedd) CreateStartupLimit(ctx context.Context, req *StartupLimitRequest) (string, error) {
	if req == nil {
		return "", fmt.Errorf("request cannot be nil")
	}
	if req.Tag == "" {
		return "", fmt.Errorf("tag is required")
	}
	if req.Expression == "" {
		return "", fmt.Errorf("expression is required")
	}
	if req.RateCount < 0 {
		return "", fmt.Errorf("rate_count must be non-negative")
	}
	if req.RateCount > 0 && req.RateWindow <= 0 {
		return "", fmt.Errorf("rate_window must be positive when rate_count > 0")
	}

	// Apply rate limiting if configured
	username := GetAuthenticatedUserFromContext(ctx)
	rateLimitManager := getRateLimitManager()
	if rateLimitManager != nil {
		if err := rateLimitManager.WaitSchedd(ctx, username); err != nil {
			return "", fmt.Errorf("rate limit exceeded: %w", err)
		}
	}

	// Get SecurityConfig
	secConfig, err := GetSecurityConfigOrDefault(ctx, nil, cmdCreateStartupLimit, "CLIENT", s.address)
	if err != nil {
		return "", fmt.Errorf("failed to create security config: %w", err)
	}

	// Establish connection and authenticate
	htcondorClient, err := client.ConnectAndAuthenticate(ctx, s.address, secConfig)
	if err != nil {
		return "", fmt.Errorf("failed to connect and authenticate to schedd at %s: %w", s.address, err)
	}
	defer func() {
		if cerr := htcondorClient.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("failed to close connection: %w", cerr)
		}
	}()

	// Get CEDAR stream from client
	cedarStream := htcondorClient.GetStream()

	// Build request ClassAd
	requestAd := classad.New()
	_ = requestAd.Set(AttrStartupLimitTag, req.Tag)

	// Parse expression as ClassAd expression
	exprTree, err := classad.ParseExpr(req.Expression)
	if err != nil {
		return "", fmt.Errorf("invalid expression: %w", err)
	}
	_ = requestAd.Set(AttrStartupLimitExpr, exprTree)

	_ = requestAd.Set(AttrStartupLimitRateCount, int64(req.RateCount))
	_ = requestAd.Set(AttrStartupLimitRateWindow, int64(req.RateWindow))

	if req.UUID != "" {
		_ = requestAd.Set(AttrStartupLimitUUID, req.UUID)
	}
	if req.Name != "" {
		_ = requestAd.Set(AttrStartupLimitName, req.Name)
	}
	if req.CostExpression != "" {
		costExpr, err := classad.ParseExpr(req.CostExpression)
		if err != nil {
			return "", fmt.Errorf("invalid cost expression: %w", err)
		}
		_ = requestAd.Set(AttrStartupLimitCostExpr, costExpr)
	}
	if req.Burst > 0 {
		_ = requestAd.Set(AttrStartupLimitBurst, int64(req.Burst))
	}
	if req.MaxBurstCost > 0 {
		_ = requestAd.Set(AttrStartupLimitMaxBurstCost, int64(req.MaxBurstCost))
	}
	if req.Expiration > 0 {
		_ = requestAd.Set(AttrStartupLimitExpiration, int64(req.Expiration))
	}

	// Send request ClassAd
	msg := message.NewMessageForStream(cedarStream)
	if err := msg.PutClassAd(ctx, requestAd); err != nil {
		return "", fmt.Errorf("failed to send request: %w", err)
	}
	if err := msg.FinishMessage(ctx); err != nil {
		return "", fmt.Errorf("failed to send end of message: %w", err)
	}

	// Receive response
	responseMsg := message.NewMessageFromStream(cedarStream)
	replyAd, err := responseMsg.GetClassAd(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to receive response: %w", err)
	}

	// Parse response
	status, ok := replyAd.EvaluateAttrInt(AttrStartupLimitStatus)
	if !ok {
		return "", fmt.Errorf("response missing status")
	}

	if status != 0 {
		errMsg := "unknown error"
		if val, ok := replyAd.EvaluateAttrString(AttrStartupLimitError); ok {
			errMsg = val
		}
		return "", fmt.Errorf("schedd rejected request: %s", errMsg)
	}

	uuid, ok := replyAd.EvaluateAttrString(AttrStartupLimitUUID)
	if !ok {
		return "", fmt.Errorf("response missing uuid")
	}

	return uuid, nil
}

// QueryStartupLimits queries startup rate limits from the schedd
//
// Parameters:
//   - ctx: Context for the operation (can include security config via WithSecurityConfig)
//   - uuid: Optional UUID to filter results (empty string = all limits)
//   - tag: Optional tag to filter results (empty string = all limits)
//
// Returns:
//   - Slice of startup limits matching the query
//   - Error if the operation fails
//
// Example:
//
//	// Get all limits
//	limits, err := schedd.QueryStartupLimits(ctx, "", "")
//
//	// Get specific limit by UUID
//	limits, err := schedd.QueryStartupLimits(ctx, "abc123", "")
//
//	// Get all limits with tag
//	limits, err := schedd.QueryStartupLimits(ctx, "", "gpu_limit")
func (s *Schedd) QueryStartupLimits(ctx context.Context, uuid, tag string) ([]*StartupLimit, error) {
	// Apply rate limiting if configured
	username := GetAuthenticatedUserFromContext(ctx)
	rateLimitManager := getRateLimitManager()
	if rateLimitManager != nil {
		if err := rateLimitManager.WaitSchedd(ctx, username); err != nil {
			return nil, fmt.Errorf("rate limit exceeded: %w", err)
		}
	}

	// Get SecurityConfig
	secConfig, err := GetSecurityConfigOrDefault(ctx, nil, cmdQueryStartupLimits, "CLIENT", s.address)
	if err != nil {
		return nil, fmt.Errorf("failed to create security config: %w", err)
	}

	// Establish connection and authenticate
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

	// Build request ClassAd with filters
	requestAd := classad.New()
	if uuid != "" {
		_ = requestAd.Set(AttrStartupLimitUUID, uuid)
	}
	if tag != "" {
		_ = requestAd.Set(AttrStartupLimitTag, tag)
	}

	// Send request ClassAd
	msg := message.NewMessageForStream(cedarStream)
	if err := msg.PutClassAd(ctx, requestAd); err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	if err := msg.FinishMessage(ctx); err != nil {
		return nil, fmt.Errorf("failed to send end of message: %w", err)
	}

	// Receive response ads
	var limits []*StartupLimit
	for {
		responseMsg := message.NewMessageFromStream(cedarStream)
		ad, err := responseMsg.GetClassAd(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to receive response: %w", err)
		}

		// Check for "Last" marker indicating end of results
		if val, ok := ad.EvaluateAttrBool("Last"); ok && val {
			break
		}

		// Parse startup limit from ClassAd
		limit := parseStartupLimitAd(ad)
		limits = append(limits, limit)
	}

	return limits, nil
}

// parseStartupLimitAd converts a ClassAd to a StartupLimit struct
func parseStartupLimitAd(ad *classad.ClassAd) *StartupLimit {
	limit := &StartupLimit{}

	if val, ok := ad.EvaluateAttrString(AttrStartupLimitUUID); ok {
		limit.UUID = val
	}
	if val, ok := ad.EvaluateAttrString(AttrStartupLimitTag); ok {
		limit.Tag = val
	}
	if val, ok := ad.EvaluateAttrString(AttrStartupLimitName); ok {
		limit.Name = val
	}
	if val, ok := ad.EvaluateAttrString(AttrStartupLimitExpr); ok {
		limit.Expression = val
	}
	if val, ok := ad.EvaluateAttrString(AttrStartupLimitCostExpr); ok {
		limit.CostExpression = val
	}
	if val, ok := ad.EvaluateAttrInt(AttrStartupLimitRateCount); ok {
		limit.RateCount = int(val)
	}
	if val, ok := ad.EvaluateAttrInt(AttrStartupLimitRateWindow); ok {
		limit.RateWindow = int(val)
	}
	if val, ok := ad.EvaluateAttrInt(AttrStartupLimitBurst); ok {
		limit.Burst = int(val)
	}
	if val, ok := ad.EvaluateAttrInt(AttrStartupLimitMaxBurstCost); ok {
		limit.MaxBurstCost = int(val)
	}
	if val, ok := ad.EvaluateAttrInt(AttrStartupLimitExpiration); ok {
		limit.ExpiresAt = val
	}
	if val, ok := ad.EvaluateAttrInt(AttrStartupLimitJobsAllowed); ok {
		limit.JobsAllowed = val
	}
	if val, ok := ad.EvaluateAttrReal(AttrStartupLimitCostAllowed); ok {
		limit.CostAllowed = val
	}
	if val, ok := ad.EvaluateAttrInt(AttrStartupLimitJobsSkipped); ok {
		limit.JobsSkipped = val
	}
	if val, ok := ad.EvaluateAttrInt(AttrStartupLimitMatchesIgnored); ok {
		limit.MatchesIgnored = val
	}
	if val, ok := ad.EvaluateAttrInt(AttrStartupLimitLastIgnored); ok {
		limit.LastIgnored = val
	}
	if val, ok := ad.EvaluateAttrString(AttrStartupLimitIgnoredUsers); ok {
		limit.IgnoredUsers = val
	}

	return limit
}
