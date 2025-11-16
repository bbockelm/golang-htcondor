package htcondor

import (
	"context"
	"fmt"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/client"
	"github.com/bbockelm/cedar/commands"
	"github.com/bbockelm/cedar/message"
	"github.com/bbockelm/cedar/security"
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
func (c *Collector) QueryAds(ctx context.Context, adType string, constraint string) ([]*classad.ClassAd, error) {
	return c.QueryAdsWithProjection(ctx, adType, constraint, nil)
}

// QueryAdsWithProjection queries the collector for daemon advertisements with optional projection
// adType specifies the type of ads to query (e.g., "StartdAd", "ScheddAd")
// constraint is a ClassAd constraint expression string (pass empty string for no constraint)
// projection is an optional list of attribute names to return (pass nil for all attributes)
func (c *Collector) QueryAdsWithProjection(ctx context.Context, adType string, constraint string, projection []string) ([]*classad.ClassAd, error) {
	// Establish connection using cedar client
	htcondorClient, err := client.ConnectToAddress(ctx, c.address, 30*time.Second)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to collector: %w", err)
	}
	defer func() {
		if cerr := htcondorClient.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("failed to close connection: %w", cerr)
		}
	}()

	// Get CEDAR stream from client
	cedarStream := htcondorClient.GetStream()

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

	// Perform security handshake
	auth := security.NewAuthenticator(secConfig, cedarStream)
	_, err = auth.ClientHandshake(ctx)
	if err != nil {
		return nil, fmt.Errorf("security handshake failed: %w", err)
	}

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

	for {
		// Check for context cancellation
		select {
		case <-ctx.Done():
			return ads, ctx.Err()
		default:
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
