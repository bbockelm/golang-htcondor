package httpserver

import (
	"context"
	"fmt"
	"strings"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/config"
	"github.com/bbockelm/golang-htcondor/logging"
)

// discoverPlacementd finds the condor_placementd this AP should talk to.
//
// A placementd is optional: most pools do not run one, and every caller must
// treat "not found" as "the placement endpoints are disabled" rather than a
// startup failure.
//
// It looks in two places, in order:
//
//  1. The daemon's address file — PLACEMENTD_ADDRESS_FILE, or the HTCondor
//     default $(LOG)/.placementd_address. This is preferred because it is the
//     current address even across a condor_master restart, which under shared
//     port rewrites the socket token in the sinful string.
//  2. The collector, for a PlacementD ad. Unlike the schedd and credd there is
//     no name to correlate on — the placementd's Name is its own daemon name,
//     not the schedd's — so we take the first ad and, when several exist,
//     leave the choice to the operator via an explicit configuration.
func discoverPlacementd(ctx context.Context, htcConfig *config.Config, collector *htcondor.Collector, logger *logging.Logger) (string, error) {
	if htcConfig != nil {
		if path := htcondor.AddressFilePath(htcConfig, "PLACEMENTD"); path != "" {
			if addr, err := htcondor.ReadAddressFile(path); err == nil && !strings.Contains(addr, "(null)") {
				logger.Info(logging.DestinationHTTP, "Found placementd via address file", "path", path, "address", addr)
				return addr, nil
			}
			logger.Debug(logging.DestinationHTTP, "No readable placementd address file", "path", path)
		}
	}

	if collector == nil {
		return "", fmt.Errorf("no placementd address file and no collector to query")
	}

	queryCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	ads, _, err := collector.QueryAdsWithOptions(queryCtx, htcondor.PlacementdAdType, "", nil)
	if err != nil {
		return "", fmt.Errorf("failed to query collector for placementd: %w", err)
	}
	if len(ads) == 0 {
		return "", fmt.Errorf("no placementd ads found in collector")
	}
	if len(ads) > 1 {
		logger.Warn(logging.DestinationHTTP, "Multiple placementds advertised; using the first",
			"count", len(ads))
	}

	address, ok := ads[0].EvaluateAttrString("MyAddress")
	if !ok || address == "" {
		return "", fmt.Errorf("placementd ad missing MyAddress attribute")
	}
	return address, nil
}
