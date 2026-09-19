package httpserver

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/config"
	"github.com/bbockelm/golang-htcondor/logging"
)

// Finding the credd that belongs to the schedd this server submits to.
//
// Credentials are only useful in the credd the SUBMITTING schedd consults. Any
// other credd accepts the write, reports success, and leaves the job held for
// exactly the reason the credential was meant to prevent -- while this server
// caches "present" and stops looking. So a wrong answer here is worse than no
// answer, and discovery must be bound to the schedd rather than to the pool.
//
// HTCondor already publishes that binding: the schedd puts its credd's address
// in its own ad and in its address file as CredDIpAddr, and the C++ client
// reads it back the same way (DCSchedd::getCreddAddress). Following that makes
// the credd correct by construction, local or remote, instead of inferred.

// creddAddressAttr is the schedd's own statement of which credd it uses
// (ATTR_CREDD_IP_ADDR in HTCondor).
//
//nolint:gosec // G101: a ClassAd attribute name, not a credential.
const creddAddressAttr = "CredDIpAddr"

// creddDiscoveryTimeout bounds one collector round trip.
const creddDiscoveryTimeout = 10 * time.Second

// creddSource describes where an address came from, for the log line an
// operator reads when credentials end up somewhere unexpected.
type creddSource string

//nolint:gosec // G101: these name where an address came from, not a credential.
const (
	creddFromConfig      creddSource = "HTTP_API_CREDD_ADDRESS"
	creddFromScheddAd    creddSource = "the schedd's CredDIpAddr"
	creddFromAddressFile creddSource = "a local credd address file"
)

// discoverCredd returns the address of the credd this schedd uses.
//
// In order: what the operator configured, what the schedd says, and -- only
// when the schedd is this host's -- the local address file. There is no
// "any credd in the pool" fallback on purpose; see the note above.
func discoverCredd(ctx context.Context, cfg creddLookup, logger *logging.Logger) (string, error) {
	if addr := strings.TrimSpace(cfg.configured); addr != "" {
		logger.Info(logging.DestinationHTTP, "using the configured credd",
			"address", addr, "source", string(creddFromConfig))
		return addr, nil
	}

	// What the schedd says. This is the authoritative binding, so it is
	// tried for local and remote schedds alike.
	if addr, err := creddFromSchedd(ctx, cfg, logger); err == nil && addr != "" {
		logger.Info(logging.DestinationHTTP, "using the credd the schedd advertises",
			"address", addr, "schedd", cfg.scheddName, "source", string(creddFromScheddAd))
		return addr, nil
	} else if err != nil {
		logger.Debug(logging.DestinationHTTP, "could not read the schedd's credd address", "error", err)
	}

	// A schedd on this host may predate the attribute, so fall back to the
	// local address file -- but only then. For a remote schedd the local
	// credd is somebody else's.
	if cfg.scheddIsLocal {
		if addr := cfg.localCreddFunc()(logger); addr != "" {
			logger.Info(logging.DestinationHTTP, "using the local credd address file",
				"address", addr, "source", string(creddFromAddressFile))
			return addr, nil
		}
	}

	if !cfg.scheddIsLocal {
		return "", fmt.Errorf("the schedd %q does not advertise %s and is not on this host, "+
			"so there is no credd to use; set HTTP_API_CREDD_ADDRESS to name one",
			cfg.scheddName, creddAddressAttr)
	}
	return "", fmt.Errorf("no credd found: the schedd advertises no %s and no local credd address file exists",
		creddAddressAttr)
}

// creddLookup is what discovery needs to know about the schedd being fronted.
type creddLookup struct {
	// configured is HTTP_API_CREDD_ADDRESS, which always wins.
	configured string
	// scheddName and scheddAddr identify the schedd whose credd is wanted.
	scheddName string
	scheddAddr string
	// scheddIsLocal reports whether that schedd runs on this host, which is
	// the only case where a local credd address file can be its credd.
	scheddIsLocal bool
	collector     *htcondor.Collector
	// scheddAddressFile is this host's schedd address file, if any: it
	// carries CredDIpAddr among its metadata lines, so a local deployment
	// needs no collector at all.
	scheddAddressFile string
	// localCredd reads this host's credd address file. A field so a test
	// can supply one and prove a remote schedd still refuses it: without
	// the seam the "never use the local credd for a remote schedd" test
	// passes on any machine that simply has no credd installed.
	localCredd func(*logging.Logger) string
}

// localCreddFunc is cfg.localCredd, or the real lookup.
func (c creddLookup) localCreddFunc() func(*logging.Logger) string {
	if c.localCredd != nil {
		return c.localCredd
	}
	return localCreddAddress
}

// creddFromSchedd reads CredDIpAddr from the schedd's address file, else from
// its ad in the collector.
func creddFromSchedd(ctx context.Context, cfg creddLookup, logger *logging.Logger) (string, error) {
	if cfg.scheddIsLocal && cfg.scheddAddressFile != "" {
		if addr, err := creddFromAddressFileMetadata(cfg.scheddAddressFile); err == nil && addr != "" {
			return addr, nil
		}
	}

	if cfg.collector == nil {
		return "", fmt.Errorf("no collector configured and the schedd address file carries no %s", creddAddressAttr)
	}

	qctx, cancel := context.WithTimeout(ctx, creddDiscoveryTimeout)
	defer cancel()

	// Identify the schedd the same way the rest of this server does: by
	// name when there is one, else by the address we are actually talking
	// to, so a pool with several schedds cannot answer for the wrong one.
	constraint := ""
	switch {
	case cfg.scheddName != "":
		constraint = fmt.Sprintf("Name == %s", classadString(cfg.scheddName))
	case cfg.scheddAddr != "":
		constraint = fmt.Sprintf("MyAddress == %s", classadString(cfg.scheddAddr))
	default:
		return "", fmt.Errorf("neither a schedd name nor an address is known, so its credd cannot be identified")
	}

	ads, _, err := cfg.collector.QueryAdsWithOptions(qctx, "ScheddAd", constraint, nil)
	if err != nil {
		return "", fmt.Errorf("querying the collector for the schedd ad: %w", err)
	}
	if len(ads) == 0 {
		return "", fmt.Errorf("no schedd ad matched %s", constraint)
	}
	if len(ads) > 1 {
		// Ambiguous: guessing here is how credentials end up in the wrong
		// credd, which is the failure this whole path exists to avoid.
		logger.Warn(logging.DestinationHTTP, "several schedd ads matched; not guessing which credd to use",
			"constraint", constraint, "matches", len(ads))
		return "", fmt.Errorf("%d schedd ads matched %s", len(ads), constraint)
	}

	addr, ok := ads[0].EvaluateAttrString(creddAddressAttr)
	if !ok || strings.TrimSpace(addr) == "" {
		return "", fmt.Errorf("the schedd ad carries no %s", creddAddressAttr)
	}
	return strings.TrimSpace(addr), nil
}

// creddFromAddressFileMetadata reads CredDIpAddr from an HTCondor address
// file, whose first line is the sinful and whose later lines are metadata.
func creddFromAddressFileMetadata(path string) (string, error) {
	data, err := os.ReadFile(path) //nolint:gosec // path comes from HTCondor config
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		name, value, ok := strings.Cut(line, "=")
		if !ok || !strings.EqualFold(strings.TrimSpace(name), creddAddressAttr) {
			continue
		}
		return strings.Trim(strings.TrimSpace(value), `"`), nil
	}
	return "", fmt.Errorf("%s not found in %s", creddAddressAttr, path)
}

// localCreddAddress reads this host's credd address file, if it has one.
func localCreddAddress(logger *logging.Logger) string {
	path := findCreddAddressFile(logger)
	if path == "" {
		return ""
	}
	data, err := os.ReadFile(path) //nolint:gosec // path comes from HTCondor config or known locations
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "$") {
			continue
		}
		if strings.Contains(line, "(null)") {
			return ""
		}
		return line
	}
	return ""
}

// classadString quotes a value for a ClassAd constraint.
func classadString(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}

// scheddAddressFilePath is where this host's schedd would publish its address,
// per the HTCondor configuration. Empty when the configuration does not say.
func scheddAddressFilePath(cfg *config.Config) string {
	if cfg == nil {
		return ""
	}
	if path, ok := cfg.Get("SCHEDD_ADDRESS_FILE"); ok && strings.TrimSpace(path) != "" {
		return strings.TrimSpace(path)
	}
	if spool, ok := cfg.Get("SPOOL"); ok && strings.TrimSpace(spool) != "" {
		return filepath.Join(strings.TrimSpace(spool), ".schedd_address")
	}
	return ""
}

// scheddIsOnThisHost reports whether the schedd at scheddAddr is the one this
// host runs.
//
// The test is whether this host's schedd address file names that same address,
// rather than whether the address looks like loopback: a schedd reached by its
// real hostname is still local, and a loopback address inside a container need
// not be. Getting this wrong in the permissive direction is what would let a
// remote deployment use this host's credd.
func scheddIsOnThisHost(addressFile, scheddAddr string) bool {
	scheddAddr = strings.TrimSpace(scheddAddr)
	if scheddAddr == "" || addressFile == "" {
		return false
	}
	data, err := os.ReadFile(addressFile) //nolint:gosec // path comes from HTCondor config
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "$") {
			continue
		}
		return line == scheddAddr
	}
	return false
}

// creddLookupFor describes the schedd this server fronts, for discovery.
func (h *Handler) creddLookupFor(scheddAddr string) creddLookup {
	addressFile := scheddAddressFilePath(h.htcondorConfig)
	return creddLookup{
		configured:        h.creddAddress,
		scheddName:        h.scheddName,
		scheddAddr:        scheddAddr,
		scheddIsLocal:     scheddIsOnThisHost(addressFile, scheddAddr),
		collector:         h.collector,
		scheddAddressFile: addressFile,
	}
}
