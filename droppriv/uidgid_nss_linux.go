//go:build linux && !cgo

package droppriv

import (
	"context"
	"sync"
	"time"
)

// NSSLookupStrategy uses nsswitch.conf to determine the order of lookup strategies.
// It parses /etc/nsswitch.conf and builds a chain of strategies based on the passwd line.
type NSSLookupStrategy struct {
	*ChainedLookupStrategy
}

var (
	nssInitOnce   sync.Once
	nssMethods    []NSSSwitchMethod
	nssParseErr   error
	nssSwitchPath = "/etc/nsswitch.conf"
)

// ResetNSSCache resets the nsswitch.conf parsing cache. This is intended for testing only.
func ResetNSSCache() {
	nssInitOnce = sync.Once{}
	nssMethods = nil
	nssParseErr = nil
}

// SetNSSSwitchPath sets the path to nsswitch.conf. This is intended for testing only.
// Must be called before NewNSSLookup() and after ResetNSSCache() to take effect.
func SetNSSSwitchPath(path string) {
	nssSwitchPath = path
}

// NewNSSLookup creates a new NSS-based lookup strategy.
// It parses /etc/nsswitch.conf and creates a chain of strategies based on the passwd configuration.
func NewNSSLookup() (*NSSLookupStrategy, error) {
	// Parse nsswitch.conf only once
	nssInitOnce.Do(func() {
		nssMethods, nssParseErr = ParseNSSwitch(nssSwitchPath)
	})

	if nssParseErr != nil {
		// If we can't parse nsswitch.conf, this strategy is not available
		return nil, nssParseErr
	}

	// Build a chain of strategies based on nsswitch.conf ordering
	var strategies []LookupStrategy

	// Use a context with timeout for initialization
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	for _, method := range nssMethods {
		switch method {
		case NSSSwitchMethodSSS:
			// Try SSSD via gosssd
			if strategy, err := trySSSD(ctx); err == nil && strategy != nil {
				strategies = append(strategies, strategy)
			}
		case NSSSwitchMethodFiles:
			// Add Go's os/user fallback for files
			if strategy, err := tryGoFallback(); err == nil && strategy != nil {
				strategies = append(strategies, strategy)
			}
		}
	}

	// If no strategies were successfully created, this strategy is not available
	if len(strategies) == 0 {
		return nil, ErrStrategyNotAvailable
	}

	return &NSSLookupStrategy{
		ChainedLookupStrategy: &ChainedLookupStrategy{strategies: strategies},
	}, nil
}

// Name returns the strategy name.
func (n *NSSLookupStrategy) Name() string {
	return "nss:" + n.ChainedLookupStrategy.Name()
}

// tryNSSStrategy attempts to create an NSS-based lookup strategy.
func tryNSSStrategy() (LookupStrategy, error) {
	return NewNSSLookup()
}
