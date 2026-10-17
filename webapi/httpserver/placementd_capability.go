package httpserver

import (
	"context"
	"sync"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/logging"
)

// The placementd's directory commands (PLACEMENT_QUERY, PLACEMENT_EDIT) exist
// only on a daemon that advertises PlacementdApiVersion >= 2. The version is
// read from the daemon's collector ad and cached briefly, so a daemon upgrade
// shows up without restarting this server.

const (
	// placementCapabilityTTL is how long a successful lookup is trusted.
	placementCapabilityTTL = time.Minute
	// placementCapabilityRetry is how soon a failed lookup is retried.
	placementCapabilityRetry = 15 * time.Second
	// placementCapabilityTimeout bounds one collector query.
	placementCapabilityTimeout = 10 * time.Second
)

// placementAPIVersionCache remembers the placementd's API version.
type placementAPIVersionCache struct {
	mu      sync.Mutex
	address string
	version int
	expires time.Time
}

// placementAPIVersioner is implemented by a PlacementdClient that knows its
// daemon's API version without asking the collector (test fakes).
type placementAPIVersioner interface {
	APIVersion(ctx context.Context) (int, error)
}

// placementAPIVersion returns the placementd's API version: 0 when no
// placementd is available, 1 when its ad does not advertise one or cannot be
// read.
func (s *Handler) placementAPIVersion(ctx context.Context) int {
	if s.placementd == nil || !s.placementdAvailable.Load() {
		return 0
	}
	// The lookup is shared by every request that waits on it, so it must
	// not die with the request that happened to trigger it.
	lookupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), placementCapabilityTimeout)
	defer cancel()
	lookupCtx = htcondor.WithDaemonCredential(lookupCtx, "placementd capability lookup")

	if v, ok := s.placementd.(placementAPIVersioner); ok {
		n, err := v.APIVersion(lookupCtx)
		if err != nil || n < 1 {
			return 1
		}
		return n
	}

	address := ""
	if p, ok := s.placementd.(*htcondor.Placementd); ok {
		address = p.Address()
	}

	c := &s.placementCaps
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	if c.address == address && c.version > 0 && now.Before(c.expires) {
		return c.version
	}

	n, err := htcondor.QueryPlacementdAPIVersion(lookupCtx, s.collector, address)
	if err != nil {
		if s.logger != nil {
			s.logger.Debug(logging.DestinationHTTP, "Could not read the placementd API version", "error", err)
		}
		// Keep what we knew about this daemon rather than flap the UI
		// on one failed query.
		if c.address != address || c.version == 0 {
			c.version = 1
		}
		c.address = address
		c.expires = now.Add(placementCapabilityRetry)
		return c.version
	}
	c.address = address
	c.version = n
	c.expires = now.Add(placementCapabilityTTL)
	return n
}
