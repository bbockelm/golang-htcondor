package httpserver

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/config"
	"github.com/bbockelm/golang-htcondor/logging"
)

// Finding the condor_placementd that belongs to this access point.
//
// A placementd mints tokens for the access point it serves, and it
// authorizes that access point's daemon identity to ask. So the one this
// server talks to must be its own: a placementd on another access point
// that happened to trust this server would hand out tokens for the wrong
// access point. Several access points sharing one collector is the normal
// case, so "the first PlacementD ad" is not an answer.
//
// A placementd is optional: most pools do not run one, and every caller
// treats "not found" as "the placement endpoints are disabled" rather than
// a startup failure.

// placementdDiscoveryTimeout bounds one collector round trip.
const placementdDiscoveryTimeout = 10 * time.Second

// adQueryFunc queries the collector: the ads of adType matching constraint,
// carrying at least the projected attributes. A seam so discovery can be
// tested against a collector's answers without a collector.
type adQueryFunc func(ctx context.Context, adType, constraint string, projection []string) ([]*classad.ClassAd, error)

// collectorAdQuery is an adQueryFunc over a real collector, or nil for none.
func collectorAdQuery(c *htcondor.Collector) adQueryFunc {
	if c == nil {
		return nil
	}
	return func(ctx context.Context, adType, constraint string, projection []string) ([]*classad.ClassAd, error) {
		// The projection has to be named: nil options select the
		// collector's default projection, which drops Machine.
		ads, _, err := c.QueryAdsWithOptions(ctx, adType, constraint, &htcondor.QueryOptions{
			Limit:      -1,
			Projection: projection,
		})
		return ads, err
	}
}

// placementdLocator finds this access point's placementd. Its discover
// method is both the startup lookup and the client's resolver
// (Placementd.WithResolver), so a connection that fails can only ever be
// re-resolved to a placementd the same rule accepts.
type placementdLocator struct {
	// htcConfig names the local address file and FULL_HOSTNAME.
	htcConfig *config.Config
	// name is the operator's choice of placementd by its ad's Name
	// (HTTP_API_PLACEMENTD_NAME, else PLACEMENTD_HOST), or a sinful
	// string. It wins over everything else.
	name string
	// scheddName and scheddAddr identify this access point's schedd,
	// whose host is the access point's. scheddAddr is a function because
	// a discovered schedd's address follows its restarts; nil when there
	// is no single schedd (multi-AP mode).
	scheddName string
	scheddAddr func() string
	// query asks the collector; nil when there is none.
	query  adQueryFunc
	logger *logging.Logger

	// lastErr is why the most recent discovery found nothing, for the
	// admin status endpoint.
	mu      sync.Mutex
	lastErr error
}

// discover returns the address of this access point's placementd.
//
// In order:
//
//  1. The placementd the operator named (HTTP_API_PLACEMENTD_NAME, else
//     HTCondor's own PLACEMENTD_HOST), looked up by Name. This is how a
//     placementd on another host is used: it is never chosen otherwise.
//  2. This host's address file — PLACEMENTD_ADDRESS_FILE, or the HTCondor
//     default $(LOG)/.placementd_address. Preferred over the collector
//     because it is current even across a restart, which under shared
//     port rewrites the socket name in the sinful string.
//  3. A PlacementD ad in the collector whose Machine is this access
//     point's host. See accessPointHosts for what that is.
func (l *placementdLocator) discover(ctx context.Context) (string, error) {
	addr, err := l.find(htcondor.WithDaemonCredential(ctx, "placementd discovery"))
	l.mu.Lock()
	l.lastErr = err
	l.mu.Unlock()
	return addr, err
}

// lastError is why the most recent discovery found nothing, or nil.
func (l *placementdLocator) lastError() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.lastErr
}

func (l *placementdLocator) find(ctx context.Context) (string, error) {
	if name := strings.TrimSpace(l.name); name != "" {
		return l.byName(ctx, name)
	}

	if l.htcConfig != nil {
		if path := htcondor.AddressFilePath(l.htcConfig, "PLACEMENTD"); path != "" {
			if addr, err := htcondor.ReadAddressFile(path); err == nil && !strings.Contains(addr, "(null)") {
				l.logger.Info(logging.DestinationHTTP, "Found placementd via address file", "path", path, "address", addr)
				return addr, nil
			}
			l.logger.Debug(logging.DestinationHTTP, "No readable placementd address file", "path", path)
		}
	}

	if l.query == nil {
		return "", fmt.Errorf("no placementd address file and no collector to query")
	}

	hosts := l.accessPointHosts(ctx)
	if len(hosts) == 0 {
		return "", fmt.Errorf("cannot tell which host this access point runs on, so no placementd in the collector can be matched to it; set HTTP_API_PLACEMENTD_NAME to name one")
	}

	ads, err := l.placementdAds(ctx, "")
	if err != nil {
		return "", err
	}
	if len(ads) == 0 {
		return "", fmt.Errorf("no placementd ads found in collector")
	}

	var local []*classad.ClassAd
	var elsewhere []string
	for _, ad := range ads {
		host := placementdHost(ad)
		if host != "" && hosts[host] {
			local = append(local, ad)
			continue
		}
		name, _ := ad.EvaluateAttrString("Name")
		elsewhere = append(elsewhere, fmt.Sprintf("%s on %s", name, host))
	}
	if len(local) == 0 {
		return "", fmt.Errorf("found %d placementd ad(s) in the collector, none on this access point (%s): %s; "+
			"set HTTP_API_PLACEMENTD_NAME to use a placementd on another host",
			len(ads), strings.Join(slices.Sorted(maps.Keys(hosts)), ", "), strings.Join(elsewhere, "; "))
	}
	if len(local) > 1 {
		l.logger.Warn(logging.DestinationHTTP, "Several placementds advertise from this access point's host; using the first. Set HTTP_API_PLACEMENTD_NAME to choose.",
			"count", len(local))
	}
	return placementdAddress(local[0])
}

// byName looks up the placementd the operator named.
func (l *placementdLocator) byName(ctx context.Context, name string) (string, error) {
	// A sinful string is already an address.
	if strings.HasPrefix(name, "<") {
		return name, nil
	}
	if l.query == nil {
		return "", fmt.Errorf("placementd %q is configured but there is no collector to look it up in", name)
	}
	ads, err := l.placementdAds(ctx, "Name == "+classadString(name))
	if err != nil {
		return "", err
	}
	for _, ad := range ads {
		if n, ok := ad.EvaluateAttrString("Name"); ok && strings.EqualFold(n, name) {
			return placementdAddress(ad)
		}
	}
	return "", fmt.Errorf("no placementd named %q is advertised in the collector", name)
}

func (l *placementdLocator) placementdAds(ctx context.Context, constraint string) ([]*classad.ClassAd, error) {
	qctx, cancel := context.WithTimeout(ctx, placementdDiscoveryTimeout)
	defer cancel()
	ads, err := l.query(qctx, htcondor.PlacementdAdType, constraint, placementdQueryProjection())
	if err != nil {
		return nil, fmt.Errorf("failed to query collector for placementd: %w", err)
	}
	return ads, nil
}

// placementdQueryProjection is what discovery reads off a PlacementD ad.
func placementdQueryProjection() []string {
	return []string{"Name", "Machine", "MyAddress"}
}

// accessPointHosts is the set of host names this access point runs on,
// lowercased: a placementd advertising one of them as its Machine is this
// access point's.
//
// The schedd defines the access point, so its host comes first, from the
// schedd's own ad (Machine, which every HTCondor daemon sets to its host's
// full name) and from its Name (HTCondor names a daemon "host" or
// "name@host"). Those hold wherever this server runs, including in a
// container in front of a schedd on another machine. FULL_HOSTNAME, this
// server's own host, is the same rule the address file already applies.
func (l *placementdLocator) accessPointHosts(ctx context.Context) map[string]bool {
	hosts := map[string]bool{}
	add := func(h string) {
		if h = normalizeHost(h); h != "" {
			hosts[h] = true
		}
	}

	scheddAddr := ""
	if l.scheddAddr != nil {
		scheddAddr = strings.TrimSpace(l.scheddAddr())
	}
	constraint := ""
	switch {
	case l.scheddName != "":
		constraint = "Name == " + classadString(l.scheddName)
	case scheddAddr != "":
		constraint = "MyAddress == " + classadString(scheddAddr)
	}
	if constraint != "" && l.query != nil {
		qctx, cancel := context.WithTimeout(ctx, placementdDiscoveryTimeout)
		ads, err := l.query(qctx, "ScheddAd", constraint, []string{"Name", "Machine"})
		cancel()
		if err != nil {
			l.logger.Debug(logging.DestinationHTTP, "Could not read the schedd ad to find this access point's host", "error", err)
		}
		for _, ad := range ads {
			if m, ok := ad.EvaluateAttrString("Machine"); ok {
				add(m)
			}
		}
	}
	if i := strings.LastIndex(l.scheddName, "@"); i >= 0 {
		add(l.scheddName[i+1:])
	} else {
		add(l.scheddName)
	}
	if l.htcConfig != nil {
		if h, ok := l.htcConfig.Get("FULL_HOSTNAME"); ok {
			add(h)
		}
	}
	return hosts
}

// placementdHost is the host a PlacementD ad says its daemon runs on: its
// Machine, else the host part of its Name.
func placementdHost(ad *classad.ClassAd) string {
	if m, ok := ad.EvaluateAttrString("Machine"); ok && strings.TrimSpace(m) != "" {
		return normalizeHost(m)
	}
	name, _ := ad.EvaluateAttrString("Name")
	if i := strings.LastIndex(name, "@"); i >= 0 {
		name = name[i+1:]
	}
	return normalizeHost(name)
}

func placementdAddress(ad *classad.ClassAd) (string, error) {
	address, ok := ad.EvaluateAttrString("MyAddress")
	if !ok || address == "" {
		return "", fmt.Errorf("placementd ad missing MyAddress attribute")
	}
	return address, nil
}

// normalizeHost lowercases a host name and drops a trailing dot.
func normalizeHost(h string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(h)), ".")
}

// placementdReady reports whether a placementd can be used, noticing one
// that appeared since startup. A discovered client re-resolves its address
// on its own when a connection fails (Placementd.WithResolver); this covers
// the other case, a placementd that was not running when this server
// started.
//
// It never blocks the request on discovery, which can wait on the
// collector: an unavailable placementd starts a background look (throttled
// inside the client) and the answer is "not yet". A later request sees it.
func (h *Handler) placementdReady(ctx context.Context) bool {
	if h.placementd == nil {
		return false
	}
	if h.placementdAvailable.Load() {
		return true
	}
	p, ok := h.placementd.(*htcondor.Placementd)
	if !ok || !h.placementOnboard.resolving.CompareAndSwap(false, true) {
		return false
	}
	// Detached from the request, which may end first; bounded on its own.
	bg := context.WithoutCancel(ctx)
	go func() {
		defer h.placementOnboard.resolving.Store(false)
		ctx, cancel := context.WithTimeout(bg, 15*time.Second)
		defer cancel()
		if p.Resolve(htcondor.WithDaemonCredential(ctx, "placementd discovery")) != "" {
			h.placementdAvailable.Store(true)
			h.logger.Info(logging.DestinationHTTP, "Discovered placementd", "address", p.Address())
		}
	}()
	return false
}
