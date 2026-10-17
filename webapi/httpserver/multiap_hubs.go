package httpserver

import (
	"context"
	"errors"
	"strings"
	"sync"

	"github.com/PelicanPlatform/classad/dbrpc"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/config"
	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/webapi/dbmirror"
	"github.com/bbockelm/golang-htcondor/webapi/multiap"
)

// The federation hubs multi-AP mode reads from.
//
// By default every HTCondorDB ad carrying FederationConstraint is a hub,
// and the set is re-discovered every 30 seconds. HTTP_API_HUB_NAME names
// the hubs instead (one, or several separated by commas or spaces);
// HTTP_API_HUB_ADDRESS dials one named, or the one discovered, at a
// fixed address. Each hub is reached through a locator of its own,
// pinned to its Name, so a hub that restarts on a new address is found
// again after a failed dial exactly as a lone hub is. multiap.Hub
// chooses which one reads go to.

// hubLocators is one dbmirror.Locator per hub, by lower-cased Name.
type hubLocators struct {
	collector *htcondor.Collector
	cfg       *config.Config

	mu    sync.Mutex
	locs  map[string]*dbmirror.Locator
	token func(ctx context.Context) (string, error)
}

// locator returns the locator for the hub named name, creating it with
// opts.
func (l *hubLocators) locator(name string, opts dbmirror.Options) *dbmirror.Locator {
	l.mu.Lock()
	defer l.mu.Unlock()
	key := strings.ToLower(name)
	if loc := l.locs[key]; loc != nil {
		return loc
	}
	loc := dbmirror.NewLocatorWithOptions(l.collector, l.cfg, opts)
	if l.token != nil {
		loc.SetTokenSource(l.token)
	}
	if l.locs == nil {
		l.locs = map[string]*dbmirror.Locator{}
	}
	l.locs[key] = loc
	return loc
}

// named is the locator of a hub found by name.
func (l *hubLocators) named(name string) *dbmirror.Locator {
	return l.locator(name, dbmirror.Options{Name: name, Constraint: dbmirror.HubConstraint, NoLocalFallback: true})
}

// get returns the locator already made for name, or nil.
func (l *hubLocators) get(name string) *dbmirror.Locator {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.locs[strings.ToLower(name)]
}

// setTokenSource gives every hub connection, present and future, the
// IDTOKEN the single-AP mirror would use.
func (l *hubLocators) setTokenSource(src func(ctx context.Context) (string, error)) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.token = src
	for _, loc := range l.locs {
		loc.SetTokenSource(src)
	}
}

func hubDialer(loc *dbmirror.Locator) multiap.Dialer {
	return func(ctx context.Context) (*dbrpc.Client, func(), error) {
		c, closer, _, err := loc.Client(ctx)
		return c, closer, err
	}
}

// splitHubNames reads HTTP_API_HUB_NAME: names separated by commas or
// white space.
func splitHubNames(v string) []string {
	var out []string
	for _, f := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' }) {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

// newHubSet builds the hub set multi-AP mode reads from.
func newHubSet(mc MultiAPConfig, locs *hubLocators, logger *logging.Logger) (*multiap.Hub, error) {
	names := splitHubNames(mc.HubName)
	if mc.HubAddress != "" && len(names) > 1 {
		return nil, errors.New("HTTP_API_HUB_ADDRESS is one address and HTTP_API_HUB_NAME names several hubs; " +
			"name one hub with the address, or unset the address and let each named hub be found in the collector")
	}
	opts := multiap.HubOptions{
		Policy: multiap.HubPolicy{SwitchAfter: mc.HubSwitchAfter, SwitchMargin: mc.HubSwitchMargin, FailAfter: mc.HubFailAfter},
		OnSwitch: func(sw multiap.HubSwitch) {
			logger.Warn(logging.DestinationHTTP, "Federation hub switched; reads now come from another hub",
				"from", sw.From, "to", sw.To, "reason", sw.Reason, "generation", sw.Generation)
		},
	}
	switch {
	case mc.HubAddress != "" || len(names) == 1:
		// One pinned hub, located as it always was.
		name := ""
		if len(names) == 1 {
			name = names[0]
		}
		hubOpts := dbmirror.Options{Name: name, Address: mc.HubAddress}
		if name == "" {
			hubOpts.Constraint = dbmirror.HubConstraint
		}
		// The database on this host is a spoke, not the hub, unless the
		// operator pinned the hub's address -- then asking that address
		// directly is the right fallback.
		hubOpts.NoLocalFallback = mc.HubAddress == ""
		loc := locs.locator(name, hubOpts)
		opts.Static = []multiap.HubSpec{{Name: name, Address: mc.HubAddress, Dial: hubDialer(loc)}}
	case len(names) > 1:
		for _, n := range names {
			opts.Static = append(opts.Static, multiap.HubSpec{Name: n, Dial: hubDialer(locs.named(n))})
		}
	default:
		disc := dbmirror.NewLocatorWithOptions(locs.collector, locs.cfg,
			dbmirror.Options{Constraint: dbmirror.HubConstraint, NoLocalFallback: true})
		opts.Discover = func(ctx context.Context) ([]multiap.HubSpec, error) {
			infos, err := disc.Hubs(ctx)
			if err != nil {
				return nil, err
			}
			specs := make([]multiap.HubSpec, 0, len(infos))
			for _, info := range infos {
				specs = append(specs, multiap.HubSpec{Name: info.Name, Address: info.Address, Dial: hubDialer(locs.named(info.Name))})
			}
			return specs, nil
		}
	}
	return multiap.NewHubSet(opts), nil
}

// hubAddress is where a hub was last found: the address its status
// carries, else its locator's last discovery.
func (m *multiAPMode) hubAddress(st multiap.HubStatus) string {
	if st.Address != "" || m.hubLocs == nil {
		return st.Address
	}
	if loc := m.hubLocs.get(st.Name); loc != nil {
		if info := loc.Health().Info; info != nil {
			return info.Address
		}
	}
	return ""
}
