package htcondor

import (
	"context"
	"fmt"
	"net"
	"strings"
	"unicode"

	"github.com/bbockelm/cedar/addresses"
	"github.com/bbockelm/golang-htcondor/config"
)

// checkStarterBrokers refuses a starter address that routes through a CCB
// broker this pool's configuration does not name.
//
// The broker leg is the one connection on the way into a job that
// authenticates as this daemon, and the address naming the broker comes from
// the execute node, by way of the schedd. So the broker has to be one this
// side already knows: listed in CCB_ADDRESS, or one of the collectors in
// COLLECTOR_HOST, which run the CCB server by default and are what an
// execute node's CCB_ADDRESS usually points at.
//
// Hosts are compared, not ports or shared-port ids: a pool may spread CCB
// over several ports of its central manager, and a ccbid carries the broker
// as the address the execute node registered with -- usually an IP -- while
// the configuration usually names it by host name, so both sides are
// resolved before comparing.
func checkStarterBrokers(ctx context.Context, cfg *config.Config, starterAddr string) error {
	sinful, err := addresses.ParseSinful(starterAddr)
	if err != nil || !sinful.IsCCB() {
		return nil
	}
	if cfg == nil {
		cfg = getDefaultConfig()
	}
	trusted := trustedCCBBrokers(cfg)
	if len(trusted) == 0 {
		return fmt.Errorf("the starter at %s is reached through a CCB broker, and neither CCB_ADDRESS "+
			"nor COLLECTOR_HOST is configured to say which brokers this pool uses", starterAddr)
	}
	allowed := resolveBrokerHosts(ctx, trusted)
	for _, c := range sinful.CCBContacts {
		broker := firstCCBHop(c.BrokerAddr)
		if !brokerHostAllowed(ctx, broker, allowed) {
			return fmt.Errorf("the starter at %s names CCB broker %s, which is not among this pool's "+
				"brokers (CCB_ADDRESS, or else COLLECTOR_HOST); refusing to authenticate to it",
				starterAddr, broker)
		}
	}
	return nil
}

// trustedCCBBrokers lists the broker addresses the configuration names.
func trustedCCBBrokers(cfg *config.Config) []string {
	if cfg == nil {
		return nil
	}
	var out []string
	for _, key := range []string{"CCB_ADDRESS", "COLLECTOR_HOST"} {
		v, ok := cfg.Get(key)
		if !ok {
			continue
		}
		out = append(out, strings.FieldsFunc(v, func(r rune) bool {
			return r == ',' || unicode.IsSpace(r)
		})...)
	}
	return out
}

// firstCCBHop is the broker a contact is dialed through first. A nested
// (multi-hop) contact carries further hops after a '#'; the first hop is the
// only one this process connects and authenticates to.
func firstCCBHop(broker string) string {
	if i := strings.IndexByte(broker, '#'); i >= 0 {
		return broker[:i]
	}
	return broker
}

// brokerHosts is the set a broker must fall in: the configured names as
// written, and every address they resolve to.
type brokerHosts struct {
	names map[string]bool
	ips   map[string]bool
}

func sinfulHost(addr string) string {
	s, err := addresses.ParseSinful(addr)
	if err != nil {
		return ""
	}
	host := s.Host
	if host == "" {
		// A bare host name, with no port.
		host = s.PrimaryAddr
	}
	return strings.ToLower(strings.Trim(host, "[]"))
}

func resolveBrokerHosts(ctx context.Context, entries []string) brokerHosts {
	out := brokerHosts{names: map[string]bool{}, ips: map[string]bool{}}
	for _, e := range entries {
		host := sinfulHost(e)
		if host == "" {
			continue
		}
		out.names[host] = true
		for _, ip := range lookupHostIPs(ctx, host) {
			out.ips[ip] = true
		}
	}
	return out
}

func brokerHostAllowed(ctx context.Context, broker string, allowed brokerHosts) bool {
	host := sinfulHost(broker)
	if host == "" {
		return false
	}
	if allowed.names[host] {
		return true
	}
	for _, ip := range lookupHostIPs(ctx, host) {
		if allowed.ips[ip] {
			return true
		}
	}
	return false
}

// lookupHostIPs returns host's addresses in canonical form: host itself when
// it is a literal, nothing when it does not resolve.
func lookupHostIPs(ctx context.Context, host string) []string {
	if ip := net.ParseIP(host); ip != nil {
		return []string{ip.String()}
	}
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, a.IP.String())
	}
	return out
}
