package config

import (
	"context"
	"errors"
	"net"
	"os"
	"runtime"
	"strings"
	"time"
)

// hostSystem is what localHostnames asks of the machine, so tests can stand
// in for it.
type hostSystem interface {
	// Hostname is gethostname(2).
	Hostname() (string, error)
	// CanonicalName is the ai_canonname getaddrinfo(3) returns for host with
	// AI_CANONNAME: the hosts-file entry's first name, or the name DNS
	// answered for, following CNAMEs.
	CanonicalName(host string) (string, error)
	// LookupHost is host's addresses, first one first.
	LookupHost(host string) ([]string, error)
	// RouteAddr is the local address the kernel would send a datagram to
	// host from.
	RouteAddr(host string) (string, error)
	// BestAddr is the address HTCondor would pick from the interfaces when
	// NETWORK_INTERFACE is a pattern.
	BestAddr() string
}

// localHostnames returns HOSTNAME and FULL_HOSTNAME as C++ HTCondor computes
// them (init_local_hostname_impl, condor_utils/ipv6_hostname.cpp), reading
// NETWORK_HOSTNAME, NO_DNS, DEFAULT_DOMAIN_NAME and, under NO_DNS,
// NETWORK_INTERFACE and COLLECTOR_HOST through param:
//
//   - The name is NETWORK_HOSTNAME if it is set, otherwise condor_gethostname:
//     gethostname(2), or under NO_DNS a name made from an address.
//   - Unless NETWORK_HOSTNAME or NO_DNS is set, the name is replaced by its
//     getaddrinfo canonical name when there is one. That is done whether or
//     not the name already has a dot, and the canonical name is taken even
//     without one ("localhost"). There is no reverse lookup.
//   - A name with a dot is the FULL_HOSTNAME, and HOSTNAME is its first
//     label. A name without one is HOSTNAME, and FULL_HOSTNAME is it plus
//     DEFAULT_DOMAIN_NAME when that is set.
//
// Both are "" when the name cannot be determined, as they are in C++.
func localHostnames(param func(string) (string, bool), sys hostSystem) (short, fqdn string) {
	get := func(name string) string {
		v, _ := param(name)
		return strings.TrimSpace(v)
	}
	noDNS := parseBoolDefault(get("NO_DNS"), false)

	hostname := get("NETWORK_HOSTNAME")
	fromNetworkHostname := hostname != ""
	if !fromNetworkHostname {
		var err error
		if hostname, err = condorGethostname(get, noDNS, sys); err != nil {
			return "", ""
		}
	}

	if !noDNS && !fromNetworkHostname {
		if canon, err := sys.CanonicalName(hostname); err == nil && canon != "" {
			hostname = canon
		}
	}

	if i := strings.IndexByte(hostname, '.'); i >= 0 {
		return hostname[:i], hostname
	}
	fqdn = hostname
	if domain := get("DEFAULT_DOMAIN_NAME"); domain != "" {
		if domain[0] != '.' {
			fqdn += "."
		}
		fqdn += domain
	}
	return hostname, fqdn
}

// condorGethostname is condor_gethostname (ipv6_hostname.cpp). Without NO_DNS
// it is gethostname(2). Under NO_DNS the name is made from an address
// (fakeHostname): NETWORK_INTERFACE's when it is set (it defaults to "*"),
// otherwise the one routing to COLLECTOR_HOST, otherwise the first address of
// gethostname(2)'s name.
func condorGethostname(get func(string) string, noDNS bool, sys hostSystem) (string, error) {
	if !noDNS {
		return sys.Hostname()
	}
	if iface := get("NETWORK_INTERFACE"); iface != "" {
		// A literal address is taken as is; a pattern takes the best
		// detected address, as IP_ADDRESS does.
		addr := iface
		if net.ParseIP(iface) == nil {
			addr = sys.BestAddr()
		}
		if addr == "" {
			return "", errors.New("NO_DNS: no address matches NETWORK_INTERFACE")
		}
		return fakeHostname(addr, get("DEFAULT_DOMAIN_NAME")), nil
	}
	if collector := get("COLLECTOR_HOST"); collector != "" {
		host, _, _ := strings.Cut(collector, ":")
		addr, err := sys.RouteAddr(host)
		if err != nil {
			return "", err
		}
		return fakeHostname(addr, get("DEFAULT_DOMAIN_NAME")), nil
	}
	name, err := sys.Hostname()
	if err != nil {
		return "", err
	}
	addrs, err := sys.LookupHost(name)
	if err != nil || len(addrs) == 0 {
		return "", errors.New("NO_DNS: cannot resolve " + name)
	}
	return fakeHostname(addrs[0], get("DEFAULT_DOMAIN_NAME")), nil
}

// fakeHostname is convert_ipaddr_to_fake_hostname (ipv6_hostname.cpp): the
// address with '.' and ':' turned into '-', in DEFAULT_DOMAIN_NAME, and ""
// when that is unset. A name may not begin with '-' (as "::1" would), so it
// is then prefixed with "0".
func fakeHostname(addr, domain string) string {
	if domain == "" {
		return ""
	}
	name := strings.NewReplacer(".", "-", ":", "-").Replace(addr) + "." + domain
	if name[0] == '-' {
		name = "0" + name
	}
	return name
}

// shortFromFQDN returns the first DNS label of a (possibly qualified) name --
// "ap43.uw.osg-htc.org" -> "ap43", "ap43" -> "ap43".
func shortFromFQDN(fqdn string) string {
	if i := strings.IndexByte(fqdn, '.'); i >= 0 {
		return fqdn[:i]
	}
	return fqdn
}

// parseBoolDefault reads an HTCondor boolean knob, returning def when it is
// unset or not a boolean.
func parseBoolDefault(v string, def bool) bool {
	switch strings.ToLower(v) {
	case "true", "t", "yes", "y", "1":
		return true
	case "false", "f", "no", "n", "0":
		return false
	}
	return def
}

// systemHosts is hostSystem on the real machine. Name lookups are bounded by a
// short timeout so loading the configuration never blocks on slow DNS.
type systemHosts struct{}

const hostLookupTimeout = 2 * time.Second

func (systemHosts) Hostname() (string, error) { return os.Hostname() }

// CanonicalName asks the resolver for host's canonical name. With cgo on
// Linux, LookupCNAME is getaddrinfo with AI_CANONNAME. On macOS the system
// resolver's LookupCNAME queries DNS only, skipping the hosts file that
// getaddrinfo reads first (where a Mac maps its own name to localhost), so
// Go's resolver, which reads /etc/hosts and then DNS, is used there.
func (systemHosts) CanonicalName(host string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), hostLookupTimeout)
	defer cancel()
	r := net.DefaultResolver
	if runtime.GOOS == "darwin" {
		r = &net.Resolver{PreferGo: true}
	}
	cname, err := r.LookupCNAME(ctx, host)
	if err != nil {
		return "", err
	}
	return strings.TrimSuffix(cname, "."), nil
}

func (systemHosts) LookupHost(host string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), hostLookupTimeout)
	defer cancel()
	return net.DefaultResolver.LookupHost(ctx, host)
}

// RouteAddr connects a UDP socket, which sends nothing, and reads the local
// address the kernel bound, as condor_gethostname does with port 1980.
func (systemHosts) RouteAddr(host string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), hostLookupTimeout)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "udp", net.JoinHostPort(host, "1980"))
	if err != nil {
		return "", err
	}
	defer func() { _ = conn.Close() }()
	addr, _, err := net.SplitHostPort(conn.LocalAddr().String())
	return addr, err
}

func (systemHosts) BestAddr() string {
	_, _, best := detectIPAddresses()
	return best
}

// memoHosts caches a hostSystem's CanonicalName answers, so one Config load
// that computes the names more than once asks the resolver once per name.
type memoHosts struct {
	hostSystem
	canon map[string]canonAnswer
}

type canonAnswer struct {
	name string
	err  error
}

func (m *memoHosts) CanonicalName(host string) (string, error) {
	if a, ok := m.canon[host]; ok {
		return a.name, a.err
	}
	name, err := m.hostSystem.CanonicalName(host)
	if m.canon == nil {
		m.canon = map[string]canonAnswer{}
	}
	m.canon[host] = canonAnswer{name, err}
	return name, err
}
