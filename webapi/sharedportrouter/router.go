// Package sharedportrouter runs the API server's own inbound port for
// HTCondor shared-port traffic, so it can accept CCB connection reversal
// without a condor_shared_port daemon.
//
// The problem it solves is narrow. Reaching into a running job -- a shell, a
// tail, an exec -- means connecting to the starter on the execute node, and an
// execute node behind a firewall is reachable only through a Condor Connection
// Broker. CCB's default is for the starter to dial back to the caller, which
// needs the caller to be reachable from the execute node. An API server in a
// container or a Kubernetes pod is not. The broker's other mode, relaying the
// connection itself, does not need that -- but it arrived in HTCondor 25.13,
// the broker for any given dial is chosen by the execute node, and a pool
// running an older one leaves no way through at all.
//
// So do what the access point already does for condor_ssh_to_job: open one
// port and multiplex it. Each dial registers an id, advertises
// "<host:port?sock=ID>" as its reverse-connect address, and gets its own
// connection back on the shared port. Unlike condor_shared_port this routes
// within the process rather than passing file descriptors, because everything
// that needs a route is in this process.
package sharedportrouter

import (
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"

	cedarsharedport "github.com/bbockelm/cedar/server/sharedport"
)

// Config configures the router.
type Config struct {
	// Listen is the address to bind, as "host:port", ":port" or a bare port.
	// Required.
	Listen string

	// Advertised is the "host:port" execute nodes should dial to reach this
	// router. It has to be set whenever what peers dial is not what this
	// process binds -- behind NAT, a container port mapping, a Kubernetes
	// Service -- and binding a wildcard address with no Advertised is
	// rejected rather than guessed at.
	Advertised string

	// Logger receives the router's diagnostics.
	Logger *slog.Logger
}

// Router is a running inbound shared port.
type Router struct {
	srv *cedarsharedport.Server
}

// Start binds the port and begins routing. The caller must Close it.
func Start(cfg Config) (*Router, error) {
	listen, err := normalizeListenAddr(cfg.Listen)
	if err != nil {
		return nil, err
	}
	srv, err := cedarsharedport.Listen(listen, cedarsharedport.Options{
		AdvertisedAddr: strings.TrimSpace(cfg.Advertised),
		Logger:         cfg.Logger,
	})
	if err != nil {
		return nil, err
	}
	return &Router{srv: srv}, nil
}

// Register claims an inbound path for one CCB dial, satisfying
// htcondor.CCBReverseRouter. The listener it returns is closed by the dial,
// which releases the registration.
func (r *Router) Register() (net.Listener, string, error) {
	route, err := r.srv.Register("")
	if err != nil {
		return nil, "", err
	}
	return route, route.Sinful(), nil
}

// AdvertisedAddr is the "host:port" this router tells execute nodes to dial.
func (r *Router) AdvertisedAddr() string { return r.srv.AdvertisedAddr() }

// Stats reports what the router has routed, for the status endpoint and for
// tests that need to prove a connection took this path.
func (r *Router) Stats() cedarsharedport.Stats { return r.srv.Stats() }

// Close stops the router.
func (r *Router) Close() error { return r.srv.Close() }

// normalizeListenAddr accepts a bare port ("9618"), a port with a leading
// colon, or a full "host:port".
func normalizeListenAddr(raw string) (string, error) {
	addr := strings.TrimSpace(raw)
	if addr == "" {
		return "", fmt.Errorf("sharedportrouter: no listen address configured")
	}
	if !strings.Contains(addr, ":") {
		if _, err := strconv.Atoi(addr); err != nil {
			return "", fmt.Errorf("sharedportrouter: %q is neither a port nor a host:port", raw)
		}
		return ":" + addr, nil
	}
	if _, _, err := net.SplitHostPort(addr); err != nil {
		return "", fmt.Errorf("sharedportrouter: %q is not a valid listen address: %w", raw, err)
	}
	return addr, nil
}
