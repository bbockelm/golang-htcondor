package daemon

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"regexp"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/bbockelm/cedar/commands"
	"github.com/bbockelm/cedar/security"
	cedarserver "github.com/bbockelm/cedar/server"
	"github.com/bbockelm/golang-htcondor/authz"
	"github.com/bbockelm/golang-htcondor/config"
	"github.com/bbockelm/golang-htcondor/logging"
)

// AuthzOptions configures an Authz.
type AuthzOptions struct {
	// Subsys is the subsystem whose ALLOW_<level>_<SUBSYS> variants apply.
	// Daemon.NewAuthz defaults it to the daemon's subsystem.
	Subsys string

	// Holes are the hole sets the daemon punches, re-evaluated on every
	// reload. nil means authz.DaemonCoreHoles(), the sets every C++ daemon
	// punches; a daemon adds its own (authz.StartdMatchSessionHoles for a
	// startd, authz.ScheddMatchSessionHoles for a schedd) to those.
	Holes []authz.HoleSet

	// CommandNames names, in denial logs, the commands this daemon serves
	// that cedar's command table and the DaemonCore defaults do not.
	CommandNames map[int]string
}

// Authz is a daemon's ALLOW_<level>/DENY_<level> authorization policy for
// every command on its command socket, with the authorization holes C++
// DaemonCore punches for the sessions it trusts. It is rebuilt on reconfig,
// as the C++ daemons rebuild IpVerify; holes, as in C++, carry over. Its
// Authorize is a cedar Server.Authorizer, and its Serve logs each command
// the policy refused.
type Authz struct {
	subsys string
	sets   []authz.HoleSet
	holes  *authz.Holes
	names  map[int]string

	mu     sync.Mutex // serializes Reload
	policy atomic.Pointer[authz.Policy]
}

// NewAuthz builds the policy from cfg. It does not reload by itself; see
// Daemon.NewAuthz.
func NewAuthz(cfg authz.ConfigGetter, opts AuthzOptions) (*Authz, error) {
	a := &Authz{
		subsys: opts.Subsys,
		sets:   opts.Holes,
		holes:  authz.NewHoles(),
		names:  opts.CommandNames,
	}
	if a.sets == nil {
		a.sets = authz.DaemonCoreHoles()
	}
	if err := a.Reload(cfg); err != nil {
		return nil, err
	}
	return a, nil
}

// NewAuthz builds the daemon's policy from its configuration and rebuilds it
// on every reconfig (SIGHUP or DC_RECONFIG), keeping the previous one if the
// rebuild fails. Install it with srv.Authorizer = a.Authorize and serve srv
// with a.Serve.
func (d *Daemon) NewAuthz(opts AuthzOptions) (*Authz, error) {
	if opts.Subsys == "" {
		opts.Subsys = d.subsys
	}
	a, err := NewAuthz(d.Config(), opts)
	if err != nil {
		return nil, err
	}
	d.OnReconfig(func(cfg *config.Config) {
		if err := a.Reload(cfg); err != nil {
			d.log.Error(logging.DestinationSecurity, "reloading authorization policy failed; keeping the previous one", "err", err.Error())
		}
	})
	return a, nil
}

// Reload rebuilds the policy from cfg and opens or closes each hole set as
// cfg now says; commands dispatched afterwards are checked against it.
func (a *Authz) Reload(cfg authz.ConfigGetter) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	p, err := authz.NewPolicy(cfg, a.subsys)
	if err != nil {
		return err
	}
	p.SetHoles(a.holes)
	a.holes.Apply(a.sets, cfg)
	a.policy.Store(p)
	return nil
}

// Authorize reports whether user, connecting from peerAddr, holds the
// authorization level perm. It has the signature of cedar's
// Server.Authorizer.
func (a *Authz) Authorize(perm, peerAddr, user string) bool {
	return a.policy.Load().Authorize(perm, peerAddr, user)
}

// Policy returns the current policy.
func (a *Authz) Policy() *authz.Policy { return a.policy.Load() }

// Holes returns the holes every policy a consults, for a daemon that punches
// holes as it runs (as the schedd opens READ to a claimed startd).
func (a *Authz) Holes() *authz.Holes { return a.holes }

// dcCommandNames names the DaemonCore commands RegisterDefaultCommands serves
// that cedar's command table does not.
var dcCommandNames = map[int]string{
	commands.DC_NOP:                  "DC_NOP",
	commands.DC_NOP_READ:             "DC_NOP_READ",
	commands.DC_NOP_WRITE:            "DC_NOP_WRITE",
	commands.DC_NOP_NEGOTIATOR:       "DC_NOP_NEGOTIATOR",
	commands.DC_NOP_ADMINISTRATOR:    "DC_NOP_ADMINISTRATOR",
	commands.DC_NOP_OWNER:            "DC_NOP_OWNER",
	commands.DC_NOP_CONFIG:           "DC_NOP_CONFIG",
	commands.DC_NOP_DAEMON:           "DC_NOP_DAEMON",
	commands.DC_NOP_ADVERTISE_STARTD: "DC_NOP_ADVERTISE_STARTD",
	commands.DC_NOP_ADVERTISE_SCHEDD: "DC_NOP_ADVERTISE_SCHEDD",
	commands.DC_NOP_ADVERTISE_MASTER: "DC_NOP_ADVERTISE_MASTER",
	commands.DC_RECONFIG:             "DC_RECONFIG",
	commands.DC_RECONFIG_FULL:        "DC_RECONFIG_FULL",
	commands.DC_OFF_GRACEFUL:         "DC_OFF_GRACEFUL",
	commands.DC_OFF_PEACEFUL:         "DC_OFF_PEACEFUL",
	commands.DC_OFF_FAST:             "DC_OFF_FAST",
}

// CommandName returns cmd's HTCondor name, or its number if it has none.
func (a *Authz) CommandName(cmd int) string {
	if n := commands.GetCommandName(cmd); n != "" {
		return n
	}
	if n, ok := a.names[cmd]; ok {
		return n
	}
	if n, ok := dcCommandNames[cmd]; ok {
		return n
	}
	return strconv.Itoa(cmd)
}

// refusedRE matches the error cedar's Server.ServeConn returns when the
// Authorizer refuses a command: it names the command and the identity, which
// is unauthenticated@unmapped for a peer that did not authenticate.
// limitedRE matches the one it returns when the command's levels are outside
// the authorization limits of the peer's credential (an IDTOKEN's
// condor:/<LEVEL> scopes), which cedar checks before the Authorizer. The
// tests fail if cedar changes either wording. cedar answers the peer DENIED
// for both. notFoundRE matches the error for a command the server has no
// handler for, which cedar answers CMD_NOT_FOUND and marks with
// security.ErrCommandNotFound.
var (
	refusedRE  = regexp.MustCompile(`command (\d+) \([^)]*\) refused: identity ("(?:[^"\\]|\\.)*") is not authorized`)
	limitedRE  = regexp.MustCompile(`command (\d+) \([^)]*\) refused: authorization levels \[([^\]]*)\] are outside the session's authorization limits \[([^\]]*)\]`)
	notFoundRE = regexp.MustCompile(`no authenticated handler for command (\d+)`)
)

// LogDenial logs err as PERMISSION DENIED if it is a command refused for
// authorization: by the ALLOW_/DENY_ policy, with the command, its
// authorization levels, the peer, the identity and the settings that decide
// those levels; or by the peer's authorization limits, with the command,
// levels, peer and those limits. A command the server has no handler for is
// logged as an unregistered command, as DaemonCore logs one. It reports
// whether err was one of these refusals. srv is the server that refused the
// command, for its registered levels.
func (a *Authz) LogDenial(log *slog.Logger, srv *cedarserver.Server, peerAddr string, err error) bool {
	msg := err.Error()
	if errors.Is(err, security.ErrCommandNotFound) {
		cmd := -1
		if m := notFoundRE.FindStringSubmatch(msg); m != nil {
			cmd, _ = strconv.Atoi(m[1])
		}
		log.Error("UNREGISTERED COMMAND",
			"command", a.CommandName(cmd),
			"command_id", cmd,
			"peer", peerAddr,
			"destination", "security")
		return true
	}
	if m := limitedRE.FindStringSubmatch(msg); m != nil {
		cmd, convErr := strconv.Atoi(m[1])
		if convErr != nil {
			return false
		}
		log.Warn("PERMISSION DENIED",
			"command", a.CommandName(cmd),
			"command_id", cmd,
			"level", strings.Join(strings.Fields(m[2]), ","),
			"peer", peerAddr,
			"authorization_limits", strings.Join(strings.Fields(m[3]), ","),
			"destination", "security")
		return true
	}
	m := refusedRE.FindStringSubmatch(msg)
	if m == nil {
		return false
	}
	cmd, convErr := strconv.Atoi(m[1])
	if convErr != nil {
		return false
	}
	user, convErr := strconv.Unquote(m[2])
	if convErr != nil {
		return false
	}
	if user == "" {
		user = cedarserver.UnauthenticatedFQU
	}
	var perms []string
	if srv != nil {
		perms = srv.CommandPerms(cmd)
	}
	p := a.Policy()
	var allow, deny []string
	for _, perm := range perms {
		ak, dk := p.Knobs(authz.Perm(perm))
		if ak == "" {
			ak = "ALLOW_" + perm + " (unset)"
		}
		allow = append(allow, ak)
		if dk != "" {
			deny = append(deny, dk)
		}
	}
	log.Warn("PERMISSION DENIED",
		"command", a.CommandName(cmd),
		"command_id", cmd,
		"level", strings.Join(perms, ","),
		"peer", peerAddr,
		"user", user,
		"allow_knob", strings.Join(allow, ","),
		"deny_knob", strings.Join(deny, ","),
		"destination", "security")
	return true
}

// Serve returns a serve loop for srv, for Daemon.Serve: like cedar's
// Server.Serve, it accepts connections on a listener and serves each on srv
// until ctx is cancelled, and it also logs every command refused for
// authorization (LogDenial) to log. cedar closes a refused connection without
// logging it, so this is the operator's record of a denial.
func (a *Authz) Serve(srv *cedarserver.Server, log *slog.Logger) func(context.Context, net.Listener) error {
	return func(ctx context.Context, ln net.Listener) error {
		go func() {
			<-ctx.Done()
			_ = ln.Close()
		}()
		for {
			conn, err := ln.Accept()
			if err != nil {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				return err
			}
			_ = srv.KeepAlive.Apply(conn)
			go func() {
				peer := conn.RemoteAddr().String()
				defer func() {
					if r := recover(); r != nil {
						log.Error("panic in connection handler; recovered",
							"panic", r, "remote", peer, "stack", string(debug.Stack()))
						_ = conn.Close()
					}
				}()
				if err := srv.ServeConn(ctx, conn); err != nil {
					a.LogDenial(log, srv, peer, err)
				}
			}()
		}
	}
}
