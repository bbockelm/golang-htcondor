package daemon

import (
	"context"

	"github.com/bbockelm/cedar/commands"
	cedarserver "github.com/bbockelm/cedar/server"
	"github.com/bbockelm/golang-htcondor/logging"
)

// RegisterDefaultCommands wires the standard DaemonCore command handlers onto a
// CEDAR command server so the daemon responds to the same command-port commands
// HTCondor's tools send directly (condor_ping, condor_reconfig -daemon,
// condor_off -daemon):
//
//   - DC_NOP / DC_NOP_*   -> liveness check; succeeds.
//   - DC_RECONFIG[_FULL]  -> Reconfigure (reload config + OnReconfig callbacks).
//   - DC_OFF_GRACEFUL / DC_OFF_PEACEFUL / DC_OFF_FAST -> Shutdown.
//
// Pool-wide condor_reconfig / condor_off go through condor_master, which signals
// children (SIGHUP / SIGTERM) — handled by Serve directly; these handlers cover
// the case where a tool targets this daemon's command port.
//
// The caller registers these on the same cedarserver.Server it uses for its own
// commands, then serves it via Daemon.Serve. Authentication is governed by the
// server's security config; callers that need per-command authorization should
// enforce it in addition (e.g. the authz package).
func (d *Daemon) RegisterDefaultCommands(srv *cedarserver.Server) {
	nop := func(context.Context, *cedarserver.Conn) error { return nil }
	for _, cmd := range []int{
		commands.DC_NOP,
		commands.DC_NOP_READ,
		commands.DC_NOP_WRITE,
		commands.DC_NOP_NEGOTIATOR,
	} {
		srv.Handle(cmd, nop)
	}

	reconfig := func(_ context.Context, c *cedarserver.Conn) error {
		d.log.Info(logging.DestinationGeneral, "DC_RECONFIG received; reloading configuration", "remote", c.RemoteAddr)
		d.Reconfigure()
		return nil
	}
	srv.Handle(commands.DC_RECONFIG, reconfig)
	srv.Handle(commands.DC_RECONFIG_FULL, reconfig)

	off := func(_ context.Context, c *cedarserver.Conn) error {
		d.log.Info(logging.DestinationGeneral, "DC_OFF received; shutting down", "command", c.Command, "remote", c.RemoteAddr)
		d.Shutdown()
		return nil
	}
	srv.Handle(commands.DC_OFF_GRACEFUL, off)
	srv.Handle(commands.DC_OFF_PEACEFUL, off)
	srv.Handle(commands.DC_OFF_FAST, off)
}
