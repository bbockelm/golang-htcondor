// Command testdaemon is a minimal HTCondor daemon built on the daemon framework,
// used by the daemon-under-condor_master integration test. It does nothing but
// come up under condor_master: connect to the master (DC_SET_READY +
// DC_CHILDALIVE heartbeat), adopt the inherited shared-port listener, and serve
// the default DaemonCore commands (DC_NOP / DC_RECONFIG / DC_OFF) on its command
// port until shut down.
package main

import (
	"context"
	"fmt"
	"net"
	"os"

	"github.com/bbockelm/cedar/commands"
	cedarserver "github.com/bbockelm/cedar/server"
	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/daemon"
	"github.com/bbockelm/golang-htcondor/logging"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "testdaemon:", err)
		os.Exit(1)
	}
}

func run() error {
	d, err := daemon.New(daemon.Options{Subsys: "TESTGODAEMON"})
	if err != nil {
		return err
	}
	log := d.Logger()

	ln, err := d.Listener(func() (net.Listener, error) {
		return (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	})
	if err != nil {
		return err
	}
	defer func() { _ = ln.Close() }()

	// Server security from the pool config so the command port speaks the same
	// authentication the rest of the daemons do.
	sec, err := htcondor.GetServerSecurityConfig(d.Config(), commands.DC_NOP, "DEFAULT")
	if err != nil {
		return fmt.Errorf("building security config: %w", err)
	}

	srv := cedarserver.New(sec)
	d.RegisterDefaultCommands(srv)

	log.Info(logging.DestinationGeneral, "testdaemon starting",
		"listen", ln.Addr().String(), "under_master", d.UnderMaster())

	return d.Serve(context.Background(), ln, srv.Serve)
}
