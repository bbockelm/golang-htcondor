package daemon

import (
	"sync/atomic"

	"github.com/bbockelm/cedar/commands"
	"github.com/bbockelm/cedar/security"
	cedarserver "github.com/bbockelm/cedar/server"
	"github.com/bbockelm/golang-htcondor/authz"
	"github.com/bbockelm/golang-htcondor/config"
	"github.com/bbockelm/golang-htcondor/logging"
)

// SecurityLevels are the authorization levels a command can be registered at,
// each of which has its own SEC_<level>_* security policy.
var SecurityLevels = []authz.Perm{
	authz.PermAllow, authz.PermRead, authz.PermWrite, authz.PermNegotiator,
	authz.PermAdministrator, authz.PermConfig, authz.PermDaemon,
	authz.PermAdvertiseStartd, authz.PermAdvertiseSchedd, authz.PermAdvertiseMaster,
}

// SecurityLevelConfigs builds the server security policy of every level in
// SecurityLevels with ServerSecurityConfig, keyed by level name. Each
// SEC_<level>_* setting falls back on its own along the level's chain (an
// ADVERTISE_* level to SEC_DAEMON_*, every level to SEC_DEFAULT_*), as
// htcondor.GetServerSecurityConfig resolves it. Call it after Listener.
func (d *Daemon) SecurityLevelConfigs() (map[string]*security.SecurityConfig, error) {
	byLevel := make(map[string]*security.SecurityConfig, len(SecurityLevels))
	for _, lvl := range SecurityLevels {
		sc, err := d.ServerSecurityConfig(commands.DC_NOP, string(lvl))
		if err != nil {
			return nil, err
		}
		byLevel[string(lvl)] = sc
	}
	return byLevel, nil
}

// InstallSecurityLevels makes srv negotiate each command under the security
// policy of the first authorization level the command is registered at, as
// DaemonCore does (daemon_command.cpp takes the server's policy from the
// command table's perm): a QUERY registered at READ under SEC_READ_*, an
// UPDATE_STARTD_AD registered at ADVERTISE_STARTD under SEC_ADVERTISE_STARTD_*,
// falling back setting by setting to SEC_DAEMON_* and SEC_DEFAULT_*. A
// DC_SEC_QUERY (condor_ping) negotiates under the level of the command it asks
// about. The policies are rebuilt on every reconfig, keeping the previous ones
// if the rebuild fails.
//
// The level is looked up when a connection negotiates, so it covers commands
// registered on srv after this call too (RegisterDefaultCommands, a CCB
// server, an embedded negotiator). A command registered at no level, or at
// one outside SecurityLevels, negotiates under srv.SecurityConfig. cedar gives
// each per-level policy srv.SecurityConfig's post-authentication policy and
// command levels, so every session maps identities and advertises its
// commands as the base policy does.
//
// Call it after Listener (the policies carry the shared-port id) and
// cedarserver.New.
func (d *Daemon) InstallSecurityLevels(srv *cedarserver.Server) error {
	byLevel, err := d.SecurityLevelConfigs()
	if err != nil {
		return err
	}
	var current atomic.Pointer[map[string]*security.SecurityConfig]
	current.Store(&byLevel)
	installSecurityLevels(srv, func() map[string]*security.SecurityConfig { return *current.Load() })
	d.OnReconfig(func(*config.Config) {
		byLevel, err := d.SecurityLevelConfigs()
		if err != nil {
			d.log.Error(logging.DestinationSecurity, "rebuilding per-level security policy failed; keeping the previous one", "err", err.Error())
			return
		}
		current.Store(&byLevel)
	})
	return nil
}

// InstallSecurityLevels makes srv negotiate each command under byLevel's
// policy for the first level the command is registered at, as
// Daemon.InstallSecurityLevels does, for a server whose policies are built
// elsewhere (Daemon.SecurityLevelConfigs). byLevel is not rebuilt on reconfig.
func InstallSecurityLevels(srv *cedarserver.Server, byLevel map[string]*security.SecurityConfig) {
	installSecurityLevels(srv, func() map[string]*security.SecurityConfig { return byLevel })
}

func installSecurityLevels(srv *cedarserver.Server, byLevel func() map[string]*security.SecurityConfig) {
	srv.SecurityConfigForCommand = func(command int) *security.SecurityConfig {
		perms := srv.CommandPerms(command)
		if len(perms) == 0 {
			return nil
		}
		return byLevel()[perms[0]]
	}
}
