package main

import (
	"slices"
	"sort"

	"github.com/bbockelm/golang-htcondor/config"
	"github.com/bbockelm/golang-htcondor/logging"
)

// Reconfigure: what a running htcondor-api does with SIGHUP (or condor_reconfig,
// which arrives as DC_RECONFIG and runs the same path).
//
// The daemon framework reloads the configuration file and re-applies log levels
// on its own. Everything else about this server is read once at startup and
// copied into the running objects, so until a parameter is listed here a change
// to it either does nothing or is not noticed at all. The second case is the
// one that costs an operator an afternoon: reconfigure appeared to succeed, and
// the setting they edited simply never took.
//
// So every parameter in this table is one the daemon has an answer for. Those
// with an apply function are installed on the running server; those without are
// reported as needing a restart, naming the parameter. Making a parameter
// dynamic means writing its setter (see httpserver/reconfig.go) and moving it
// up into the dynamic group -- the reporting half then takes care of itself.
type reconfigParam struct {
	// name is the bare parameter name. Lookup goes through config.Get, so
	// the daemon's subsystem and -local-name scoping applies, exactly as it
	// did when the value was first read at startup.
	name string
	// apply installs a new value on the running server. Nil means the
	// parameter is read only at startup and a change requires a restart.
	apply func(reconfigTarget, string)
}

// reconfigTarget is the running server a reconfigure updates. It is an
// interface, not *httpserver.Server, so the table and its bookkeeping can be
// exercised without standing up an HTTP server; *httpserver.Server satisfies it
// through the setters in httpserver/reconfig.go.
type reconfigTarget interface {
	SetMCPInstructions(string)
	SetMCPAccessGroups(string)
	SetMCPReadGroups(string)
	SetMCPWriteGroups(string)
	SetMCPAdminGroups(string)
	SetMCPSuperuserGroups(string)
	SetWebUIAccessGroups(string)
	SetWebUIAdminGroups(string)
	SetSuperuserGroups(string)
	SetMCPSkillsDir(string)
	SetMCPDisabledTools(string)
}

// reconfigParams is the table described above. It is deliberately a list of
// parameters this daemon actually consumes rather than every key in the
// configuration: a warning about a pool-wide knob htcondor-api never reads
// would be noise, and noise is what teaches operators to ignore warnings.
var reconfigParams = []reconfigParam{
	// --- Applied on reconfigure ---

	// Deployment-specific MCP guidance. Pure text handed to agents in the
	// initialize response, with nothing built from it, which is what makes
	// it safe to swap under live traffic.
	{
		name: "MCP_INSTRUCTIONS",
		apply: func(s reconfigTarget, v string) {
			s.SetMCPInstructions(v)
		},
	},

	// Which MCP tools this site offers. The catalogue is rebuilt per
	// call and the check runs on every dispatch, so nothing is
	// constructed from this and a change takes effect on the next
	// request -- including for sessions already connected, which is the
	// point: a tool withdrawn because policy changed should stop working
	// without waiting for agents to reconnect.
	{
		name: "HTTP_API_MCP_DISABLED_TOOLS",
		apply: func(s reconfigTarget, v string) {
			s.SetMCPDisabledTools(v)
		},
	},

	// Authorization group lists. Each is only a membership test on a
	// request -- nothing is constructed from one -- so they can be swapped
	// under live traffic. These are also the settings most often wrong on
	// a first deployment, where the alternative to a reconfigure is
	// restarting the daemon to find out whether the fix was right.
	//
	// Sessions already granted keep their grant until they refresh, at
	// which point the reauthorization path re-runs the policy.
	{
		name:  "HTTP_API_MCP_ACCESS_GROUP",
		apply: func(s reconfigTarget, v string) { s.SetMCPAccessGroups(v) },
	},
	{
		name:  "HTTP_API_MCP_READ_GROUP",
		apply: func(s reconfigTarget, v string) { s.SetMCPReadGroups(v) },
	},
	{
		name:  "HTTP_API_MCP_WRITE_GROUP",
		apply: func(s reconfigTarget, v string) { s.SetMCPWriteGroups(v) },
	},
	{
		name:  "HTTP_API_MCP_ADMIN_GROUP",
		apply: func(s reconfigTarget, v string) { s.SetMCPAdminGroups(v) },
	},
	{
		name:  "HTTP_API_MCP_SUPERUSER_GROUP",
		apply: func(s reconfigTarget, v string) { s.SetMCPSuperuserGroups(v) },
	},
	// Reloaded unconditionally in reconfigure() as well; this entry is what
	// handles the path being changed or cleared.
	//
	// A running daemon also polls this directory on its own
	// (HTTP_API_MCP_SKILLS_RELOAD_INTERVAL), so a checkout updated in place
	// no longer needs a reconfigure at all. What a reconfigure adds is
	// immediacy and an unconditional re-read: the poll skips files whose
	// size and modification time are unchanged, and this does not.
	{
		name:  "HTTP_API_MCP_SKILLS_DIR",
		apply: func(s reconfigTarget, v string) { s.SetMCPSkillsDir(v) },
	},
	{
		name:  "HTTP_API_WEBUI_ACCESS_GROUP",
		apply: func(s reconfigTarget, v string) { s.SetWebUIAccessGroups(v) },
	},
	{
		name:  "HTTP_API_WEBUI_ADMIN_GROUP",
		apply: func(s reconfigTarget, v string) { s.SetWebUIAdminGroups(v) },
	},
	// Membership only: superuser mode is built at startup, so this cannot
	// switch it on in a running daemon. Emptying it does switch it off.
	{
		name:  "HTTP_API_SUPERUSER_GROUP",
		apply: func(s reconfigTarget, v string) { s.SetSuperuserGroups(v) },
	},

	// --- Restart required (read once at startup) ---

	// The server's own identity. Beyond the links it builds, this is the
	// OAuth2 and IDP issuer: it is the `iss` of every token already issued
	// and the origin of the redirect URIs registered clients hold, so it
	// cannot be swapped under live sessions without invalidating them.
	{name: "HTTP_API_BASE_URL"},
	{name: "HTTP_API_MCP_BASE_URL"},

	// Listener and credentials, all bound or opened during startup.
	{name: "HTTP_API_LISTEN_ADDR"},
	{name: "HTTP_API_SIGNING_KEY"},
	{name: "HTTP_API_KEK_FILE"},
	{name: "HTTP_API_TLS_CERT"},
	{name: "HTTP_API_TLS_KEY"},

	// OAuth2 / IDP wiring, captured when the provider was constructed.
	{name: "HTTP_API_OAUTH2_ISSUER"},
	{name: "HTTP_API_OAUTH2_IDP"},
	{name: "HTTP_API_OAUTH2_CLIENT_ID"},
	{name: "HTTP_API_OAUTH2_CLIENT_SECRET_FILE"},
	{name: "HTTP_API_OAUTH2_SCOPES"},
	{name: "HTTP_API_OAUTH2_USERNAME_CLAIM"},
	{name: "HTTP_API_OAUTH2_GROUPS_CLAIM"},
	{name: "HTTP_API_OAUTH2_REQUIREMENTS"},
	{name: "HTTP_API_IDENTITY_MAP_STRIP_DOMAIN"},

	// The skills poll's ticker is started once, when the MCP server is
	// built. Changing how often it fires needs a restart; changing what it
	// reads does not (see HTTP_API_MCP_SKILLS_DIR above).
	{name: "HTTP_API_MCP_SKILLS_RELOAD_INTERVAL"},

	// Authorization groups. Worth making dynamic later -- they are consulted
	// per request -- but some are also folded into policy objects at
	// startup, so they need their setters before they can move up.
	{name: "MCP_ADMIN_USERS"},

	// Submit-time policy, compiled into the submit policy at startup.
	{name: "HTTP_API_SUBMIT_FILE_DEFAULTS"},
	{name: "HTTP_API_SUBMIT_FILE_OVERRIDES"},
	{name: "HTTP_API_INTERACTIVE_REQUIREMENTS"},
	{name: "HTTP_API_DAGMAN_PATH"},
	{name: "HTTP_API_DAGMAN_ENVIRONMENT"},
	{name: "HTTP_API_INTERACTIVE_EXTRA_SUBMIT"},
	{name: "HTTP_API_BUILD_EXTRA_SUBMIT"},
	{name: "HTTP_API_BUILD_REQUIREMENTS"},
	{name: "HTTP_API_BUILD_STAGING_BASE"},
	{name: "HTTP_API_BUILD_DEFAULT_CPUS"},
	{name: "HTTP_API_BUILD_DEFAULT_MEMORY_MB"},
	{name: "HTTP_API_BUILD_DEFAULT_DISK_MB"},
	{name: "HTTP_API_BUILD_MAX_CPUS"},
	{name: "HTTP_API_BUILD_MAX_MEMORY_MB"},
	{name: "HTTP_API_BUILD_MAX_DISK_MB"},

	// Mirror routing, resolved into a discovery locator at startup.
	{name: "HTTP_API_DBMIRROR_NAME"},
	{name: "HTTP_API_DBMIRROR_ADDRESS"},
	{name: "HTTP_API_DBMIRROR_REQUIRED"},
}

// reconfigWatcher remembers what each known parameter was set to, so a
// reconfigure can report what actually changed rather than re-applying
// everything blindly.
type reconfigWatcher struct {
	srv    reconfigTarget
	logger *logging.Logger
	params []reconfigParam
	// prev is the value each parameter had the last time it was observed:
	// at startup, then after each reconfigure.
	prev map[string]string
}

// newReconfigWatcher snapshots the current value of every known parameter.
// cfg must be the configuration the server was built from, so the first
// reconfigure compares against what is actually running.
func newReconfigWatcher(cfg *config.Config, srv reconfigTarget, logger *logging.Logger) *reconfigWatcher {
	w := &reconfigWatcher{srv: srv, logger: logger, params: reconfigParams, prev: map[string]string{}}
	for _, p := range w.params {
		w.prev[p.name] = configValue(cfg, p.name)
	}
	return w
}

// reconfigure applies the parameters that can be applied and reports the ones
// that cannot. It is registered with daemon.OnReconfig, so it runs on the
// daemon's signal goroutine while requests are being served.
func (w *reconfigWatcher) reconfigure(cfg *config.Config) {
	applied, needRestart := w.diff(cfg)

	// The skill library is reloaded from disk on every reconfigure, not
	// only when HTTP_API_MCP_SKILLS_DIR changes. The usual reason to
	// reload is that the checkout the path points at was updated -- a git
	// pull, a new deployment of the site's documentation -- which a diff
	// of the setting itself cannot see. This is the only parameter here
	// whose meaning lives outside the configuration file.
	if dir := configValue(cfg, "HTTP_API_MCP_SKILLS_DIR"); dir != "" {
		w.srv.SetMCPSkillsDir(dir)
		if !slices.Contains(applied, "HTTP_API_MCP_SKILLS_DIR") {
			applied = append(applied, "HTTP_API_MCP_SKILLS_DIR")
		}
	}

	// Values can be secrets, so log which parameters changed, never what
	// they changed to.
	if len(applied) > 0 {
		w.logger.Info(logging.DestinationGeneral, "reconfigure: applied configuration changes",
			"parameters", applied)
	}
	if len(needRestart) > 0 {
		w.logger.Warn(logging.DestinationGeneral,
			"reconfigure: these parameters changed but are only read at startup; the running server still uses the old values. Restart htcondor-api to apply them",
			"parameters", needRestart)
	}
	if len(applied) == 0 && len(needRestart) == 0 {
		w.logger.Info(logging.DestinationGeneral, "reconfigure: no known parameter changed")
	}
}

// diff applies every changed dynamic parameter and returns the names of what it
// applied and what it could not, each sorted. It updates the remembered values,
// so a restart-only parameter is reported when it changes and not on every
// reconfigure thereafter.
func (w *reconfigWatcher) diff(cfg *config.Config) (applied, needRestart []string) {
	for _, p := range w.params {
		newVal := configValue(cfg, p.name)
		if newVal == w.prev[p.name] {
			continue
		}
		// Record the new value either way. A restart-only parameter is
		// reported once, when it changes, rather than on every
		// reconfigure from here until the daemon is restarted.
		w.prev[p.name] = newVal
		if p.apply == nil {
			needRestart = append(needRestart, p.name)
			continue
		}
		p.apply(w.srv, newVal)
		applied = append(applied, p.name)
	}
	sort.Strings(applied)
	sort.Strings(needRestart)
	return applied, needRestart
}

// configValue returns the resolved value of a parameter, or "" when it is
// unset. Unset and empty compare equal on purpose: for every parameter here
// they mean the same thing to the server, and distinguishing them would report
// a change when a config file merely spells the default out.
func configValue(cfg *config.Config, name string) string {
	if v, ok := cfg.Get(name); ok {
		return v
	}
	return ""
}
