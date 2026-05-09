package config

// paramOverrides patches selected entries from the auto-generated
// paramDefaults table. Use this file (not param_defaults.go) when an
// upstream HTCondor default has drifted from what's encoded in our
// generated table — param_defaults.go is regenerated from HTCondor's
// param_info source and any hand-edits there get clobbered, while
// this file is owned by humans and survives regeneration.
//
// Each entry overrides a single parameter's default value. The
// override is applied AFTER paramDefaults loads but BEFORE any
// CONDOR_CONFIG file is read, so user-provided values still win.
// That ordering matches Config.initBuiltins() in config.go.
//
// Add entries sparingly: prefer regenerating param_defaults.go from
// upstream when feasible, and only override here when a stale
// generated default would cause functional breakage.
var paramOverrides = []struct {
	Name    string
	Default string
}{
	{
		// Generated default in param_defaults.go is the very old
		// "FS,TOKEN" pair, dating from before HTCondor split TOKEN
		// into IDTOKENS/SCITOKENS and added SSL to its built-in
		// fallback. Modern HTCondor (verified against 25.8 via
		// `condor_config_val -v SEC_DEFAULT_AUTHENTICATION_METHODS`)
		// uses the broader list below as its `<Default>` source.
		//
		// The stale value caused a real production failure: a
		// match-analysis collector query offered TOKEN only, the
		// server's IDTOKENS were filtered by iss/kid mismatch, and
		// the handshake errored out with "no compatible authentication
		// methods found" even though SSL would have worked on both
		// sides. Aligning with HTCondor's real default lets cedar
		// negotiate SSL transparently when token auth fails.
		Name:    "SEC_DEFAULT_AUTHENTICATION_METHODS",
		Default: "FS,IDTOKENS,KERBEROS,SCITOKENS,SSL",
	},
	{
		// HTTP_API_LOG follows HTCondor's per-daemon log convention:
		// every DC daemon's log path defaults to $(LOG)/<CamelCase>Log
		// (see param_info.in's MASTER_LOG, NEGOTIATOR_LOG, etc.).
		// HTTP_API isn't in HTCondor's upstream param_info, so the
		// generated paramDefaults table doesn't carry it — without
		// this override, an operator who only sets `HTTP_API =
		// /usr/sbin/htcondor-api` and adds it to DAEMON_LIST would
		// get a "No LOG path configured, using stdout" startup log
		// even though `$(LOG)` is set on the host. Defaulting here
		// matches what every other daemon does and what operators
		// expect.
		Name:    "HTTP_API_LOG",
		Default: "$(LOG)/HttpApiLog",
	},
	{
		// Companion rotation cap, mirroring MAX_SCHEDD_LOG /
		// MAX_MASTER_LOG. $(MAX_DEFAULT_LOG) is HTCondor's
		// pool-wide rotation default (10 MiB out of the box) —
		// inheriting it keeps HTTP_API consistent with the rest of
		// the pool's log-management policy.
		Name:    "MAX_HTTP_API_LOG",
		Default: "$(MAX_DEFAULT_LOG)",
	},
}
