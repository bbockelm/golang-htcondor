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
		// Encryption method default. In param_info.in this only appears
		// inside the security:* metaknobs (recommended/strong/FIPS),
		// never as a standalone param, so nothing bootstraps it unless a
		// config does `use security:...`. Without it, cfg.Get(
		// "SEC_DEFAULT_CRYPTO_METHODS") returns false and encryption
		// negotiation survived only on a scattered "AES" string literal
		// deep in getSecurityMethods — a workaround, not a real default,
		// and invisible to condor_config_val or any direct cfg.Get.
		// AES matches HTCondor 9.0+ (<Default> = AES); cedar only
		// implements AES-GCM anyway. The CLIENT/READ/etc. contexts fall
		// through to this via getSecurityMethods.
		//
		// Note: the authentication-method defaults are NOT bootstrapped
		// here. They are built programmatically in getSecurityMethods /
		// getDefaultAuthMethods (security.go) from the methods cedar
		// actually implements — the Go analogue of C++ building
		// SEC_STD_AUTH_METHOD_NAMES from compile-time HAVE_EXT_* flags —
		// so a static override cannot list a method (e.g. KERBEROS) that
		// cedar cannot perform. The stale generated
		// SEC_DEFAULT_AUTHENTICATION_METHODS = "FS,TOKEN" is handled
		// there (isStaleAuthDefault), not overridden here.
		Name:    "SEC_DEFAULT_CRYPTO_METHODS",
		Default: "AES",
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
