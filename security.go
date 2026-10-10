package htcondor

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"weak"

	"github.com/bbockelm/cedar/security"
	"github.com/bbockelm/golang-htcondor/config"
	"github.com/bbockelm/golang-htcondor/ratelimit"
)

// globalDefaultConfig holds a pointer to the default HTCondor configuration.
// Access is thread-safe via atomic operations.
// This is loaded lazily on first use or via explicit ReloadDefaultConfig() call.
var globalDefaultConfig atomic.Pointer[config.Config]

// globalRateLimitManager holds a pointer to the global rate limiter manager.
// Access is thread-safe via atomic operations.
// This is loaded lazily based on the global configuration.
var globalRateLimitManager atomic.Pointer[ratelimit.Manager]

// loadDefaultConfig attempts to load the default HTCondor configuration.
// Returns nil if loading fails (e.g., config files not found).
func loadDefaultConfig() *config.Config {
	cfg, err := config.New()
	if err != nil {
		return nil
	}
	return cfg
}

// getDefaultConfig returns the global default configuration, loading it lazily if needed.
// Returns nil if no default configuration is available.
func getDefaultConfig() *config.Config {
	cfg := globalDefaultConfig.Load()
	if cfg == nil {
		// Attempt lazy load
		cfg = loadDefaultConfig()
		if cfg != nil {
			globalDefaultConfig.Store(cfg)
		}
	}
	return cfg
}

// NewClientSecurityConfig builds a SecurityConfig for a client→daemon
// connection, starting from the configured SEC_<context>_AUTHENTICATION_METHODS
// (or SEC_DEFAULT_*) in the loaded HTCondor configuration and overlaying
// the supplied token, peer name, and session cache. This is the
// preferred constructor for any daemon-side path that needs to talk to
// another condor daemon — call sites that hand-build a SecurityConfig
// literal will lock themselves into a specific auth-method list and
// silently override what the operator configured.
//
// Method-list construction:
//
//   - Starts from the configured SEC_<context>_AUTHENTICATION_METHODS
//     (falling back to SEC_DEFAULT_*, then to a sensible compiled-in
//     fallback that includes SSL alongside TOKEN/FS). Read through
//     loadClientSecurityDefaults when a token was supplied, and through
//     GetSecurityConfigOrDefault -- which may instead return a credential
//     the context already carries -- when none was.
//   - When a non-empty token is supplied, guarantees TOKEN appears in
//     the method list — prepended if absent — so the supplied token is
//     actually offered to the peer, and drops every method that would
//     identify this process instead (FS, KERBEROS, PASSWORD) or no one
//     (ANONYMOUS). AuthIDTokens already counts as TOKEN at the wire
//     level, so we don't duplicate.
//
// Field overlays:
//
//   - Token: set when token != "". TokenFile, TokenDir, CertFile and
//     KeyFile are then cleared and Authentication is REQUIRED, so the
//     token is the only credential the connection can present.
//   - SessionCache: set when sessionCache != nil; otherwise cedar uses
//     its global cache.
//   - PeerName: populated from the argument, used for session-cache
//     lookups and SSL hostname verification.
//
// Other security parameters (CryptoMethods, Authentication/Encryption/
// Integrity levels, SSL credentials when SSL is configured) come from
// GetSecurityConfig — same code path that condor_config_val sees.
//
// command is the cedar/commands constant for the RPC the caller is
// about to dispatch. Used for session-cache lookups via LookupByCommand;
// stored on the resulting SecurityConfig.
//
// secContext should be one of "CLIENT", "READ", "WRITE",
// "ADMINISTRATOR", "DAEMON", "NEGOTIATOR" — the same context strings
// HTCondor uses for SEC_<context>_* knob lookup. Empty defaults to
// "CLIENT".
func NewClientSecurityConfig(
	ctx context.Context,
	token string,
	peerName string,
	command int,
	secContext string,
	sessionCache *security.SessionCache,
) (*security.SecurityConfig, error) {
	return NewClientSecurityConfigWithConfig(ctx, nil, token, peerName, command, secContext, sessionCache)
}

// NewClientSecurityConfigWithConfig is NewClientSecurityConfig reading the
// SEC_* settings from cfg instead of the process-wide default configuration.
// A nil cfg is exactly NewClientSecurityConfig. cfg decides only where the
// configuration comes from; which credential is presented is decided the same
// way for either.
func NewClientSecurityConfigWithConfig(
	ctx context.Context,
	cfg *config.Config,
	token string,
	peerName string,
	command int,
	secContext string,
	sessionCache *security.SessionCache,
) (*security.SecurityConfig, error) {
	if secContext == "" {
		secContext = "CLIENT"
	}
	// Two different questions used to share one call here. With an explicit
	// token the caller has already decided whose credential this connection
	// presents, so the only thing wanted from the configuration is the SEC_*
	// base to overlay it on -- loadClientSecurityDefaults, which resolves no
	// identity. Without one, this really is "authenticate as whoever the
	// context says", which is GetSecurityConfigOrDefault's job.
	//
	// Consulting the context on the token path was also wrong on its own
	// terms: it copied *someone else's* resolved config -- SessionCache,
	// SecurityTag, SSL client cert, TokenDir -- and then swapped the token
	// underneath it. Every caller that mints a token for a second identity
	// (superuser impersonation, the SSH gateway, the authz probe) has had to
	// remember to overwrite SecurityTag afterwards, because cedar's client
	// session cache is keyed on it and inheriting one means resuming a
	// session that was authenticated as somebody else. Not inheriting the
	// config in the first place removes the thing they were compensating for.
	var secConfig *security.SecurityConfig
	var err error
	if token != "" {
		secConfig, err = loadClientSecurityDefaults(cfg, command, secContext, peerName)
	} else {
		secConfig, err = GetSecurityConfigOrDefault(ctx, cfg, command, secContext, peerName)
	}
	if err != nil {
		return nil, err
	}
	if token != "" {
		// A supplied token means this connection acts on behalf of
		// whoever holds it, so it must not be able to authenticate as
		// the process running this code instead.
		//
		// Ordering alone does not achieve that, and the earlier version
		// of this code — which merely moved AuthToken to the front —
		// did not work: the two sides negotiate in the SERVER's
		// preference order, so a schedd
		// configured SEC_DEFAULT_AUTHENTICATION_METHODS = FS,TOKEN —
		// the ordinary access-point setting — picks FS and maps the
		// connection to the daemon's own account while the forwarded
		// token sits unused on the wire. Everything downstream that
		// asks "who is this connection?" then answers with the service
		// account, and on an AP that account is a queue superuser, so
		// the schedd drops owner filtering entirely and a "my jobs"
		// query returns every user's jobs.
		//
		// So the offered list keeps only methods that present the
		// caller's token or nothing of ours: TOKEN, moved to the front,
		// then SCITOKENS and SSL if configured. Everything else
		// identifies the process -- FS and CLAIMTOBE by its OS user,
		// KERBEROS by its credential cache, PASSWORD by the pool
		// password -- and ANONYMOUS (AuthNone) would let the connection
		// complete with no identity at all. SSL stays because some pools
		// need it alongside IDTOKENS (a collector query whose token kid
		// does not match), but only as an anonymous client that checks
		// the server's certificate: the client cert is cleared below.
		//
		// webapi/httpserver has carried this same rule for its session
		// path since jobs submitted through a session cookie came out
		// owned by the OS user instead of the JWT subject. That fix
		// never reached here, so every other delegated caller — the MCP
		// tools among them — kept authenticating as the daemon.
		filtered := make([]security.AuthMethod, 0, len(secConfig.AuthMethods)+1)
		filtered = append(filtered, security.AuthToken)
		for _, m := range secConfig.AuthMethods {
			if m == security.AuthSciTokens || m == security.AuthSSL {
				filtered = append(filtered, m)
			}
		}
		secConfig.AuthMethods = filtered
		secConfig.Token = token
		// The configuration's own credentials belong to this process.
		// Cedar treats Token as the first candidate, not the only one:
		// when it is incompatible with the peer (another issuer, an
		// unknown kid) or expired, it goes on to TokenFile and TokenDir
		// -- for a daemon, SEC_TOKEN_SYSTEM_DIRECTORY -- and sends
		// whatever compatible token it finds there, and the SSL
		// handshake presents CertFile/KeyFile. Either way the peer would
		// see this process rather than the caller.
		secConfig.TokenFile = ""
		secConfig.TokenDir = ""
		secConfig.CertFile = ""
		secConfig.KeyFile = ""
		// The caller brought a credential to be identified by, so the
		// connection must authenticate; at the configured default of
		// OPTIONAL a peer that also says OPTIONAL skips authentication.
		secConfig.Authentication = security.SecurityRequired
	}
	if sessionCache != nil {
		secConfig.SessionCache = sessionCache
	}
	return secConfig, nil
}

// hasAuthMethod reports whether m is in list. Small helper so callers
// that need to overlay additional methods on top of NewClientSecurityConfig's
// configured-base list can do so idempotently — e.g. file_transfer
// adding AuthNone for anonymous transfers, or the keepalive path
// adding AuthFS as an in-process fallback.
func hasAuthMethod(list []security.AuthMethod, m security.AuthMethod) bool {
	for _, x := range list {
		if x == m {
			return true
		}
	}
	return false
}

// GetDefaultConfig returns the global default HTCondor configuration,
// loading it from CONDOR_CONFIG on first access. Returns nil if no
// config is reachable (which happens in unit tests and any process
// that runs outside an HTCondor install).
//
// Exposed so callers in other packages (notably httpserver) can build
// SecurityConfigs that respect SEC_CLIENT_AUTHENTICATION_METHODS,
// AUTH_SSL_CLIENT_CERTFILE, etc., without re-implementing the loader.
func GetDefaultConfig() *config.Config {
	return getDefaultConfig()
}

// LookupSSLClientCredentials reads the AUTH_SSL_CLIENT_CERTFILE,
// AUTH_SSL_CLIENT_KEYFILE, and AUTH_SSL_CLIENT_CAFILE settings from the
// global HTCondor configuration. Returns ok=true only when both cert
// and key paths are configured (CA may legitimately be empty when the
// system trust store is used).
//
// Intended for callers that want to add SSL as a secondary auth method
// to a hand-built SecurityConfig without going through the full
// GetSecurityConfig path (which only loads SSL credentials when the
// configured AuthenticationMethods list already names SSL).
func LookupSSLClientCredentials() (certFile, keyFile, caFile string, ok bool) {
	return LookupSSLClientCredentialsWithConfig(nil)
}

// LookupSSLClientCredentialsWithConfig is LookupSSLClientCredentials reading
// cfg instead of the process-wide default configuration. A nil cfg is exactly
// LookupSSLClientCredentials.
func LookupSSLClientCredentialsWithConfig(cfg *config.Config) (certFile, keyFile, caFile string, ok bool) {
	if cfg == nil {
		cfg = getDefaultConfig()
	}
	if cfg == nil {
		return "", "", "", false
	}
	if v, found := cfg.Get("AUTH_SSL_CLIENT_CERTFILE"); found {
		certFile = v
	}
	if v, found := cfg.Get("AUTH_SSL_CLIENT_KEYFILE"); found {
		keyFile = v
	}
	if v, found := cfg.Get("AUTH_SSL_CLIENT_CAFILE"); found {
		caFile = v
	}
	return certFile, keyFile, caFile, certFile != "" && keyFile != ""
}

// ReloadDefaultConfig reloads the global default HTCondor configuration.
// This is useful when configuration files change and need to be re-read.
// If loading fails, the global config is set to nil.
func ReloadDefaultConfig() {
	cfg := loadDefaultConfig()
	globalDefaultConfig.Store(cfg)

	// Also reload rate limiter from new config
	if cfg != nil {
		manager := ratelimit.ConfigFromHTCondor(cfg)
		globalRateLimitManager.Store(manager)
	} else {
		globalRateLimitManager.Store(nil)
	}
}

// getRateLimitManager returns the global rate limiter manager, loading it lazily if needed.
// Returns nil if no configuration is available (which means unlimited).
func getRateLimitManager() *ratelimit.Manager {
	manager := globalRateLimitManager.Load()
	if manager == nil {
		// Try to load from config
		cfg := getDefaultConfig()
		if cfg != nil {
			manager = ratelimit.ConfigFromHTCondor(cfg)
			globalRateLimitManager.Store(manager)
		}
	}
	return manager
}

// configRateLimitManagers holds the rate limiter built for each explicit
// configuration a client object was given (see rateLimitManagerFor), keyed by
// a weak pointer so that an entry goes away with its configuration.
var configRateLimitManagers sync.Map // weak.Pointer[config.Config] -> *ratelimit.Manager

// rateLimitManagerFor returns the rate limiter for a client object whose
// configuration is cfg. A nil cfg is the process-wide limiter
// (getRateLimitManager). An explicit cfg gets a limiter built from that
// configuration's *_QUERY_RATE_LIMIT knobs, never the global one, and shared by
// every object carrying the same *config.Config, so that -- like the global
// limiter -- it limits the traffic of everything using that configuration
// rather than of one object (a Schedd recreated after a restart keeps its
// budget).
func rateLimitManagerFor(cfg *config.Config) *ratelimit.Manager {
	if cfg == nil {
		return getRateLimitManager()
	}
	key := weak.Make(cfg)
	if m, ok := configRateLimitManagers.Load(key); ok {
		return m.(*ratelimit.Manager)
	}
	m, loaded := configRateLimitManagers.LoadOrStore(key, ratelimit.ConfigFromHTCondor(cfg))
	if !loaded {
		runtime.AddCleanup(cfg, func(k weak.Pointer[config.Config]) {
			configRateLimitManagers.Delete(k)
		}, key)
	}
	return m.(*ratelimit.Manager)
}

// daemonCredentialCache is the process-wide privileged credential reader shared by every
// security config this package builds, inbound and outbound. Sharing one cache means
// cached credentials (and a single SIGHUP-driven Reload) cover all connections, and it
// gives outbound client configs -- which are rebuilt per call, e.g. the master's
// DC_SET_READY -- the same root-capable reader the server side already had. On a process
// that is not privileged, droppriv.OpenAsRoot degrades to reading as the current user, so
// wiring it unconditionally is safe for user tools too.
var daemonCredentialCache = NewCredentialCache()

// Package-level helpers in cedar that read a credential without a SecurityConfig
// to consult -- security.GenerateJWT, which is handed a key directory and a key
// id -- go through the same reader. Without this a daemon that has dropped to
// the condor account mints tokens by reading /etc/condor/passwords.d/POOL with a
// plain os.ReadFile, which is root:root 0600, and fails with "permission
// denied" while every other credential read succeeds.
func init() {
	security.SetDefaultCredentialReader(daemonCredentialCache)
}

// runningAsDaemon reports whether this process is an HTCondor daemon that can read
// root-only credentials (the SSL host key, the system token directory): it is running as
// root, or it was launched by condor_master (CONDOR_INHERIT set) and therefore started as
// root before dropping privilege. This mirrors the "is this a daemon" test HTCondor uses
// to choose SEC_TOKEN_SYSTEM_DIRECTORY over the per-user token directory. It is a var so
// tests can force the non-daemon path (unit tests frequently run as root under CI).
var runningAsDaemon = func() bool {
	return os.Geteuid() == 0 || os.Getenv("CONDOR_INHERIT") != ""
}

// condorUsername returns the condor service account name (CONDOR_USER, default "condor"),
// used by FS auth to map a root-owned marker to the condor identity.
func condorUsername(cfg *config.Config) string {
	if cfg != nil {
		if v, ok := cfg.Get("CONDOR_USER"); ok {
			if s := strings.TrimSpace(v); s != "" {
				return s
			}
		}
	}
	return "condor"
}

// fsAuthDir reads an FS-auth base-directory knob (FS_LOCAL_DIR / FS_REMOTE_DIR), trimmed, or
// "" when unset -- which leaves cedar's on-the-wire default (/tmp). Populating this is what
// lets a site running e.g. FS_LOCAL_DIR=/dev/shm authenticate over FS: cedar validates the
// peer's marker path against the configured base instead of a hardcoded /tmp.
func fsAuthDir(cfg *config.Config, key string) string {
	if cfg != nil {
		if v, ok := cfg.Get(key); ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// configUIDDomain reads UID_DOMAIN, trimmed, or "" when unset.
func configUIDDomain(cfg *config.Config) string {
	if cfg != nil {
		if v, ok := cfg.Get("UID_DOMAIN"); ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// fsRootToCondor reads FS_ROOT_TO_CONDOR as a tri-state: nil (unset) leaves cedar's
// default (enabled, matching HTCondor); an explicit value overrides it.
func fsRootToCondor(cfg *config.Config) *bool {
	if cfg == nil {
		return nil
	}
	// A nil return leaves cedar's default (enabled) in place. Since the
	// v25.13.2 param_info.in refresh this is mostly unreachable: HTCondor now
	// publishes default=true for this knob, so Get resolves it from the
	// generated table even when no operator set it. Both paths mean enabled.
	v, ok := cfg.Get("FS_ROOT_TO_CONDOR")
	if !ok {
		return nil
	}
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "":
		return nil
	case "true", "t", "1", "yes", "y", "on":
		b := true
		return &b
	default:
		b := false
		return &b
	}
}

// GetSecurityConfig creates a SecurityConfig from HTCondor configuration.
// It reads security-related parameters like SEC_CLIENT_AUTHENTICATION, SEC_DEFAULT_AUTHENTICATION,
// SEC_CLIENT_AUTHENTICATION_METHODS, etc., and maps them to the cedar SecurityConfig struct.
//
// The function follows HTCondor's security configuration pattern:
//   - SEC_<context>_<feature> where context is CLIENT, READ, WRITE, etc.
//   - Falls back to SEC_DEFAULT_* if context-specific settings are not found
//   - Supports REQUIRED, PREFERRED, OPTIONAL, NEVER security levels
//   - Supports multiple authentication methods (SSL, KERBEROS, TOKEN, etc.)
//   - Supports multiple encryption methods (AES, BLOWFISH, 3DES)
//
// Parameters:
//   - cfg: HTCondor configuration object
//   - command: The command to be executed (from cedar/commands package)
//   - context: Security context ("CLIENT", "READ", "WRITE", "ADMINISTRATOR", etc.)
//
// Returns:
//   - *security.SecurityConfig: Cedar security configuration
//   - error: Any configuration error encountered
//
// Deficiencies (to be addressed in follow-up):
//   - Authorization settings (ALLOW_READ, DENY_WRITE, etc.) are separate from SecurityConfig
//   - Context-specific overrides beyond CLIENT not yet fully implemented
//   - NEGOTIATION security level not yet mapped
func GetSecurityConfig(cfg *config.Config, command int, context string) (*security.SecurityConfig, error) {
	if context == "" {
		context = "CLIENT"
	}

	secConfig := &security.SecurityConfig{
		Command: command,
		// Read credentials (SSL key/cert, token files, and -- via
		// CredentialCache.ListCredentialDir -- the token directory) through the
		// privileged reader, so a daemon that dropped to a service account can still
		// read root-owned 0600 credentials. Without this, an outbound auth (e.g. the
		// master's DC_SET_READY) falls back to an unprivileged os.ReadFile and fails
		// on /etc/grid-security/hostkey.pem and /etc/condor/tokens.d.
		Credentials: daemonCredentialCache,
		// FS auth: create the marker as condor (client, via droppriv) and map a
		// root-owned marker to condor (server), so a tool or daemon run as root
		// authenticates as condor rather than root -- mirroring C++ set_condor_priv()
		// and FS_ROOT_TO_CONDOR. On an unprivileged process the runner is a no-op.
		CondorUsername:   condorUsername(cfg),
		CondorPrivRunner: daemonCondorPrivRunner,
		FSRootToCondor:   fsRootToCondor(cfg),
		// FS_LOCAL_DIR / FS_REMOTE_DIR: the base directory the FS / FS_REMOTE marker is
		// created under. Empty leaves cedar's default (/tmp). Without this a site running
		// e.g. FS_LOCAL_DIR=/dev/shm fails FS auth -- the peer hands out a /dev/shm/FS_...
		// path and the client rejects anything not under /tmp.
		FSLocalDir:  fsAuthDir(cfg, "FS_LOCAL_DIR"),
		FSRemoteDir: fsAuthDir(cfg, "FS_REMOTE_DIR"),
		// UID_DOMAIN: the domain of an FS or CLAIMTOBE identity (user@UID_DOMAIN),
		// on the server for the peer it authenticates and on the client for the
		// name CLAIMTOBE claims, and of a mapped name without one. Empty leaves
		// cedar's fallback, the host name, which is what UID_DOMAIN defaults to.
		UIDDomain: configUIDDomain(cfg),
	}

	// Get authentication level
	authLevel := getSecurityLevel(cfg, context, "AUTHENTICATION")
	secConfig.Authentication = mapSecurityLevel(authLevel)

	// Get encryption level
	encLevel := getSecurityLevel(cfg, context, "ENCRYPTION")
	secConfig.Encryption = mapSecurityLevel(encLevel)

	// Get integrity level
	intLevel := getSecurityLevel(cfg, context, "INTEGRITY")
	secConfig.Integrity = mapSecurityLevel(intLevel)

	// Get authentication methods
	authMethods := getSecurityMethods(cfg, context, "AUTHENTICATION_METHODS")
	secConfig.AuthMethods = mapAuthMethods(authMethods)

	// Get crypto methods
	cryptoMethods := getSecurityMethods(cfg, context, "CRYPTO_METHODS")
	secConfig.CryptoMethods = mapCryptoMethods(cryptoMethods)

	// Get SSL certificate/key paths if SSL authentication is enabled
	for _, method := range secConfig.AuthMethods {
		if method == security.AuthSSL {
			if certFile, ok := cfg.Get("AUTH_SSL_CLIENT_CERTFILE"); ok {
				secConfig.CertFile = certFile
			}
			if keyFile, ok := cfg.Get("AUTH_SSL_CLIENT_KEYFILE"); ok {
				secConfig.KeyFile = keyFile
			}
			if caFile, ok := cfg.Get("AUTH_SSL_CLIENT_CAFILE"); ok {
				secConfig.CAFile = caFile
			}
			break
		}
	}

	// Get token file/directory if token authentication is enabled.
	// AuthIDTokens isn't checked here — mapAuthMethods folds the
	// IDTOKENS config string into AuthToken so cedar serializes it
	// on the wire as "TOKEN".
	for _, method := range secConfig.AuthMethods {
		if method == security.AuthToken || method == security.AuthSciTokens {
			if tokenDir, ok := cfg.Get("SEC_TOKEN_DIRECTORY"); ok && strings.TrimSpace(tokenDir) != "" {
				// An explicit SEC_TOKEN_DIRECTORY always wins (daemon or tool).
				secConfig.TokenDir = strings.TrimSpace(tokenDir)
			} else if runningAsDaemon() {
				// A daemon with no explicit token directory reads the system token
				// directory (SEC_TOKEN_SYSTEM_DIRECTORY, default /etc/condor/tokens.d),
				// matching HTCondor's daemon-vs-user selection in condor_auth_passwd.
				// The privileged reader above makes this root-only directory readable.
				if sysDir, ok := cfg.Get("SEC_TOKEN_SYSTEM_DIRECTORY"); ok && strings.TrimSpace(sysDir) != "" {
					secConfig.TokenDir = strings.TrimSpace(sysDir)
				}
			}
			// Note: TokenFile is typically used for single-token scenarios
			// In practice, HTCondor usually uses TokenDir with multiple tokens
			break
		}
	}

	return secConfig, nil
}

// GetServerSecurityConfig builds a *server-side* SecurityConfig from the
// HTCondor configuration. It takes the same auth/crypto methods and security
// levels as GetSecurityConfig (so the server enforces the pool's SEC_* policy),
// and additionally loads the credentials a server needs to *verify* incoming
// authentications rather than to present its own:
//
//   - SSL: the server certificate/key/CA (AUTH_SSL_SERVER_CERTFILE / KEYFILE /
//     CAFILE) instead of the client ones.
//   - TOKEN/IDTOKENS: the signing keys used to validate presented tokens
//     (SEC_TOKEN_POOL_SIGNING_KEY_FILE for the pool key, SEC_PASSWORD_DIRECTORY
//     for named issuer keys), the trust domain (TRUST_DOMAIN, defaulting to
//     UID_DOMAIN), and the maximum token age (SEC_TOKEN_MAX_AGE).
//
// UID_DOMAIN (set by GetSecurityConfig) is the domain of an FS peer's identity,
// user@UID_DOMAIN. A daemon behind a shared port should build its configs with
// daemon.Daemon.ServerSecurityConfig, which also sets the shared-port id.
//
// This is what a Go HTCondor daemon (e.g. a CCB server) should use so it
// authenticates clients with the same policy and keys as the C++ daemons.
func GetServerSecurityConfig(cfg *config.Config, command int, secContext string) (*security.SecurityConfig, error) {
	if secContext == "" {
		secContext = "DEFAULT"
	}
	sc, err := GetSecurityConfig(cfg, command, secContext)
	if err != nil {
		return nil, err
	}

	hasMethod := func(m security.AuthMethod) bool {
		for _, am := range sc.AuthMethods {
			if am == m {
				return true
			}
		}
		return false
	}

	// SSL: replace the client cert/key/CA (loaded by GetSecurityConfig) with the
	// server's own.
	if hasMethod(security.AuthSSL) {
		if v, ok := cfg.Get("AUTH_SSL_SERVER_CERTFILE"); ok {
			sc.CertFile = v
		}
		if v, ok := cfg.Get("AUTH_SSL_SERVER_KEYFILE"); ok {
			sc.KeyFile = v
		}
		if v, ok := cfg.Get("AUTH_SSL_SERVER_CAFILE"); ok {
			sc.CAFile = v
		}
	}

	// TOKEN/IDTOKENS: the keys and trust domain used to verify presented tokens.
	if hasMethod(security.AuthToken) || hasMethod(security.AuthSciTokens) {
		if v, ok := cfg.Get("SEC_TOKEN_POOL_SIGNING_KEY_FILE"); ok {
			sc.TokenPoolSigningKeyFile = v
		}
		if v, ok := cfg.Get("SEC_PASSWORD_DIRECTORY"); ok {
			sc.TokenSigningKeyDir = v
		}
		if v, ok := cfg.Get("SEC_TOKEN_MAX_AGE"); ok {
			if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
				sc.TokenMaxAge = n
			}
		}
		// Trust domain identifies the issuer this pool accepts; it defaults to
		// the pool's UID_DOMAIN when TRUST_DOMAIN is unset.
		if v, ok := cfg.Get("TRUST_DOMAIN"); ok && v != "" {
			sc.TrustDomain = v
		} else if v, ok := cfg.Get("UID_DOMAIN"); ok {
			sc.TrustDomain = v
		}
	}

	// The server's credential files (SSL key/cert, token signing keys) are read as
	// root via droppriv, so they remain readable after the daemon drops to the
	// condor account. GetSecurityConfig already wired the shared, reload-aware
	// daemonCredentialCache; keep it (a SIGHUP Reload then covers server and client
	// reads alike). Callers wire Reload via daemon.OnReconfig (see CredentialReloader).
	sc.Credentials = daemonCredentialCache

	return sc, nil
}

// CredentialReloader is implemented by a SecurityConfig.Credentials value (e.g.
// *CredentialCache) that can drop cached credentials so the next read picks up
// rotated keys / renewed certs. A daemon wires this to its SIGHUP reconfigure.
type CredentialReloader interface {
	Reload()
}

// getSecurityLevel retrieves a security level setting with context and default fallback
// For example: SEC_CLIENT_AUTHENTICATION, falling back to SEC_DEFAULT_AUTHENTICATION
func getSecurityLevel(cfg *config.Config, context, feature string) string {
	// Try context-specific setting first
	contextKey := fmt.Sprintf("SEC_%s_%s", context, feature)
	if value, ok := cfg.Get(contextKey); ok {
		return value
	}

	// Fall back to DEFAULT setting
	defaultKey := fmt.Sprintf("SEC_DEFAULT_%s", feature)
	if value, ok := cfg.Get(defaultKey); ok {
		return value
	}

	// Return HTCondor's default
	switch feature {
	case "AUTHENTICATION":
		return "OPTIONAL"
	case "ENCRYPTION":
		return "OPTIONAL"
	case "INTEGRITY":
		return "OPTIONAL"
	case "NEGOTIATION":
		return "PREFERRED"
	default:
		return "OPTIONAL"
	}
}

// getSecurityMethods retrieves a comma-separated list of security methods
// For example: SEC_CLIENT_AUTHENTICATION_METHODS, falling back to SEC_DEFAULT_AUTHENTICATION_METHODS
func getSecurityMethods(cfg *config.Config, context, feature string) string {
	// An operator's context-specific setting always wins.
	if value, ok := cfg.Get(fmt.Sprintf("SEC_%s_%s", context, feature)); ok && value != "" {
		return value
	}

	switch feature {
	case "AUTHENTICATION_METHODS":
		// An operator's SEC_DEFAULT_AUTHENTICATION_METHODS wins -- but ignore the stale
		// generated-table value (staleGeneratedAuthDefault, from before TOKEN split into
		// IDTOKENS/SCITOKENS) so it cannot shadow the programmatic default. There is no
		// standalone param_info.in default for this key, so a resolved value is either the
		// operator's or that one stale generated artifact.
		methods := getDefaultAuthMethods()
		if v, ok := cfg.Get("SEC_DEFAULT_AUTHENTICATION_METHODS"); ok && v != "" && !isStaleAuthDefault(v) {
			methods = v
		}
		// CLIENT and READ contexts append ANONYMOUS (an auth method that does not actually
		// authenticate) so an encrypted-but-unauthenticated READ works -- matching
		// HTCondor's SEC_CLIENT/READ_AUTHENTICATION_METHODS = $(SEC_DEFAULT_...),ANONYMOUS.
		if context == "CLIENT" || context == "READ" {
			methods = appendMethod(methods, "ANONYMOUS")
		}
		return methods
	case "CRYPTO_METHODS":
		if value, ok := cfg.Get("SEC_DEFAULT_CRYPTO_METHODS"); ok && value != "" {
			return value
		}
		return "AES" // HTCondor 9.0+ default; cedar implements AES-GCM only
	}

	return ""
}

// staleGeneratedAuthDefault is the value the generated param table ships for
// SEC_DEFAULT_AUTHENTICATION_METHODS (param_defaults.go). It predates HTCondor splitting
// TOKEN into IDTOKENS/SCITOKENS and adding SSL, so it must not be treated as a configured
// default; getSecurityMethods substitutes the programmatic default when it sees this value.
const staleGeneratedAuthDefault = "FS,TOKEN"

func isStaleAuthDefault(v string) bool {
	return strings.EqualFold(strings.ReplaceAll(v, " ", ""), staleGeneratedAuthDefault)
}

// appendMethod appends name to a method list if not already present.
func appendMethod(list, name string) string {
	for _, m := range config.SplitConfigList(list) {
		if strings.EqualFold(m, name) {
			return list
		}
	}
	if list == "" {
		return name
	}
	return list + "," + name
}

// getDefaultAuthMethods returns the fallback authentication-methods
// list used when neither SEC_CLIENT_AUTHENTICATION_METHODS nor
// SEC_DEFAULT_AUTHENTICATION_METHODS appears in the on-disk
// configuration. The string mirrors HTCondor's own built-in default
// (verifiable via `condor_config_val -v SEC_DEFAULT_AUTHENTICATION_METHODS`
// on a host with no method overrides — the "<Default>" source line
// shows this same list).
//
// Earlier versions returned just "FS,IDTOKENS". That bit a production
// pool whose CONDOR_CONFIG files set no SEC_*_AUTHENTICATION_METHODS:
// our client offered TOKEN only (FS gets filtered out at the wire
// boundary because remote FS auth doesn't apply), the server's
// IDTOKENS were filtered by `iss`/`kid` mismatch, and the handshake
// failed with "no compatible authentication methods found" even
// though SSL was available on both sides.
// getDefaultAuthMethods returns the default authentication-method list: HTCondor's standard
// precedence (SEC_STD_AUTH_METHOD_NAMES) filtered to the methods this build of cedar can
// actually perform. cedar is the source of truth (security.DefaultAuthMethods), so a method
// whose handshake is unimplemented (PASSWORD today) is never offered -- offering it would
// just make negotiation fail. Yields "FS,IDTOKENS,KERBEROS,SCITOKENS,SSL" today; PASSWORD
// joins automatically once cedar implements it. The names are cedar's config-language
// spellings (IDTOKENS, not the wire name TOKEN); mapAuthMethods handles the mapping.
func getDefaultAuthMethods() string {
	methods := security.DefaultAuthMethods()
	names := make([]string, len(methods))
	for i, m := range methods {
		names[i] = string(m)
	}
	return strings.Join(names, ",")
}

// mapSecurityLevel converts HTCondor security level string to cedar SecurityLevel
func mapSecurityLevel(level string) security.SecurityLevel {
	switch strings.ToUpper(strings.TrimSpace(level)) {
	case "REQUIRED":
		return security.SecurityRequired
	case "PREFERRED":
		return security.SecurityPreferred
	case "OPTIONAL":
		return security.SecurityOptional
	case "NEVER":
		return security.SecurityNever
	default:
		return security.SecurityOptional
	}
}

// mapAuthMethods converts comma-separated HTCondor auth methods to
// cedar AuthMethod slice.
//
// Note on IDTOKENS vs TOKEN: in HTCondor's *config language* IDTOKENS
// is the modern name for the same authentication mechanism whose
// *wire-protocol name* is TOKEN (SecMan::sec_char_to_auth_method maps
// IDTOKENS, IDTOKEN and TOKENS to CAUTH_TOKEN). Every spelling maps to
// cedar's AuthToken, which serializes on the wire as "TOKEN" -- what
// every HTCondor schedd / collector recognizes, and what the C++
// client sends whatever its config says. Since cedar v0.7.5,
// AuthIDTokens is the same method too (the TOKEN bit, sent as
// "TOKEN"); before it, cedar mapped AuthIDTokens to the SciTokens bit
// and sent the literal "IDTOKENS", which an HTCondor peer does not
// recognize. Mapping to AuthToken keeps one name for the method.
func mapAuthMethods(methods string) []security.AuthMethod {
	if methods == "" {
		return []security.AuthMethod{}
	}

	var result []security.AuthMethod
	for _, method := range config.SplitConfigList(methods) {
		method = strings.ToUpper(method)
		switch method {
		case "SSL":
			result = append(result, security.AuthSSL)
		case "KERBEROS":
			result = append(result, security.AuthKerberos)
		case "PASSWORD":
			result = append(result, security.AuthPassword)
		case "FS":
			result = append(result, security.AuthFS)
		case "FS_REMOTE":
			// Cedar doesn't have FS_REMOTE as separate method, map to FS
			result = append(result, security.AuthFS)
		case "TOKEN", "TOKENS", "IDTOKEN", "IDTOKENS":
			// All four config-language spellings collapse to cedar's
			// AuthToken so cedar serializes as "TOKEN" on the wire. C++
			// SecMan::sec_char_to_auth_method accepts every one of these
			// as CAUTH_TOKEN, and real configs use the singular IDTOKEN
			// too -- dropping it silently strips the only method that
			// would succeed. See doc comment above for the full rationale.
			result = append(result, security.AuthToken)
		case "SCITOKENS", "SCITOKEN":
			// C++ accepts both spellings as CAUTH_SCITOKENS.
			result = append(result, security.AuthSciTokens)
		case "NTSSPI":
			// NTSSPI not in cedar's current auth methods (Windows-specific)
			// Skip for now
		case "MUNGE":
			// MUNGE not in cedar's current auth methods
			// Skip for now
		case "CLAIMTOBE":
			// CLAIMTOBE not in cedar's current auth methods
			// Skip for now
		case "ANONYMOUS":
			// Map ANONYMOUS to AuthNone
			result = append(result, security.AuthNone)
		}
	}

	return result
}

// mapCryptoMethods converts comma-separated HTCondor crypto methods to cedar CryptoMethod slice
func mapCryptoMethods(methods string) []security.CryptoMethod {
	if methods == "" {
		return []security.CryptoMethod{}
	}

	var result []security.CryptoMethod
	for _, method := range config.SplitConfigList(methods) {
		method = strings.ToUpper(method)
		switch method {
		case "AES":
			result = append(result, security.CryptoAES)
		case "BLOWFISH":
			result = append(result, security.CryptoBlowfish)
		case "3DES":
			result = append(result, security.Crypto3DES)
		}
	}

	return result
}

// GetSecurityConfigOrDefault retrieves SecurityConfig from context if available,
// otherwise attempts to load from HTCondor configuration, and falls back to defaults.
//
// This function provides consistent SecurityConfig creation across the module:
//  1. Check context for existing SecurityConfig
//  2. If not in context, use provided config or fall back to global default config
//  3. If config available, load from HTCondor configuration
//  4. Fall back to sensible defaults if config is not available
//
// Parameters:
//   - ctx: Context that may contain SecurityConfig
//   - cfg: HTCondor configuration (can be nil, will use global default if available)
//   - command: The command code for the operation
//   - context: Security context ("CLIENT", "READ", "WRITE", etc.)
//   - peerName: Peer name for session cache (e.g., schedd address)
//
// Returns:
//   - *security.SecurityConfig: Cedar security configuration
//   - error: Any configuration error encountered
func GetSecurityConfigOrDefault(ctx context.Context, cfg *config.Config, command int, secContext string, peerName string) (*security.SecurityConfig, error) {
	// 1. Check if SecurityConfig is provided in context
	if ctxSecConfig, ok := GetSecurityConfigFromContext(ctx); ok {
		// Make a copy to avoid modifying the original
		secConfig := &ctxSecConfig
		// Update command for the specific operation
		secConfig.Command = command
		// Set PeerName for session cache lookups if not already set
		if secConfig.PeerName == "" {
			secConfig.PeerName = peerName
		}
		// A credential carried for somebody else is the only one this
		// connection may present. Without this, CEDAR treats the
		// caller's token as the first candidate in a search: if the
		// peer will not accept it -- an issuer that does not match its
		// trust domain, a key it does not know, an expiry -- discovery
		// moves on to this host's own token files and the handshake
		// succeeds as this daemon. The caller's request then runs with
		// an identity they never had.
		//
		// Decided here, from how the context was already classified at
		// the transport, rather than asked of each place that builds a
		// config. That is the whole point: a per-config field is a
		// thing to remember at every call site and every new route,
		// and the evidence is that it does not get remembered. There
		// is nothing to forget if the answer is derived from the
		// origin that is already marked.
		if origin, _ := CredentialOriginFromContext(ctx); origin == OriginUser {
			secConfig.DelegatedCredential = true
		}
		return secConfig, nil
	}

	// 2. No caller credential on the context: everything below this point
	// authenticates as this daemon, so decide first whether that is
	// legitimate for this context. The check sits here rather than inside
	// loadClientSecurityDefaults because both of that function's outcomes
	// are the daemon -- the configured one and the compiled-in fallback,
	// whose FS method plus privileged credential reader authenticate as the
	// daemon's OS user on a same-host schedd with no token involved at all.
	if err := checkDaemonFallbackAllowed(ctx, command, secContext, peerName); err != nil {
		return nil, err
	}
	return loadClientSecurityDefaults(cfg, command, secContext, peerName)
}

// loadClientSecurityDefaults builds a client SecurityConfig out of the
// HTCondor configuration alone: the SEC_* method lists, crypto methods and
// security levels, plus the credential material those methods need. It makes
// no reference to a context and therefore resolves no identity.
//
// Split out of GetSecurityConfigOrDefault because those were two different
// acts sharing one entry point. "Read SEC_CLIENT_AUTHENTICATION_METHODS" is a
// configuration lookup; "decide whose credential goes on the wire" is an
// identity decision, and only the second one has any business consulting the
// context. A caller that already holds an explicit credential -- the token
// argument to NewClientSecurityConfig -- has made the identity decision
// itself and wants nothing from here but the configured base to overlay it
// on.
//
// Note what this still returns when no configuration is reachable at all: a
// method list containing FS, Authentication=OPTIONAL, and
// daemonCredentialCache as the credential reader. On a same-host schedd that
// combination authenticates as the daemon's OS user with no token involved,
// so anything that wants to restrict the daemon identity has to sit in front
// of this function rather than in front of GetSecurityConfig.
func loadClientSecurityDefaults(cfg *config.Config, command int, secContext string, peerName string) (*security.SecurityConfig, error) {
	// If cfg is nil, try the global default config
	if cfg == nil {
		cfg = getDefaultConfig()
	}

	if cfg != nil {
		secConfig, err := GetSecurityConfig(cfg, command, secContext)
		if err != nil {
			return nil, err
		}
		// Set PeerName for session cache lookups
		if secConfig.PeerName == "" {
			secConfig.PeerName = peerName
		}
		return secConfig, nil
	}

	// Fall back to sensible defaults
	return &security.SecurityConfig{
		Command:        command,
		AuthMethods:    []security.AuthMethod{security.AuthSSL, security.AuthToken, security.AuthFS},
		Authentication: security.SecurityOptional,
		CryptoMethods:  []security.CryptoMethod{security.CryptoAES},
		Encryption:     security.SecurityOptional,
		Integrity:      security.SecurityOptional,
		PeerName:       peerName,
		Credentials:    daemonCredentialCache,
	}, nil
}
