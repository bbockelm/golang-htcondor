package htcondor

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync/atomic"

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
//   - Starts from GetSecurityConfigOrDefault, which reads
//     SEC_<context>_AUTHENTICATION_METHODS (falling back to
//     SEC_DEFAULT_*, then to a sensible compiled-in fallback that
//     includes SSL alongside TOKEN/FS).
//   - When a non-empty token is supplied, guarantees TOKEN appears in
//     the method list — prepended if absent — so the supplied token is
//     actually offered to the peer. AuthIDTokens already counts as
//     TOKEN at the wire level, so we don't duplicate.
//
// Field overlays:
//
//   - Token: set when token != "".
//   - SessionCache: set when sessionCache != nil; otherwise cedar uses
//     its global cache.
//   - PeerName: GetSecurityConfigOrDefault populates this from the
//     argument, used for session-cache lookups and SSL hostname
//     verification.
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
	if secContext == "" {
		secContext = "CLIENT"
	}
	secConfig, err := GetSecurityConfigOrDefault(ctx, nil, command, secContext, peerName)
	if err != nil {
		return nil, err
	}
	if token != "" {
		// Ensure cedar's AuthToken is at the FRONT of the method
		// list so the supplied token actually goes on the wire as
		// "TOKEN" first. mapAuthMethods folds the IDTOKENS config
		// string into AuthToken, so an operator with
		// SEC_*_AUTHENTICATION_METHODS = FS,IDTOKENS,SSL ends up
		// with AuthFS first and would silently authenticate via FS
		// before TOKEN was even tried — that defeats the purpose of
		// supplying a token (production deployments lose the FS
		// shortcut anyway, so callers passing a token are explicitly
		// asking for token-based identity). We move AuthToken to
		// position 0 unconditionally and preserve the rest as
		// fallback order.
		filtered := make([]security.AuthMethod, 0, len(secConfig.AuthMethods)+1)
		filtered = append(filtered, security.AuthToken)
		for _, m := range secConfig.AuthMethods {
			if m != security.AuthToken {
				filtered = append(filtered, m)
			}
		}
		secConfig.AuthMethods = filtered
		secConfig.Token = token
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
	cfg := getDefaultConfig()
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
//   - SSL certificate paths (AUTH_SSL_CLIENT_CERTFILE, etc.) not yet mapped
//   - Token directory locations (SEC_TOKEN_DIRECTORY, etc.) not yet mapped
//   - Authorization settings (ALLOW_READ, DENY_WRITE, etc.) are separate from SecurityConfig
//   - Context-specific overrides beyond CLIENT not yet fully implemented
//   - NEGOTIATION security level not yet mapped
func GetSecurityConfig(cfg *config.Config, command int, context string) (*security.SecurityConfig, error) {
	if context == "" {
		context = "CLIENT"
	}

	secConfig := &security.SecurityConfig{
		Command: command,
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
			if tokenDir, ok := cfg.Get("SEC_TOKEN_DIRECTORY"); ok {
				secConfig.TokenDir = tokenDir
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

	// Read the server's credential files (SSL key/cert, token signing keys) as
	// root via droppriv, so they remain readable after the daemon drops to the
	// condor account. The cache supports reload-on-SIGHUP; callers wire its
	// Reload via daemon.OnReconfig (see CredentialReloader).
	sc.Credentials = NewCredentialCache()

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

// appendMethod appends name to a comma-separated method list if not already present.
func appendMethod(list, name string) string {
	for _, m := range strings.Split(list, ",") {
		if strings.EqualFold(strings.TrimSpace(m), name) {
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
// *wire-protocol name* is TOKEN. We want both config strings to
// produce cedar's AuthToken, which serializes on the wire as "TOKEN"
// — that's what every HTCondor schedd / collector recognizes. Mapping
// IDTOKENS to cedar's AuthIDTokens (which serializes as the literal
// "IDTOKENS") makes the schedd's SECMAN drop the offer and fall
// through to whatever is left, typically SSL — see
// cedar/security/auth.go where AuthIDTokens has the comment
// `IDTokens not defined in HTCondor's condor_auth.h, map to
// SciTokens for compatibility`. The C++ HTCondor client always
// sends "TOKEN" regardless of what's in the config; this matches
// that behavior.
func mapAuthMethods(methods string) []security.AuthMethod {
	if methods == "" {
		return []security.AuthMethod{}
	}

	var result []security.AuthMethod
	for _, method := range strings.Split(methods, ",") {
		method = strings.ToUpper(strings.TrimSpace(method))
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
		case "IDTOKENS", "TOKEN":
			// Both config-language spellings collapse to cedar's
			// AuthToken so cedar serializes as "TOKEN" on the wire.
			// See doc comment above for the full rationale.
			result = append(result, security.AuthToken)
		case "SCITOKENS":
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
	for _, method := range strings.Split(methods, ",") {
		method = strings.ToUpper(strings.TrimSpace(method))
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
		return secConfig, nil
	}

	// 2. Try to load from HTCondor configuration if available
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

	// 3. Fall back to sensible defaults
	return &security.SecurityConfig{
		Command:        command,
		AuthMethods:    []security.AuthMethod{security.AuthSSL, security.AuthToken, security.AuthFS},
		Authentication: security.SecurityOptional,
		CryptoMethods:  []security.CryptoMethod{security.CryptoAES},
		Encryption:     security.SecurityOptional,
		Integrity:      security.SecurityOptional,
		PeerName:       peerName,
	}, nil
}
