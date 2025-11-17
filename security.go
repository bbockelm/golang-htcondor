package htcondor

import (
	"context"
	"fmt"
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

	// Get token file/directory if token authentication is enabled
	for _, method := range secConfig.AuthMethods {
		if method == security.AuthToken || method == security.AuthIDTokens || method == security.AuthSciTokens {
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

	// Return HTCondor's default based on platform
	switch feature {
	case "AUTHENTICATION_METHODS":
		return getDefaultAuthMethods()
	case "CRYPTO_METHODS":
		return "AES" // HTCondor 9.0+ default
	}

	return ""
}

// getDefaultAuthMethods returns platform-appropriate default authentication methods
func getDefaultAuthMethods() string {
	// Unix/Linux/macOS default: FS, IDTOKENS, KERBEROS
	// Windows default: NTSSPI, IDTOKENS, KERBEROS
	// We'll use Unix default since this is primarily targeting Unix systems
	// Note: HTCondor also includes FS_REMOTE by default, but cedar maps it to FS
	return "FS,IDTOKENS"
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

// mapAuthMethods converts comma-separated HTCondor auth methods to cedar AuthMethod slice
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
		case "IDTOKENS":
			result = append(result, security.AuthIDTokens)
		case "SCITOKENS":
			result = append(result, security.AuthSciTokens)
		case "TOKEN":
			result = append(result, security.AuthToken)
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
