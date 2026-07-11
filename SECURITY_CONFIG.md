# Security Configuration Implementation

This document describes the implementation of security configuration mapping from HTCondor configuration parameters to the cedar SecurityConfig struct, along with known deficiencies and areas for future improvement.

## Implementation Summary

The `GetSecurityConfig` function in `security.go` reads HTCondor's `SEC_*` configuration parameters and produces a `SecurityConfig` struct compatible with the cedar protocol library (`github.com/bbockelm/cedar/security`).

### Key Features

1. **Context-Based Configuration**: Supports different security contexts (CLIENT, READ, WRITE, ADMINISTRATOR, etc.)
2. **Fallback to Defaults**: Context-specific settings fall back to `SEC_DEFAULT_*` parameters
3. **Security Level Mapping**: Maps HTCondor security levels (REQUIRED, PREFERRED, OPTIONAL, NEVER) to cedar types
4. **Authentication Methods**: Supports SSL, KERBEROS, PASSWORD, FS, IDTOKENS, SCITOKENS, TOKEN, ANONYMOUS
5. **Encryption Methods**: Supports AES, BLOWFISH, 3DES
6. **SSL Certificate Configuration**: Reads and maps SSL certificate paths (AUTH_SSL_CLIENT_CERTFILE, etc.)
7. **Token Directory Configuration**: Reads and maps token directory locations (SEC_TOKEN_DIRECTORY)

### Configuration Parameters Supported

**Authentication:**
- `SEC_<context>_AUTHENTICATION` (security level)
- `SEC_<context>_AUTHENTICATION_METHODS` (comma-separated list)
- `SEC_DEFAULT_AUTHENTICATION`
- `SEC_DEFAULT_AUTHENTICATION_METHODS`

**Encryption:**
- `SEC_<context>_ENCRYPTION` (security level)
- `SEC_<context>_CRYPTO_METHODS` (comma-separated list)
- `SEC_DEFAULT_ENCRYPTION`
- `SEC_DEFAULT_CRYPTO_METHODS`

**Integrity:**
- `SEC_<context>_INTEGRITY` (security level)
- `SEC_DEFAULT_INTEGRITY`

**SSL Certificates:**
- `AUTH_SSL_CLIENT_CERTFILE`
- `AUTH_SSL_CLIENT_KEYFILE`
- `AUTH_SSL_CLIENT_CAFILE`

**Token Authentication:**
- `SEC_TOKEN_DIRECTORY`

## Known Deficiencies

### 1. Missing SSL Configuration Parameters

**Not Yet Implemented:**
- `AUTH_SSL_SERVER_CERTFILE` - Server certificate file path
- `AUTH_SSL_SERVER_KEYFILE` - Server key file path
- `AUTH_SSL_SERVER_CAFILE` - Server CA file path
- `AUTH_SSL_REQUIRE_CLIENT_CERTIFICATE` - Whether to require client certificates
- `AUTH_SSL_CLIENT_USE_DEFAULT_CAS` - Use system default CAs
- `AUTH_SSL_SERVER_USE_DEFAULT_CAS` - Use system default CAs
- `AUTH_SSL_ALLOW_CLIENT_PROXY` - Allow proxy certificates
- `AUTH_SSL_USE_VOMS_IDENTITY` - Use VOMS identity
- `AUTH_SSL_AUTOGENERATE_CERTFILE` - Auto-generate certificate location
- `AUTH_SSL_AUTOGENERATE_KEYFILE` - Auto-generate key location

**Impact**: SSL authentication will work with basic client certificates but advanced SSL features (server-side config, proxy certificates, VOMS, auto-generation) are not configurable.

**Fix**: Add additional fields to SecurityConfig or create SSL-specific configuration function.

### 2. Missing Token Configuration Parameters

**Not Yet Implemented:**
- `SEC_TOKEN_SYSTEM_DIRECTORY` - System-wide token directory (default: /etc/condor/tokens.d)
- `SEC_PASSWORD_DIRECTORY` - Password directory for pool passwords
- `SEC_TOKEN_POOL_SIGNING_KEY_FILE` - Pool signing key file path
- `SEC_TOKEN_MAX_AGE` - Maximum token age in seconds
- `SEC_ENABLE_IMPERSONATION_TOKENS` - Enable impersonation tokens
- `SEC_ENABLE_TOKEN_FETCH` - Enable token fetching
- `SEC_ENABLE_TOKEN_REQUEST` - Enable token requests
- `SEC_SCITOKENS_ALLOW_FOREIGN_TOKEN_TYPES` - Allow foreign token types

**Impact**: Token authentication will work with basic token files but advanced token features (pool signing, token management, impersonation) are not configurable.

**Fix**: Extend SecurityConfig with token-specific fields or add token configuration helper functions.

### 3. Authorization Settings Not Mapped

**Not Implemented:**
- `ALLOW_READ`, `DENY_READ` - Read access control
- `ALLOW_WRITE`, `DENY_WRITE` - Write access control
- `ALLOW_ADMINISTRATOR`, `DENY_ADMINISTRATOR` - Administrator access control
- `ALLOW_CONFIG`, `DENY_CONFIG` - Configuration access control
- `ALLOW_DAEMON`, `DENY_DAEMON` - Daemon access control
- `ALLOW_NEGOTIATOR`, `DENY_NEGOTIATOR` - Negotiator access control
- `ALLOW_ADVERTISE_MASTER`, `DENY_ADVERTISE_MASTER` - Master ad publishing control
- `ALLOW_ADVERTISE_STARTD`, `DENY_ADVERTISE_STARTD` - Startd ad publishing control
- `ALLOW_ADVERTISE_SCHEDD`, `DENY_ADVERTISE_SCHEDD` - Schedd ad publishing control
- `ALLOW_CLIENT`, `DENY_CLIENT` - Client access control

**Impact**: Authorization policies are separate from SecurityConfig. These need to be handled at a higher level in the application or require a separate authorization configuration function.

**Fix**: Create separate authorization configuration function or integrate with higher-level HTCondor daemon configuration.

### 4. Authentication Methods Not Supported by Cedar

**HTCondor Methods Not in Cedar:**
- `NTSSPI` - Windows NT Security Support Provider Interface
- `MUNGE` - MUNGE UID/GID authentication
- `CLAIMTOBE` - Unauthenticated claim-to-be
- `FS_REMOTE` - Remote filesystem authentication (currently mapped to `FS`)
- `GSI` - Grid Security Infrastructure (deprecated)

**Impact**: These authentication methods are silently skipped when parsing configuration. Systems relying on these methods will not have them available.

**Fix**: Either add these methods to cedar or provide clear documentation about unsupported methods.

### 5. Context-Specific Configuration Limited

**Current Support:**
- Only reads `SEC_<context>_*` and `SEC_DEFAULT_*`
- Does not implement full context hierarchy

**Missing Context Support:**
- No support for command-specific overrides (e.g., `SEC_<context>_<command>_*`)
- No support for user-specific overrides
- No support for network interface-specific overrides

**Impact**: Complex security policies with fine-grained control cannot be fully expressed.

**Fix**: Implement hierarchical configuration lookup with proper precedence rules.

### 6. Negotiation Settings Not Mapped

**Not Implemented:**
- `SEC_<context>_NEGOTIATION` - Negotiation security level
- `SEC_DEFAULT_NEGOTIATION` - Default negotiation security level
- Session management parameters
- Connection timeout parameters

**Impact**: Security session negotiation uses defaults from cedar library rather than HTCondor configuration.

**Fix**: Add negotiation parameters to SecurityConfig or create negotiation-specific configuration.

### 7. Kerberos Configuration Not Mapped

**Not Implemented:**
- Kerberos principal configuration
- Kerberos keytab paths
- Kerberos credential refresh settings
- Kerberos ticket lifetime settings

**Impact**: Kerberos authentication method is available but not configurable through HTCondor configuration.

**Fix**: Add Kerberos-specific configuration fields and parsing.

### 8. Session Management Not Configured

**Not Implemented:**
- `SEC_SESSION_DURATION` - Session duration
- `SEC_SESSION_LEASE` - Session lease time
- `SEC_USE_FAMILY_SESSION` - Use family sessions
- `SEC_TCP_SESSION_TIMEOUT` - TCP session timeout

**Impact**: Session management uses cedar defaults rather than HTCondor configuration.

**Fix**: Add session management fields to SecurityConfig.

## Recommendations for Follow-up Work

### Priority 1 (Critical for Production Use)
1. Implement SSL certificate validation settings (REQUIRE_CLIENT_CERTIFICATE, etc.)
2. Add support for SEC_TOKEN_SYSTEM_DIRECTORY
3. Document unsupported authentication methods clearly

### Priority 2 (Enhanced Functionality)
1. Create authorization configuration function (ALLOW_*/DENY_*)
2. Add token signing key configuration
3. Implement Kerberos configuration parameters
4. Add session management configuration

### Priority 3 (Advanced Features)
1. Support full context hierarchy
2. Add command-specific security overrides
3. Support network interface-specific settings
4. Add NTSSPI support for Windows (if targeting Windows)

## Testing Status

All implemented features have comprehensive unit tests in `security_test.go`:
- ✅ Default configuration
- ✅ Context-specific configuration (CLIENT)
- ✅ Fallback to DEFAULT configuration
- ✅ SSL certificate mapping
- ✅ Token directory mapping
- ✅ Multiple authentication methods
- ✅ Multiple encryption methods
- ✅ Security level mapping
- ✅ Case-insensitive parsing
- ✅ Different security contexts (READ, WRITE, etc.)

## Usage Example

```go
package main

import (
    "log"
    "github.com/bbockelm/cedar/commands"
    "github.com/bbockelm/golang-htcondor"
    "github.com/bbockelm/golang-htcondor/config"
)

func main() {
    // Load HTCondor configuration
    cfg, err := config.New()
    if err != nil {
        log.Fatal(err)
    }

    // Get security configuration for CLIENT context
    secConfig, err := htcondor.GetSecurityConfig(cfg, commands.QUERY_STARTD_ADS, "CLIENT")
    if err != nil {
        log.Fatal(err)
    }

    // Use secConfig with cedar authenticator
    // auth := security.NewAuthenticator(secConfig, stream)
    // ...
}
```

## References

- HTCondor Security Documentation: https://htcondor.readthedocs.io/en/main/admin-manual/security.html
- Cedar Security Package: github.com/bbockelm/cedar/security
- HTCondor Configuration Parameters: https://htcondor.readthedocs.io/en/main/admin-manual/configuration-macros.html
