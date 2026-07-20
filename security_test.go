package htcondor

import (
	"strings"
	"testing"

	"github.com/bbockelm/cedar/security"
	"github.com/bbockelm/golang-htcondor/config"
)

func TestGetSecurityConfig_Defaults(t *testing.T) {
	// Test with empty configuration (should use defaults)
	cfgReader := strings.NewReader("")
	cfg, err := config.NewFromReader(cfgReader)
	if err != nil {
		t.Fatalf("Failed to create config: %v", err)
	}

	secConfig, err := GetSecurityConfig(cfg, 60000, "CLIENT")
	if err != nil {
		t.Fatalf("GetSecurityConfig failed: %v", err)
	}

	// Check defaults
	if secConfig.Authentication != security.SecurityOptional {
		t.Errorf("Expected Authentication=SecurityOptional, got %v", secConfig.Authentication)
	}
	if secConfig.Encryption != security.SecurityOptional {
		t.Errorf("Expected Encryption=SecurityOptional, got %v", secConfig.Encryption)
	}
	if secConfig.Integrity != security.SecurityOptional {
		t.Errorf("Expected Integrity=SecurityOptional, got %v", secConfig.Integrity)
	}

	// Check default auth methods. With no operator override, the list is built
	// programmatically (getDefaultAuthMethods) from the methods cedar actually
	// implements, in HTCondor's standard order: FS, IDTOKENS, KERBEROS, SCITOKENS, SSL.
	// PASSWORD is in HTCondor's standard order but cedar does not implement it (its
	// handshake returns "not yet implemented"), so it is excluded — offering a method
	// cedar cannot perform would just break negotiation. Because this is the CLIENT
	// context, ANONYMOUS (cedar's AuthNone) is appended so an encrypted-but-
	// unauthenticated READ works.
	//
	// Note that IDTOKENS in the *config language* maps to cedar's AuthToken (which
	// serializes on the wire as "TOKEN") — the wire-name every HTCondor schedd /
	// collector recognizes. See the doc comment on mapAuthMethods.
	wantMethods := []security.AuthMethod{
		security.AuthFS,
		security.AuthToken, // IDTOKENS -> TOKEN on the wire
		security.AuthKerberos,
		security.AuthSciTokens,
		security.AuthSSL,
		security.AuthNone, // ANONYMOUS, appended for CLIENT/READ
	}
	if len(secConfig.AuthMethods) != len(wantMethods) {
		t.Errorf("Expected %d default auth methods (FS,IDTOKENS→TOKEN,KERBEROS,SCITOKENS,SSL), got %d: %v",
			len(wantMethods), len(secConfig.AuthMethods), secConfig.AuthMethods)
	}
	for i, want := range wantMethods {
		if i >= len(secConfig.AuthMethods) {
			break
		}
		if secConfig.AuthMethods[i] != want {
			t.Errorf("AuthMethods[%d] = %v, want %v", i, secConfig.AuthMethods[i], want)
		}
	}

	// Check default crypto method (AES)
	if len(secConfig.CryptoMethods) != 1 {
		t.Errorf("Expected 1 default crypto method, got %d", len(secConfig.CryptoMethods))
	}
	if len(secConfig.CryptoMethods) > 0 && secConfig.CryptoMethods[0] != security.CryptoAES {
		t.Errorf("Expected CryptoAES, got %v", secConfig.CryptoMethods[0])
	}
}

func TestGetSecurityConfig_ClientSettings(t *testing.T) {
	configText := `
SEC_CLIENT_AUTHENTICATION = REQUIRED
SEC_CLIENT_ENCRYPTION = PREFERRED
SEC_CLIENT_INTEGRITY = OPTIONAL
SEC_CLIENT_AUTHENTICATION_METHODS = SSL,TOKEN
SEC_CLIENT_CRYPTO_METHODS = AES
`
	cfgReader := strings.NewReader(configText)
	cfg, err := config.NewFromReader(cfgReader)
	if err != nil {
		t.Fatalf("Failed to create config: %v", err)
	}

	secConfig, err := GetSecurityConfig(cfg, 60000, "CLIENT")
	if err != nil {
		t.Fatalf("GetSecurityConfig failed: %v", err)
	}

	// Check CLIENT-specific settings
	if secConfig.Authentication != security.SecurityRequired {
		t.Errorf("Expected Authentication=SecurityRequired, got %v", secConfig.Authentication)
	}
	if secConfig.Encryption != security.SecurityPreferred {
		t.Errorf("Expected Encryption=SecurityPreferred, got %v", secConfig.Encryption)
	}
	if secConfig.Integrity != security.SecurityOptional {
		t.Errorf("Expected Integrity=SecurityOptional, got %v", secConfig.Integrity)
	}

	// Check auth methods
	if len(secConfig.AuthMethods) != 2 {
		t.Errorf("Expected 2 auth methods, got %d", len(secConfig.AuthMethods))
	}
	if secConfig.AuthMethods[0] != security.AuthSSL {
		t.Errorf("Expected first auth method to be SSL, got %v", secConfig.AuthMethods[0])
	}
	if secConfig.AuthMethods[1] != security.AuthToken {
		t.Errorf("Expected second auth method to be TOKEN, got %v", secConfig.AuthMethods[1])
	}

	// Check crypto methods
	if len(secConfig.CryptoMethods) != 1 {
		t.Errorf("Expected 1 crypto method, got %d", len(secConfig.CryptoMethods))
	}
	if secConfig.CryptoMethods[0] != security.CryptoAES {
		t.Errorf("Expected CryptoAES, got %v", secConfig.CryptoMethods[0])
	}
}

func TestGetSecurityConfig_DefaultFallback(t *testing.T) {
	// Test that CLIENT context falls back to DEFAULT when CLIENT settings are not specified
	configText := `
SEC_DEFAULT_AUTHENTICATION = REQUIRED
SEC_DEFAULT_ENCRYPTION = NEVER
SEC_DEFAULT_AUTHENTICATION_METHODS = KERBEROS,SSL
SEC_DEFAULT_CRYPTO_METHODS = BLOWFISH,3DES
`
	cfgReader := strings.NewReader(configText)
	cfg, err := config.NewFromReader(cfgReader)
	if err != nil {
		t.Fatalf("Failed to create config: %v", err)
	}

	secConfig, err := GetSecurityConfig(cfg, 60000, "CLIENT")
	if err != nil {
		t.Fatalf("GetSecurityConfig failed: %v", err)
	}

	// Check that DEFAULT settings are used
	if secConfig.Authentication != security.SecurityRequired {
		t.Errorf("Expected Authentication=SecurityRequired from DEFAULT, got %v", secConfig.Authentication)
	}
	if secConfig.Encryption != security.SecurityNever {
		t.Errorf("Expected Encryption=SecurityNever from DEFAULT, got %v", secConfig.Encryption)
	}

	// Check auth methods from DEFAULT. CLIENT falls back to SEC_DEFAULT_AUTHENTICATION_METHODS
	// (KERBEROS,SSL — an operator-set value is respected verbatim, not availability-filtered),
	// then ANONYMOUS is appended for the CLIENT context: KERBEROS, SSL, ANONYMOUS.
	if len(secConfig.AuthMethods) != 3 {
		t.Errorf("Expected 3 auth methods from DEFAULT + ANONYMOUS, got %d: %v", len(secConfig.AuthMethods), secConfig.AuthMethods)
	}

	// Check crypto methods from DEFAULT
	if len(secConfig.CryptoMethods) != 2 {
		t.Errorf("Expected 2 crypto methods from DEFAULT, got %d", len(secConfig.CryptoMethods))
	}
}

func TestGetSecurityConfig_SSLCertificates(t *testing.T) {
	configText := `
SEC_CLIENT_AUTHENTICATION_METHODS = SSL
AUTH_SSL_CLIENT_CERTFILE = /path/to/cert.pem
AUTH_SSL_CLIENT_KEYFILE = /path/to/key.pem
AUTH_SSL_CLIENT_CAFILE = /path/to/ca.pem
`
	cfgReader := strings.NewReader(configText)
	cfg, err := config.NewFromReader(cfgReader)
	if err != nil {
		t.Fatalf("Failed to create config: %v", err)
	}

	secConfig, err := GetSecurityConfig(cfg, 60000, "CLIENT")
	if err != nil {
		t.Fatalf("GetSecurityConfig failed: %v", err)
	}

	// Check SSL certificate paths
	if secConfig.CertFile != "/path/to/cert.pem" {
		t.Errorf("Expected CertFile=/path/to/cert.pem, got %s", secConfig.CertFile)
	}
	if secConfig.KeyFile != "/path/to/key.pem" {
		t.Errorf("Expected KeyFile=/path/to/key.pem, got %s", secConfig.KeyFile)
	}
	if secConfig.CAFile != "/path/to/ca.pem" {
		t.Errorf("Expected CAFile=/path/to/ca.pem, got %s", secConfig.CAFile)
	}
}

func TestGetSecurityConfig_TokenDirectory(t *testing.T) {
	configText := `
SEC_CLIENT_AUTHENTICATION_METHODS = TOKEN,IDTOKENS
SEC_TOKEN_DIRECTORY = /custom/token/dir
`
	cfgReader := strings.NewReader(configText)
	cfg, err := config.NewFromReader(cfgReader)
	if err != nil {
		t.Fatalf("Failed to create config: %v", err)
	}

	secConfig, err := GetSecurityConfig(cfg, 60000, "CLIENT")
	if err != nil {
		t.Fatalf("GetSecurityConfig failed: %v", err)
	}

	// Check token directory
	if secConfig.TokenDir != "/custom/token/dir" {
		t.Errorf("Expected TokenDir=/custom/token/dir, got %s", secConfig.TokenDir)
	}
}

func TestGetSecurityConfig_MultipleAuthMethods(t *testing.T) {
	configText := `
SEC_CLIENT_AUTHENTICATION_METHODS = SSL,KERBEROS,PASSWORD,FS,IDTOKENS,SCITOKENS,TOKEN,ANONYMOUS
`
	cfgReader := strings.NewReader(configText)
	cfg, err := config.NewFromReader(cfgReader)
	if err != nil {
		t.Fatalf("Failed to create config: %v", err)
	}

	secConfig, err := GetSecurityConfig(cfg, 60000, "CLIENT")
	if err != nil {
		t.Fatalf("GetSecurityConfig failed: %v", err)
	}

	// Check that all methods are mapped
	expectedCount := 8 // SSL, KERBEROS, PASSWORD, FS, IDTOKENS, SCITOKENS, TOKEN, ANONYMOUS (as AuthNone)
	if len(secConfig.AuthMethods) != expectedCount {
		t.Errorf("Expected %d auth methods, got %d: %v", expectedCount, len(secConfig.AuthMethods), secConfig.AuthMethods)
	}

	// Verify specific methods
	hasSSL := false
	hasKerberos := false
	hasToken := false
	for _, method := range secConfig.AuthMethods {
		if method == security.AuthSSL {
			hasSSL = true
		}
		if method == security.AuthKerberos {
			hasKerberos = true
		}
		if method == security.AuthToken {
			hasToken = true
		}
	}

	if !hasSSL {
		t.Error("Expected SSL authentication method")
	}
	if !hasKerberos {
		t.Error("Expected Kerberos authentication method")
	}
	if !hasToken {
		t.Error("Expected Token authentication method")
	}
}

func TestGetSecurityConfig_MultipleCryptoMethods(t *testing.T) {
	configText := `
SEC_CLIENT_CRYPTO_METHODS = AES,BLOWFISH,3DES
`
	cfgReader := strings.NewReader(configText)
	cfg, err := config.NewFromReader(cfgReader)
	if err != nil {
		t.Fatalf("Failed to create config: %v", err)
	}

	secConfig, err := GetSecurityConfig(cfg, 60000, "CLIENT")
	if err != nil {
		t.Fatalf("GetSecurityConfig failed: %v", err)
	}

	// Check that all crypto methods are mapped
	if len(secConfig.CryptoMethods) != 3 {
		t.Errorf("Expected 3 crypto methods, got %d", len(secConfig.CryptoMethods))
	}

	// Verify order is preserved
	if secConfig.CryptoMethods[0] != security.CryptoAES {
		t.Errorf("Expected first crypto method to be AES, got %v", secConfig.CryptoMethods[0])
	}
	if secConfig.CryptoMethods[1] != security.CryptoBlowfish {
		t.Errorf("Expected second crypto method to be Blowfish, got %v", secConfig.CryptoMethods[1])
	}
	if secConfig.CryptoMethods[2] != security.Crypto3DES {
		t.Errorf("Expected third crypto method to be 3DES, got %v", secConfig.CryptoMethods[2])
	}
}

func TestMapSecurityLevel(t *testing.T) {
	tests := []struct {
		input    string
		expected security.SecurityLevel
	}{
		{"REQUIRED", security.SecurityRequired},
		{"required", security.SecurityRequired},
		{"PREFERRED", security.SecurityPreferred},
		{"OPTIONAL", security.SecurityOptional},
		{"NEVER", security.SecurityNever},
		{"  REQUIRED  ", security.SecurityRequired}, // with whitespace
		{"invalid", security.SecurityOptional},      // unknown defaults to optional
		{"", security.SecurityOptional},             // empty defaults to optional
	}

	for _, tt := range tests {
		result := mapSecurityLevel(tt.input)
		if result != tt.expected {
			t.Errorf("mapSecurityLevel(%q) = %v, expected %v", tt.input, result, tt.expected)
		}
	}
}

func TestMapAuthMethods(t *testing.T) {
	tests := []struct {
		input         string
		expectedCount int
		hasSSL        bool
		hasToken      bool
	}{
		{"SSL,TOKEN", 2, true, true},
		{"ssl,token", 2, true, true},  // case insensitive
		{"SSL, TOKEN", 2, true, true}, // with spaces
		{"", 0, false, false},         // empty string
		{"SSL,KERBEROS,PASSWORD,FS", 4, true, false},
		{"ANONYMOUS", 1, false, false}, // ANONYMOUS maps to AuthNone
		// HTCondor lists may be whitespace-separated (StringList delimiters are
		// comma AND space). These are real deployed values that previously
		// collapsed to one unrecognized token and dropped to NONE.
		{"FS TOKEN SCITOKENS SSL", 4, true, true},         // SEC_DEFAULT_AUTHENTICATION_METHODS
		{"FS SSL PASSWORD", 3, true, false},               // TOOL.SEC_CLIENT_AUTHENTICATION_METHODS
		{"FS SSL PASSWORD,ANONYMOUS", 4, true, false},     // mixed space + appended comma
	}

	for _, tt := range tests {
		result := mapAuthMethods(tt.input)
		if len(result) != tt.expectedCount {
			t.Errorf("mapAuthMethods(%q) returned %d methods, expected %d", tt.input, len(result), tt.expectedCount)
		}

		hasSSL := false
		hasToken := false
		for _, method := range result {
			if method == security.AuthSSL {
				hasSSL = true
			}
			if method == security.AuthToken {
				hasToken = true
			}
		}

		if hasSSL != tt.hasSSL {
			t.Errorf("mapAuthMethods(%q) hasSSL=%v, expected %v", tt.input, hasSSL, tt.hasSSL)
		}
		if hasToken != tt.hasToken {
			t.Errorf("mapAuthMethods(%q) hasToken=%v, expected %v", tt.input, hasToken, tt.hasToken)
		}
	}
}

func TestMapCryptoMethods(t *testing.T) {
	tests := []struct {
		input         string
		expectedCount int
		expected      []security.CryptoMethod
	}{
		{"AES", 1, []security.CryptoMethod{security.CryptoAES}},
		{"AES,BLOWFISH", 2, []security.CryptoMethod{security.CryptoAES, security.CryptoBlowfish}},
		{"aes,blowfish,3des", 3, []security.CryptoMethod{security.CryptoAES, security.CryptoBlowfish, security.Crypto3DES}},
		{"", 0, []security.CryptoMethod{}},
		// Whitespace-separated: the real deployed SEC_DEFAULT_CRYPTO_METHODS that
		// previously collapsed to one unrecognized token and yielded NO crypto.
		{"AES BLOWFISH 3DES", 3, []security.CryptoMethod{security.CryptoAES, security.CryptoBlowfish, security.Crypto3DES}},
	}

	for _, tt := range tests {
		result := mapCryptoMethods(tt.input)
		if len(result) != tt.expectedCount {
			t.Errorf("mapCryptoMethods(%q) returned %d methods, expected %d", tt.input, len(result), tt.expectedCount)
		}

		for i, expected := range tt.expected {
			if i >= len(result) || result[i] != expected {
				t.Errorf("mapCryptoMethods(%q)[%d] = %v, expected %v", tt.input, i, result[i], expected)
			}
		}
	}
}

func TestGetSecurityConfig_READContext(t *testing.T) {
	// Test with a different context
	configText := `
SEC_READ_AUTHENTICATION = NEVER
SEC_READ_ENCRYPTION = REQUIRED
SEC_DEFAULT_AUTHENTICATION = REQUIRED
`
	cfgReader := strings.NewReader(configText)
	cfg, err := config.NewFromReader(cfgReader)
	if err != nil {
		t.Fatalf("Failed to create config: %v", err)
	}

	secConfig, err := GetSecurityConfig(cfg, 60000, "READ")
	if err != nil {
		t.Fatalf("GetSecurityConfig failed: %v", err)
	}

	// READ context should use READ-specific settings
	if secConfig.Authentication != security.SecurityNever {
		t.Errorf("Expected Authentication=SecurityNever from READ context, got %v", secConfig.Authentication)
	}
	if secConfig.Encryption != security.SecurityRequired {
		t.Errorf("Expected Encryption=SecurityRequired from READ context, got %v", secConfig.Encryption)
	}
}

// TestNewClientSecurityConfig locks in the contract every site that
// migrated off a hand-built SecurityConfig literal now relies on.
//
//   - AuthMethods comes from the loaded HTCondor configuration (so SSL,
//     Kerberos, etc. are offered when the operator configures them).
//   - When a token is supplied, TOKEN/IDTOKENS is guaranteed to be in
//     the method list (prepended if absent so cedar prefers token auth
//     over anonymous SSL — token gives a real identity in logs).
//   - When no token is supplied, the method list is left as configured
//     (no TOKEN injection); useful for SSL-only or anonymous paths.
//   - The supplied SessionCache, peer name, and command flow through.
//
// The test deliberately doesn't dispatch any RPC — failures here would
// be wire-level negotiation regressions, not condor handshake bugs.
//
//nolint:gocyclo // table-driven subtests; splitting hides the contract.
func TestNewClientSecurityConfig(t *testing.T) {
	t.Run("WithToken_PrependsTokenWhenMissing", func(t *testing.T) {
		// Force a config that omits TOKEN entirely so we can observe the
		// prepend behavior. The loaded HTCondor config in the dev
		// container does include TOKEN, so we can't rely on the global
		// default for this assertion.
		cfg, err := config.NewFromReader(strings.NewReader("SEC_CLIENT_AUTHENTICATION_METHODS = SSL,KERBEROS\n"))
		if err != nil {
			t.Fatalf("config: %v", err)
		}
		// Override the global default for this test to exercise the
		// prepend path without rebuilding the whole NewClientSecurityConfig
		// call (which uses getDefaultConfig internally).
		prev := globalDefaultConfig.Load()
		globalDefaultConfig.Store(cfg)
		t.Cleanup(func() { globalDefaultConfig.Store(prev) })

		got, err := NewClientSecurityConfig(t.Context(), "tok", "<127.0.0.1:9618>", 0, "CLIENT", nil)
		if err != nil {
			t.Fatalf("NewClientSecurityConfig: %v", err)
		}
		if len(got.AuthMethods) == 0 || got.AuthMethods[0] != security.AuthToken {
			t.Errorf("expected AuthMethods[0] == AuthToken, got %v", got.AuthMethods)
		}
		if got.Token != "tok" {
			t.Errorf("Token = %q, want %q", got.Token, "tok")
		}
	})

	t.Run("WithToken_PromotesToFrontWhenIDTokensNotFirst", func(t *testing.T) {
		// Production deployments often have FS,IDTOKENS,SSL — FS comes
		// first because admin tooling on the host uses it. When the
		// caller supplies a token, they're explicitly asking for
		// token-based identity (cf. anonymous FS), so cedar MUST move
		// TOKEN to position 0 even though it was already in the list.
		// Without this, cedar's first-match-wins negotiation picks FS
		// and the token is silently never tried.
		cfg, err := config.NewFromReader(strings.NewReader("SEC_CLIENT_AUTHENTICATION_METHODS = FS,IDTOKENS,SSL\n"))
		if err != nil {
			t.Fatalf("config: %v", err)
		}
		prev := globalDefaultConfig.Load()
		globalDefaultConfig.Store(cfg)
		t.Cleanup(func() { globalDefaultConfig.Store(prev) })

		got, err := NewClientSecurityConfig(t.Context(), "tok", "<127.0.0.1:9618>", 0, "CLIENT", nil)
		if err != nil {
			t.Fatalf("NewClientSecurityConfig: %v", err)
		}
		if len(got.AuthMethods) == 0 || got.AuthMethods[0] != security.AuthToken {
			t.Errorf("expected AuthMethods[0] == AuthToken when token supplied, got %v", got.AuthMethods)
		}
		count := 0
		for _, m := range got.AuthMethods {
			if m == security.AuthToken {
				count++
			}
		}
		if count != 1 {
			t.Errorf("expected exactly one TOKEN entry; got %d in %v", count, got.AuthMethods)
		}
	})

	t.Run("WithToken_DoesNotDuplicateWhenIDTokensPresent", func(t *testing.T) {
		// IDTOKENS in the *config language* maps to cedar's AuthToken
		// (see mapAuthMethods); we shouldn't prepend a second TOKEN
		// entry when the configured method list already named it.
		cfg, err := config.NewFromReader(strings.NewReader("SEC_CLIENT_AUTHENTICATION_METHODS = IDTOKENS,SSL\n"))
		if err != nil {
			t.Fatalf("config: %v", err)
		}
		prev := globalDefaultConfig.Load()
		globalDefaultConfig.Store(cfg)
		t.Cleanup(func() { globalDefaultConfig.Store(prev) })

		got, err := NewClientSecurityConfig(t.Context(), "tok", "<127.0.0.1:9618>", 0, "CLIENT", nil)
		if err != nil {
			t.Fatalf("NewClientSecurityConfig: %v", err)
		}
		count := 0
		for _, m := range got.AuthMethods {
			if m == security.AuthToken {
				count++
			}
		}
		if count != 1 {
			t.Errorf("expected exactly one TOKEN entry; got %d in %v", count, got.AuthMethods)
		}
	})

	t.Run("EmptyToken_DoesNotInjectToken", func(t *testing.T) {
		cfg, err := config.NewFromReader(strings.NewReader("SEC_CLIENT_AUTHENTICATION_METHODS = SSL\n"))
		if err != nil {
			t.Fatalf("config: %v", err)
		}
		prev := globalDefaultConfig.Load()
		globalDefaultConfig.Store(cfg)
		t.Cleanup(func() { globalDefaultConfig.Store(prev) })

		got, err := NewClientSecurityConfig(t.Context(), "", "<127.0.0.1:9618>", 0, "CLIENT", nil)
		if err != nil {
			t.Fatalf("NewClientSecurityConfig: %v", err)
		}
		for _, m := range got.AuthMethods {
			if m == security.AuthToken {
				t.Errorf("AuthMethods unexpectedly includes AuthToken when token is empty: %v", got.AuthMethods)
			}
		}
		if got.Token != "" {
			t.Errorf("Token = %q, want empty", got.Token)
		}
	})

	t.Run("DefaultsContext_FallsBackToCLIENT", func(t *testing.T) {
		// Empty secContext should be treated as CLIENT.
		_, err := NewClientSecurityConfig(t.Context(), "tok", "<127.0.0.1:9618>", 0, "", nil)
		if err != nil {
			t.Errorf("expected empty context to default to CLIENT, got error: %v", err)
		}
	})
}

// TestGetDefaultAuthMethodsProgrammatic verifies the default auth-method list is built from
// the methods cedar actually implements: PASSWORD (still a cedar stub) is excluded,
// FS/IDTOKENS/KERBEROS/SCITOKENS/SSL are kept, in HTCondor's standard order.
func TestGetDefaultAuthMethodsProgrammatic(t *testing.T) {
	got := getDefaultAuthMethods()
	if got != "FS,IDTOKENS,KERBEROS,SCITOKENS,SSL" {
		t.Errorf("getDefaultAuthMethods() = %q, want FS,IDTOKENS,KERBEROS,SCITOKENS,SSL", got)
	}
	// The list is sourced from cedar's capability API: stubs excluded, implemented kept.
	if security.AuthPassword.Implemented() {
		t.Error("PASSWORD is a cedar stub and must not be reported implemented")
	}
	for _, m := range []security.AuthMethod{security.AuthFS, security.AuthIDTokens, security.AuthKerberos, security.AuthSciTokens, security.AuthSSL} {
		if !m.Implemented() {
			t.Errorf("%s should be reported implemented", m)
		}
	}
}

// TestGetSecurityMethodsAuth covers the resolution rules: the stale generated default is
// ignored in favor of the programmatic one, an operator default is honored, and ANONYMOUS is
// appended only for CLIENT/READ.
func TestGetSecurityMethodsAuth(t *testing.T) {
	prog := getDefaultAuthMethods()

	// No config: stale generated "FS,TOKEN" must NOT surface; CLIENT gets programmatic+ANONYMOUS.
	cfg, _ := config.NewFromReader(strings.NewReader(""))
	if got := getSecurityMethods(cfg, "CLIENT", "AUTHENTICATION_METHODS"); got != prog+",ANONYMOUS" {
		t.Errorf("CLIENT default = %q, want %q", got, prog+",ANONYMOUS")
	}
	// WRITE context gets no ANONYMOUS.
	if got := getSecurityMethods(cfg, "WRITE", "AUTHENTICATION_METHODS"); got != prog {
		t.Errorf("WRITE default = %q, want %q (no ANONYMOUS)", got, prog)
	}
	// An operator SEC_DEFAULT override is honored verbatim (WRITE), plus ANONYMOUS for CLIENT.
	cfg2, _ := config.NewFromReader(strings.NewReader("SEC_DEFAULT_AUTHENTICATION_METHODS = SSL\n"))
	if got := getSecurityMethods(cfg2, "WRITE", "AUTHENTICATION_METHODS"); got != "SSL" {
		t.Errorf("operator WRITE = %q, want SSL", got)
	}
	if got := getSecurityMethods(cfg2, "READ", "AUTHENTICATION_METHODS"); got != "SSL,ANONYMOUS" {
		t.Errorf("operator READ = %q, want SSL,ANONYMOUS", got)
	}
	// A context-specific operator setting wins outright (no append beyond what it lists).
	cfg3, _ := config.NewFromReader(strings.NewReader("SEC_CLIENT_AUTHENTICATION_METHODS = FS\n"))
	if got := getSecurityMethods(cfg3, "CLIENT", "AUTHENTICATION_METHODS"); got != "FS" {
		t.Errorf("explicit SEC_CLIENT = %q, want FS", got)
	}
}
