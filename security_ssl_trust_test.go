package htcondor

import (
	"testing"

	"github.com/bbockelm/cedar/security"
)

// checkTrust asserts the SSL trust anchors of sc.
func checkTrust(t *testing.T, what string, sc *security.SecurityConfig, caFile, caDir string, useDefault bool) {
	t.Helper()
	if sc.CAFile != caFile || sc.CADir != caDir {
		t.Errorf("%s: CAFile = %q, CADir = %q; want %q, %q", what, sc.CAFile, sc.CADir, caFile, caDir)
	}
	if sc.UseDefaultCAs == nil {
		t.Errorf("%s: UseDefaultCAs = nil, want %v", what, useDefault)
	} else if *sc.UseDefaultCAs != useDefault {
		t.Errorf("%s: UseDefaultCAs = %v, want %v", what, *sc.UseDefaultCAs, useDefault)
	}
}

// TestSSLClientTrustKnobs shows AUTH_SSL_CLIENT_CADIR and
// AUTH_SSL_CLIENT_USE_DEFAULT_CAS reach the client SecurityConfig, through
// GetSecurityConfig and through both NewClientSecurityConfig paths (the
// delegated-token path keeps verifying the server), and that the server knobs
// do not.
func TestSSLClientTrustKnobs(t *testing.T) {
	cfg := mustConfig(t, `
SEC_CLIENT_AUTHENTICATION_METHODS = SSL,TOKEN
AUTH_SSL_CLIENT_CAFILE = /client/ca.pem
AUTH_SSL_CLIENT_CADIR = /client/certs:/more/certs
AUTH_SSL_CLIENT_USE_DEFAULT_CAS = False
AUTH_SSL_SERVER_CAFILE = /server/ca.pem
AUTH_SSL_SERVER_CADIR = /server/certs
AUTH_SSL_SERVER_USE_DEFAULT_CAS = true
`)
	sc, err := GetSecurityConfig(cfg, 0, "CLIENT")
	if err != nil {
		t.Fatal(err)
	}
	checkTrust(t, "GetSecurityConfig", sc, "/client/ca.pem", "/client/certs:/more/certs", false)

	sc, err = NewClientSecurityConfigWithConfig(t.Context(), cfg, "", "", 0, "CLIENT", nil)
	if err != nil {
		t.Fatal(err)
	}
	checkTrust(t, "NewClientSecurityConfig", sc, "/client/ca.pem", "/client/certs:/more/certs", false)

	sc, err = NewClientSecurityConfigWithConfig(t.Context(), cfg, "a.token.value", "", 0, "CLIENT", nil)
	if err != nil {
		t.Fatal(err)
	}
	checkTrust(t, "NewClientSecurityConfig with a token", sc, "/client/ca.pem", "/client/certs:/more/certs", false)
}

// TestSSLServerTrustKnobs shows AUTH_SSL_SERVER_CADIR and
// AUTH_SSL_SERVER_USE_DEFAULT_CAS reach the server SecurityConfig, replacing
// the client values GetSecurityConfig loaded. A server with no
// AUTH_SSL_SERVER_CAFILE trusts no CA file, even when the client has one.
func TestSSLServerTrustKnobs(t *testing.T) {
	cfg := mustConfig(t, `
SEC_DEFAULT_AUTHENTICATION_METHODS = SSL
AUTH_SSL_CLIENT_CAFILE = /client/ca.pem
AUTH_SSL_CLIENT_CADIR = /client/certs
AUTH_SSL_CLIENT_USE_DEFAULT_CAS = true
AUTH_SSL_SERVER_CADIR = /server/certs
AUTH_SSL_SERVER_USE_DEFAULT_CAS = 0
`)
	sc, err := GetServerSecurityConfig(cfg, 0, "DEFAULT")
	if err != nil {
		t.Fatal(err)
	}
	checkTrust(t, "GetServerSecurityConfig", sc, "", "/server/certs", false)
}

// TestSSLTrustKnobsUnset shows an unset USE_DEFAULT_CAS means true on both
// sides, as in HTCondor, and that a value param_boolean rejects ("no") also
// leaves the default.
func TestSSLTrustKnobsUnset(t *testing.T) {
	for _, text := range []string{
		"",
		"AUTH_SSL_CLIENT_USE_DEFAULT_CAS = no\nAUTH_SSL_SERVER_USE_DEFAULT_CAS = no\n",
	} {
		cfg := mustConfig(t, "SEC_DEFAULT_AUTHENTICATION_METHODS = SSL\n"+text)
		sc, err := GetSecurityConfig(cfg, 0, "CLIENT")
		if err != nil {
			t.Fatal(err)
		}
		checkTrust(t, "client "+text, sc, "", "", true)
		sc, err = GetServerSecurityConfig(cfg, 0, "DEFAULT")
		if err != nil {
			t.Fatal(err)
		}
		checkTrust(t, "server "+text, sc, "", "", true)
	}
}

// TestApplySSLClientTrust shows the helper for hand-built configs reads the
// explicit configuration, or the process-wide one for nil.
func TestApplySSLClientTrust(t *testing.T) {
	setGlobalConfig(t, mustConfig(t, "AUTH_SSL_CLIENT_CADIR = /global/certs\n"))

	sc := &security.SecurityConfig{}
	ApplySSLClientTrust(mustConfig(t, "AUTH_SSL_CLIENT_CAFILE = /mine/ca.pem\nAUTH_SSL_CLIENT_USE_DEFAULT_CAS = 1 == 0\n"), sc)
	checkTrust(t, "explicit", sc, "/mine/ca.pem", "", false)

	sc = &security.SecurityConfig{}
	ApplySSLClientTrust(nil, sc)
	checkTrust(t, "nil", sc, "", "/global/certs", true)
}

// TestSciTokensTrustKnobs shows SCITOKENS alone loads the AUTH_SSL_* trust
// anchors, as HTCondor's setup_ssl_ctx does for its TLS handshake: on the
// client, the delegated-token client, the server, and a per-level server
// policy. The client presents no certificate for SCITOKENS; the server
// presents its own.
func TestSciTokensTrustKnobs(t *testing.T) {
	cfg := mustConfig(t, `
SEC_DEFAULT_AUTHENTICATION_METHODS = SCITOKENS
SEC_WRITE_AUTHENTICATION_METHODS = SCITOKENS
AUTH_SSL_CLIENT_CERTFILE = /client/cert.pem
AUTH_SSL_CLIENT_KEYFILE = /client/key.pem
AUTH_SSL_CLIENT_CAFILE = /client/ca.pem
AUTH_SSL_CLIENT_CADIR = /client/certs
AUTH_SSL_CLIENT_USE_DEFAULT_CAS = false
AUTH_SSL_SERVER_CERTFILE = /server/cert.pem
AUTH_SSL_SERVER_KEYFILE = /server/key.pem
AUTH_SSL_SERVER_CAFILE = /server/ca.pem
AUTH_SSL_SERVER_CADIR = /server/certs
AUTH_SSL_SERVER_USE_DEFAULT_CAS = false
`)
	noCert := func(what string, sc *security.SecurityConfig) {
		t.Helper()
		if sc.CertFile != "" || sc.KeyFile != "" {
			t.Errorf("%s: CertFile = %q, KeyFile = %q; want none", what, sc.CertFile, sc.KeyFile)
		}
	}

	sc, err := GetSecurityConfig(cfg, 0, "CLIENT")
	if err != nil {
		t.Fatal(err)
	}
	checkTrust(t, "GetSecurityConfig", sc, "/client/ca.pem", "/client/certs", false)
	noCert("GetSecurityConfig", sc)

	sc, err = NewClientSecurityConfigWithConfig(t.Context(), cfg, "a.token.value", "", 0, "CLIENT", nil)
	if err != nil {
		t.Fatal(err)
	}
	checkTrust(t, "NewClientSecurityConfig with a token", sc, "/client/ca.pem", "/client/certs", false)
	noCert("NewClientSecurityConfig with a token", sc)

	for _, level := range []string{"DEFAULT", "WRITE"} {
		sc, err = GetServerSecurityConfig(cfg, 0, level)
		if err != nil {
			t.Fatal(err)
		}
		checkTrust(t, "GetServerSecurityConfig "+level, sc, "/server/ca.pem", "/server/certs", false)
		if sc.CertFile != "/server/cert.pem" || sc.KeyFile != "/server/key.pem" {
			t.Errorf("GetServerSecurityConfig %s: CertFile = %q, KeyFile = %q", level, sc.CertFile, sc.KeyFile)
		}
	}

	// A method list with neither SSL nor SCITOKENS loads no trust anchors.
	sc, err = GetSecurityConfig(mustConfig(t, "SEC_DEFAULT_AUTHENTICATION_METHODS = FS\nAUTH_SSL_CLIENT_CADIR = /client/certs\n"), 0, "CLIENT")
	if err != nil {
		t.Fatal(err)
	}
	if sc.CADir != "" || sc.UseDefaultCAs != nil {
		t.Errorf("FS only: CADir = %q, UseDefaultCAs = %v; want unset", sc.CADir, sc.UseDefaultCAs)
	}
}
