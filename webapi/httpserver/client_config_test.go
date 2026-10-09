package httpserver

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/bbockelm/cedar/security"
	"github.com/bbockelm/golang-htcondor/config"
	"github.com/bbockelm/golang-htcondor/logging"
)

func clientConfigFrom(t *testing.T, text string) *config.Config {
	t.Helper()
	cfg, err := config.NewFromReader(strings.NewReader(text))
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	return cfg
}

// TestConfigureSecurityForTokenReadsClientConfig shows the token builder the
// Handler uses takes its configured base from the server's ClientConfig, with
// the session-mode FS rule still applied on top.
func TestConfigureSecurityForTokenReadsClientConfig(t *testing.T) {
	cfg := clientConfigFrom(t, "SEC_CLIENT_AUTHENTICATION_METHODS = FS,KERBEROS,SSL\n")

	got, err := configureSecurityForToken(cfg, createTestJWTToken(3600), nil, false)
	if err != nil {
		t.Fatalf("configure: %v", err)
	}
	want := []security.AuthMethod{security.AuthToken, security.AuthKerberos, security.AuthSSL}
	if !slices.Equal(got.AuthMethods, want) {
		t.Errorf("AuthMethods = %v, want %v", got.AuthMethods, want)
	}
}

func TestConfigureSecurityForCollectorPingReadsClientConfig(t *testing.T) {
	cfg := clientConfigFrom(t, "AUTH_SSL_CLIENT_CERTFILE = /pool/cert\nAUTH_SSL_CLIENT_KEYFILE = /pool/key\nAUTH_SSL_CLIENT_CAFILE = /pool/ca\n")

	got, err := configureSecurityForCollectorPing(cfg, "", "collector.example.org")
	if err != nil {
		t.Fatalf("configure: %v", err)
	}
	if got.CertFile != "/pool/cert" || got.KeyFile != "/pool/key" || got.CAFile != "/pool/ca" {
		t.Errorf("SSL credentials = (%q, %q, %q), want the ClientConfig's", got.CertFile, got.KeyFile, got.CAFile)
	}
}

// TestFindCreddAddressFileUsesServerConfig shows the local credd address file
// comes from the configuration handed in, not from $CONDOR_CONFIG.
func TestFindCreddAddressFileUsesServerConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".credd_address")
	if err := os.WriteFile(path, []byte("<127.0.0.1:1234>\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := clientConfigFrom(t, "CREDD_ADDRESS_FILE = "+path+"\n")
	logger, err := logging.New(&logging.Config{OutputPath: "stderr"})
	if err != nil {
		t.Fatal(err)
	}

	if got := findCreddAddressFile(cfg, logger); got != path {
		t.Errorf("findCreddAddressFile = %q, want %q", got, path)
	}
	if got := localCreddAddress(cfg, logger); got != "<127.0.0.1:1234>" {
		t.Errorf("localCreddAddress = %q", got)
	}
}
