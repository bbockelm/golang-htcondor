package httpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/bbockelm/cedar/commands"
	"github.com/bbockelm/cedar/security"
	cedarserver "github.com/bbockelm/cedar/server"
	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/config"
)

// newPingDaemon starts a CEDAR server that authenticates with sc's methods
// and answers DC_NOP, as a collector or schedd does for a ping.
func newPingDaemon(t *testing.T, sc *security.SecurityConfig) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0") //nolint:noctx // test-only loopback listener
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	sc.Authentication = security.SecurityRequired
	sc.CryptoMethods = []security.CryptoMethod{security.CryptoAES}
	sc.Encryption = security.SecurityOptional
	sc.Integrity = security.SecurityOptional
	sc.SessionCache = security.NewSessionCache()
	srv := cedarserver.New(sc)
	srv.Handle(int(commands.DC_NOP), func(context.Context, *cedarserver.Conn) error { return nil }, "ALLOW")
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = srv.Serve(ctx, ln) }()
	t.Cleanup(func() { cancel(); _ = ln.Close() })
	return fmt.Sprintf("<%s>", ln.Addr().String())
}

// periodicPingReadyz runs one periodic ping on a Handler configured with
// cfg and no token of its own, then returns what /readyz reports.
func periodicPingReadyz(t *testing.T, cfg *config.Config, collectorAddr, scheddAddr string) (int, publicHealthSnapshot) {
	t.Helper()
	h := &Handler{
		logger:       newTestLogger(t),
		clientConfig: cfg,
		collector:    htcondor.NewCollector(collectorAddr).WithConfig(cfg),
		schedd:       htcondor.NewSchedd("schedd", scheddAddr).WithConfig(cfg),
		pingHealth:   newPingHealth(time.Minute),
	}
	h.performPeriodicPing()

	rec := httptest.NewRecorder()
	h.handleReadyz(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/readyz", nil))
	var snap publicHealthSnapshot
	if err := json.Unmarshal(rec.Body.Bytes(), &snap); err != nil {
		t.Fatalf("decode /readyz %q: %v", rec.Body.String(), err)
	}
	return rec.Code, snap
}

// TestPeriodicCollectorPingUsesConfiguredMethods pings a collector that
// accepts only what the pool's CLIENT configuration offers -- FS, or
// IDTOKENS from the configured token directory -- with no token given to
// the server. The ping must authenticate the way every other daemon call
// does, and /readyz must report the collector healthy.
func TestPeriodicCollectorPingUsesConfiguredMethods(t *testing.T) {
	t.Run("FS", func(t *testing.T) {
		cfg := clientConfigFrom(t, "SEC_CLIENT_AUTHENTICATION_METHODS = FS, IDTOKENS\n")
		addr := newPingDaemon(t, &security.SecurityConfig{AuthMethods: []security.AuthMethod{security.AuthFS}})

		code, snap := periodicPingReadyz(t, cfg, addr, addr)
		if snap.Collector.Status != "ok" {
			t.Errorf("collector status = %q, want ok", snap.Collector.Status)
		}
		if code != http.StatusOK {
			t.Errorf("/readyz = %d (%+v), want 200", code, snap)
		}
	})

	t.Run("IDTOKENS", func(t *testing.T) {
		keyDir := t.TempDir()
		if err := os.WriteFile(filepath.Join(keyDir, "POOL"), []byte("collector-ping-test-key"), 0o600); err != nil {
			t.Fatal(err)
		}
		now := time.Now().Unix()
		tok, err := security.GenerateJWT(keyDir, "POOL", "condor@pool.example", "pool.example", now, now+3600, nil)
		if err != nil {
			t.Fatalf("GenerateJWT: %v", err)
		}
		tokenDir := t.TempDir()
		if err := os.WriteFile(filepath.Join(tokenDir, "condor"), []byte(tok+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg := clientConfigFrom(t, "SEC_CLIENT_AUTHENTICATION_METHODS = FS, IDTOKENS\nSEC_TOKEN_DIRECTORY = "+tokenDir+"\n")
		addr := newPingDaemon(t, &security.SecurityConfig{
			AuthMethods:             []security.AuthMethod{security.AuthToken},
			TrustDomain:             "pool.example",
			TokenPoolSigningKeyFile: filepath.Join(keyDir, "POOL"),
		})

		code, snap := periodicPingReadyz(t, cfg, addr, addr)
		if snap.Collector.Status != "ok" {
			t.Errorf("collector status = %q, want ok", snap.Collector.Status)
		}
		if code != http.StatusOK {
			t.Errorf("/readyz = %d (%+v), want 200", code, snap)
		}
	})
}

// TestPeriodicCollectorPingOffersSSL pings a collector that accepts only
// SSL, from a client whose configuration does and does not name SSL. SSL
// is offered either way, so an anonymous SSL handshake keeps the
// collector healthy when the configured methods are not accepted.
func TestPeriodicCollectorPingOffersSSL(t *testing.T) {
	certFile, keyFile := writeKeyPair(t, t.TempDir(), 0o600)
	collector := newPingDaemon(t, &security.SecurityConfig{
		AuthMethods: []security.AuthMethod{security.AuthSSL},
		CertFile:    certFile,
		KeyFile:     keyFile,
	})
	schedd := newPingDaemon(t, &security.SecurityConfig{AuthMethods: []security.AuthMethod{security.AuthFS}})

	for _, methods := range []string{"FS, IDTOKENS", "FS, SSL"} {
		t.Run(methods, func(t *testing.T) {
			cfg := clientConfigFrom(t, "SEC_CLIENT_AUTHENTICATION_METHODS = "+methods+"\n"+
				"AUTH_SSL_CLIENT_CAFILE = "+certFile+"\nAUTH_SSL_CLIENT_USE_DEFAULT_CAS = false\n")

			code, snap := periodicPingReadyz(t, cfg, collector, schedd)
			if snap.Collector.Status != "ok" {
				t.Errorf("collector status = %q, want ok", snap.Collector.Status)
			}
			if code != http.StatusOK {
				t.Errorf("/readyz = %d (%+v), want 200", code, snap)
			}
		})
	}
}

// TestConfigureSecurityForCollectorPingMethods pins the offered list: the
// configured CLIENT methods, TOKEN first when there is a token, SSL last
// when the configuration lacks it.
func TestConfigureSecurityForCollectorPingMethods(t *testing.T) {
	cfg := clientConfigFrom(t, "SEC_CLIENT_AUTHENTICATION_METHODS = FS, IDTOKENS\n")
	for _, tc := range []struct {
		token string
		want  []security.AuthMethod
	}{
		{"", []security.AuthMethod{security.AuthFS, security.AuthToken, security.AuthSSL}},
		{"a-token", []security.AuthMethod{security.AuthToken, security.AuthFS, security.AuthSSL}},
	} {
		got, err := configureSecurityForCollectorPing(cfg, tc.token, "collector.example.org")
		if err != nil {
			t.Fatalf("configure: %v", err)
		}
		if !slices.Equal(got.AuthMethods, tc.want) {
			t.Errorf("token %q: AuthMethods = %v, want %v", tc.token, got.AuthMethods, tc.want)
		}
		if got.Token != tc.token {
			t.Errorf("token %q: Token = %q", tc.token, got.Token)
		}
		if got.ServerName != "collector.example.org" {
			t.Errorf("ServerName = %q", got.ServerName)
		}
	}
}
