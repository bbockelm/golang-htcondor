package htcondor

import (
	"context"
	"fmt"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/cedar/commands"
	"github.com/bbockelm/cedar/security"
	cedarserver "github.com/bbockelm/cedar/server"
	"github.com/bbockelm/golang-htcondor/config"
)

// fsOnlyConfig authenticates with FS alone, which the fake daemon below
// accepts over loopback.
const fsOnlyConfig = `
SEC_CLIENT_AUTHENTICATION = REQUIRED
SEC_CLIENT_AUTHENTICATION_METHODS = FS
SEC_CLIENT_CRYPTO_METHODS = AES
`

// tokenOnlyConfig offers TOKEN alone from an empty token directory, so it has
// nothing the fake daemon will accept.
func tokenOnlyConfig(t *testing.T) string {
	return fmt.Sprintf(`
SEC_CLIENT_AUTHENTICATION = REQUIRED
SEC_CLIENT_AUTHENTICATION_METHODS = TOKEN
SEC_CLIENT_CRYPTO_METHODS = AES
SEC_TOKEN_DIRECTORY = %s
`, t.TempDir())
}

// setGlobalConfig replaces the process-wide default configuration for the
// rest of the test.
func setGlobalConfig(t *testing.T, cfg *config.Config) {
	t.Helper()
	prev := globalDefaultConfig.Load()
	prevRL := globalRateLimitManager.Load()
	globalDefaultConfig.Store(cfg)
	globalRateLimitManager.Store(nil)
	t.Cleanup(func() {
		globalDefaultConfig.Store(prev)
		globalRateLimitManager.Store(prevRL)
	})
}

// newFSOnlyDaemon starts a CEDAR server that accepts only FS authentication
// and answers DC_NOP. Each call gets its own address, so a session cached by
// one subtest is never resumed by another.
func newFSOnlyDaemon(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0") //nolint:noctx // test-only loopback listener
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := cedarserver.New(&security.SecurityConfig{
		AuthMethods:    []security.AuthMethod{security.AuthFS},
		Authentication: security.SecurityRequired,
		CryptoMethods:  []security.CryptoMethod{security.CryptoAES},
		Encryption:     security.SecurityOptional,
		Integrity:      security.SecurityOptional,
		SessionCache:   security.NewSessionCache(),
	})
	srv.Handle(int(commands.DC_NOP), func(context.Context, *cedarserver.Conn) error { return nil }, "READ")
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = srv.Serve(ctx, ln) }()
	t.Cleanup(func() { cancel(); _ = ln.Close() })
	return fmt.Sprintf("<%s>", ln.Addr().String())
}

func daemonContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	return WithDaemonCredential(ctx, "client config test")
}

// pinger is the part of Schedd and Collector these tests drive.
type pinger interface {
	Ping(ctx context.Context) (*PingResult, error)
}

// TestClientWithConfigIgnoresGlobal shows that a client given an explicit
// configuration authenticates with it, in both directions: an explicit config
// that works succeeds although the global one could not, and an explicit
// config that cannot authenticate fails although the global one would have
// -- so nothing falls back to the global configuration.
func TestClientWithConfigIgnoresGlobal(t *testing.T) {
	clients := map[string]func(addr string, cfg *config.Config) pinger{
		"Schedd": func(addr string, cfg *config.Config) pinger {
			return NewSchedd("fake", addr).WithConfig(cfg)
		},
		"Collector": func(addr string, cfg *config.Config) pinger {
			return NewCollector(addr).WithConfig(cfg)
		},
	}
	for name, newClient := range clients {
		t.Run(name+"/ExplicitWorks_GlobalWouldNot", func(t *testing.T) {
			setGlobalConfig(t, mustConfig(t, tokenOnlyConfig(t)))
			addr := newFSOnlyDaemon(t)

			res, err := newClient(addr, mustConfig(t, fsOnlyConfig)).Ping(daemonContext(t))
			if err != nil {
				t.Fatalf("Ping with explicit FS config: %v", err)
			}
			if res.AuthMethod != string(security.AuthFS) {
				t.Errorf("AuthMethod = %q, want FS", res.AuthMethod)
			}
		})
		t.Run(name+"/ExplicitFails_GlobalWould", func(t *testing.T) {
			setGlobalConfig(t, mustConfig(t, fsOnlyConfig))
			addr := newFSOnlyDaemon(t)

			// Control: the global configuration authenticates here.
			if _, err := newClient(addr, nil).Ping(daemonContext(t)); err != nil {
				t.Fatalf("control Ping with global FS config: %v", err)
			}

			// A second daemon, so the control's session is not resumed.
			addr = newFSOnlyDaemon(t)
			if _, err := newClient(addr, mustConfig(t, tokenOnlyConfig(t))).Ping(daemonContext(t)); err == nil {
				t.Fatal("Ping with explicit TOKEN-only config succeeded; it fell back to the global FS config")
			}
		})
	}
}

// TestNewClientSecurityConfigWithConfig shows the explicit config is read for
// the method list on both the token and no-token paths, and that the token
// rules (TOKEN first, FS removed) are unchanged.
func TestNewClientSecurityConfigWithConfig(t *testing.T) {
	setGlobalConfig(t, mustConfig(t, "SEC_CLIENT_AUTHENTICATION_METHODS = KERBEROS\n"))
	cfg := mustConfig(t, "SEC_CLIENT_AUTHENTICATION_METHODS = FS,SSL\n")
	ctx := WithDaemonCredential(t.Context(), "test")

	got, err := NewClientSecurityConfigWithConfig(ctx, cfg, "", "<127.0.0.1:9618>", 0, "CLIENT", nil)
	if err != nil {
		t.Fatalf("no token: %v", err)
	}
	if want := []security.AuthMethod{security.AuthFS, security.AuthSSL}; !slices.Equal(got.AuthMethods, want) {
		t.Errorf("no token: AuthMethods = %v, want %v", got.AuthMethods, want)
	}

	got, err = NewClientSecurityConfigWithConfig(ctx, cfg, "tok", "<127.0.0.1:9618>", 0, "CLIENT", nil)
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	if want := []security.AuthMethod{security.AuthToken, security.AuthSSL}; !slices.Equal(got.AuthMethods, want) {
		t.Errorf("token: AuthMethods = %v, want %v", got.AuthMethods, want)
	}

	// nil is the global configuration, as NewClientSecurityConfig.
	got, err = NewClientSecurityConfigWithConfig(ctx, nil, "", "<127.0.0.1:9618>", 0, "CLIENT", nil)
	if err != nil {
		t.Fatalf("nil cfg: %v", err)
	}
	if want := []security.AuthMethod{security.AuthKerberos}; !slices.Equal(got.AuthMethods, want) {
		t.Errorf("nil cfg: AuthMethods = %v, want %v", got.AuthMethods, want)
	}
}

func TestLookupSSLClientCredentialsWithConfig(t *testing.T) {
	setGlobalConfig(t, mustConfig(t, "AUTH_SSL_CLIENT_CERTFILE = /global/cert\nAUTH_SSL_CLIENT_KEYFILE = /global/key\n"))
	cfg := mustConfig(t, "AUTH_SSL_CLIENT_CERTFILE = /mine/cert\nAUTH_SSL_CLIENT_KEYFILE = /mine/key\nAUTH_SSL_CLIENT_CAFILE = /mine/ca\n")

	cert, key, ca, ok := LookupSSLClientCredentialsWithConfig(cfg)
	if !ok || cert != "/mine/cert" || key != "/mine/key" || ca != "/mine/ca" {
		t.Errorf("explicit: got (%q, %q, %q, %v)", cert, key, ca, ok)
	}
	cert, key, _, ok = LookupSSLClientCredentialsWithConfig(nil)
	if !ok || cert != "/global/cert" || key != "/global/key" {
		t.Errorf("nil: got (%q, %q, %v), want the global config's", cert, key, ok)
	}
}

// TestRateLimitManagerFor shows an explicit config gets its own limiter, built
// from its knobs and shared by every object carrying that config, while nil is
// still the process-wide limiter.
func TestRateLimitManagerFor(t *testing.T) {
	setGlobalConfig(t, mustConfig(t, "SCHEDD_QUERY_RATE_LIMIT = 100\n"))
	a := mustConfig(t, "SCHEDD_QUERY_RATE_LIMIT = 7\n")
	b := mustConfig(t, "SCHEDD_QUERY_RATE_LIMIT = 9\n")

	if got := rateLimitManagerFor(nil); got != getRateLimitManager() {
		t.Error("nil config did not return the process-wide limiter")
	}
	if got := rateLimitManagerFor(nil).GetScheddStats().GlobalRate; got != 100 {
		t.Errorf("global limiter rate = %v, want 100", got)
	}
	ma := rateLimitManagerFor(a)
	if ma == rateLimitManagerFor(nil) {
		t.Fatal("explicit config shares the process-wide limiter")
	}
	if got := ma.GetScheddStats().GlobalRate; got != 7 {
		t.Errorf("explicit limiter rate = %v, want 7", got)
	}
	if rateLimitManagerFor(a) != ma {
		t.Error("same config produced two limiters")
	}
	if mb := rateLimitManagerFor(b); mb == ma || mb.GetScheddStats().GlobalRate != 9 {
		t.Error("distinct configs did not get distinct limiters")
	}
}

// TestScheddWithConfigRateLimit drives the limiter through a Schedd: an
// explicit config with a tiny budget refuses the second query, although the
// global configuration is unlimited.
func TestScheddWithConfigRateLimit(t *testing.T) {
	setGlobalConfig(t, mustConfig(t, ""))
	cfg := mustConfig(t, "SCHEDD_QUERY_RATE_LIMIT = 0.001\n")
	// An address nothing listens on: an allowed query fails to connect, a
	// refused one fails on the limiter before dialling.
	s := NewSchedd("fake", "<127.0.0.1:1>").WithConfig(cfg)
	ctx := daemonContext(t)

	sawLimit := false
	for range 3 {
		_, err := s.Query(ctx, "true", nil)
		if err != nil && strings.Contains(err.Error(), "rate limit exceeded") {
			sawLimit = true
			break
		}
	}
	if !sawLimit {
		t.Error("explicit SCHEDD_QUERY_RATE_LIMIT was not applied")
	}
}

func TestMasterWithConfigReachesSender(t *testing.T) {
	cfg := mustConfig(t, "")
	m := NewMaster("<127.0.0.1:1>").WithConfig(cfg)
	cs, ok := m.sender.(*cedarMasterSender)
	if !ok || cs.cfg != cfg {
		t.Error("Master.WithConfig did not reach the CEDAR sender")
	}
}
