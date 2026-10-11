package htcondor

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/bbockelm/cedar/client"
	"github.com/bbockelm/cedar/commands"
	"github.com/bbockelm/cedar/security"
	cedarserver "github.com/bbockelm/cedar/server"
)

// TestServerFSIdentityCarriesUIDDomain runs an FS handshake against a cedar
// server built by GetServerSecurityConfig and checks the identity the handler
// sees is user@UID_DOMAIN, as a C++ daemon reports an FS peer. Without
// UID_DOMAIN on the config cedar falls back to the host name, which no
// ALLOW_* entry written for the pool's UID_DOMAIN matches.
func TestServerFSIdentityCarriesUIDDomain(t *testing.T) {
	cfg := mustConfig(t, `
SEC_DEFAULT_AUTHENTICATION = REQUIRED
SEC_DEFAULT_AUTHENTICATION_METHODS = FS
SEC_CLIENT_AUTHENTICATION_METHODS = FS
UID_DOMAIN = uid.example
`)
	sc, err := GetServerSecurityConfig(cfg, int(commands.DC_NOP), "DEFAULT")
	if err != nil {
		t.Fatal(err)
	}
	if sc.UIDDomain != "uid.example" {
		t.Errorf("server UIDDomain = %q, want uid.example", sc.UIDDomain)
	}
	sc.SessionCache = security.NewSessionCache()

	users := make(chan string, 1)
	srv := cedarserver.New(sc)
	srv.Handle(int(commands.DC_NOP), func(_ context.Context, c *cedarserver.Conn) error {
		users <- c.Negotiation.User
		return nil
	}, "READ")
	ln, err := net.Listen("tcp", "127.0.0.1:0") //nolint:noctx // test-only loopback listener
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	go func() { _ = srv.Serve(ctx, ln) }()
	t.Cleanup(func() { _ = ln.Close() })

	cc, err := GetSecurityConfig(cfg, int(commands.DC_NOP), "CLIENT")
	if err != nil {
		t.Fatal(err)
	}
	if cc.UIDDomain != "uid.example" {
		t.Errorf("client UIDDomain = %q, want uid.example", cc.UIDDomain)
	}
	cc.SessionCache = security.NewSessionCache()
	hc, err := client.ConnectAndAuthenticate(ctx, fmt.Sprintf("<%s>", ln.Addr()), cc)
	if err != nil {
		t.Fatalf("FS handshake: %v", err)
	}
	defer func() { _ = hc.Close() }()

	select {
	case user := <-users:
		// The user part is the OS account (or condor, for root under
		// FS_ROOT_TO_CONDOR); the domain is what this test is about.
		name, domain := security.SplitFQU(user)
		if name == "" || domain != "uid.example" {
			t.Errorf("FS peer authenticated as %q; want <user>@uid.example", user)
		}
	case <-ctx.Done():
		t.Fatal("handler never ran")
	}
}
