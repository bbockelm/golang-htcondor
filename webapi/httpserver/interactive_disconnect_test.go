package httpserver

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/commands"
	"github.com/bbockelm/cedar/message"
	"github.com/bbockelm/cedar/security"
	cedarserver "github.com/bbockelm/cedar/server"
	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/config"
	"github.com/bbockelm/golang-htcondor/logging"
)

// tokenPool is a pool for trust domain "pool.example" whose daemons accept
// only IDTOKENs signed with one key, with this daemon's own token in the
// configured token directory.
type tokenPool struct {
	keyDir string
	cfg    *config.Config
}

func newTokenPool(t *testing.T) *tokenPool {
	t.Helper()
	p := &tokenPool{keyDir: t.TempDir()}
	if err := os.WriteFile(filepath.Join(p.keyDir, "POOL"), []byte("token-pool-test-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	tokenDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(tokenDir, "condor"), []byte(p.mint(t, "condor@pool.example", time.Hour)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p.cfg = clientConfigFrom(t, `
SEC_CLIENT_AUTHENTICATION = REQUIRED
SEC_CLIENT_AUTHENTICATION_METHODS = IDTOKENS
SEC_CLIENT_CRYPTO_METHODS = AES
SEC_TOKEN_DIRECTORY = `+tokenDir+`
TRUST_DOMAIN = pool.example
UID_DOMAIN = pool.example
`)
	return p
}

// mint signs an IDTOKEN for sub, valid for ttl from now (negative: already
// expired).
func (p *tokenPool) mint(t *testing.T, sub string, ttl time.Duration) string {
	t.Helper()
	now := time.Now()
	tok, err := security.GenerateJWT(p.keyDir, "POOL", sub, "pool.example", now.Add(-time.Hour).Unix(), now.Add(ttl).Unix(), nil)
	if err != nil {
		t.Fatalf("GenerateJWT: %v", err)
	}
	return tok
}

// serve starts a CEDAR daemon of this pool with the given handlers.
func (p *tokenPool) serve(t *testing.T, handlers map[int]cedarserver.HandlerFunc) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0") //nolint:noctx // test-only loopback listener
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := cedarserver.New(&security.SecurityConfig{
		AuthMethods:             []security.AuthMethod{security.AuthToken},
		Authentication:          security.SecurityRequired,
		CryptoMethods:           []security.CryptoMethod{security.CryptoAES},
		Encryption:              security.SecurityOptional,
		Integrity:               security.SecurityOptional,
		TrustDomain:             "pool.example",
		TokenPoolSigningKeyFile: filepath.Join(p.keyDir, "POOL"),
		SessionCache:            security.NewSessionCache(),
	})
	srv.Handle(int(commands.DC_NOP), func(context.Context, *cedarserver.Conn) error { return nil }, "READ")
	for cmd, h := range handlers {
		srv.Handle(cmd, h, "READ")
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = srv.Serve(ctx, ln) }()
	t.Cleanup(func() { cancel(); _ = ln.Close() })
	return fmt.Sprintf("<%s>", ln.Addr().String())
}

// removal is one ACT_ON_JOBS request a fake schedd received.
type removal struct {
	user       string
	constraint string
}

// recordingRemovals answers ACT_ON_JOBS by recording who asked and with what
// constraint, and refusing.
func recordingRemovals() (cedarserver.HandlerFunc, func() []removal) {
	var mu sync.Mutex
	var got []removal
	h := func(ctx context.Context, c *cedarserver.Conn) error {
		ad, err := message.NewMessageFromStream(c.Stream).GetClassAd(ctx)
		if err != nil {
			return err
		}
		constraint := ""
		if expr, ok := ad.Lookup("ActionConstraint"); ok {
			constraint = expr.String()
		}
		mu.Lock()
		got = append(got, removal{user: c.AuthorizationUser(), constraint: constraint})
		mu.Unlock()
		reply := classad.New()
		_ = reply.Set("ActionResult", int64(0))
		out := message.NewMessageForStream(c.Stream)
		if err := out.PutClassAd(ctx, reply); err != nil {
			return err
		}
		return out.FinishMessage(ctx)
	}
	return h, func() []removal {
		mu.Lock()
		defer mu.Unlock()
		return append([]removal(nil), got...)
	}
}

// Closing the last terminal of an interactive session removes the job: as
// the caller when their request carried a credential, and confined to the
// caller's own jobs either way.
func TestInteractiveDisconnectRemovesOnlyTheCallersJob(t *testing.T) {
	logger, err := logging.New(&logging.Config{OutputPath: "stderr"})
	if err != nil {
		t.Fatal(err)
	}
	pool := newTokenPool(t)
	act, removals := recordingRemovals()
	addr := pool.serve(t, map[int]cedarserver.HandlerFunc{int(commands.ACT_ON_JOBS): act})
	h := &Handler{
		logger:       logger,
		clientConfig: pool.cfg,
		schedd:       htcondor.NewSchedd("fake", addr).WithConfig(pool.cfg),
	}

	caller := func(withCredential bool) context.Context {
		ctx := htcondor.WithUserRequest(context.Background(), "test request")
		ctx = htcondor.WithAuthenticatedUser(ctx, "alice@pool.example")
		if withCredential {
			sec, err := configureSecurityForToken(pool.cfg, pool.mint(t, "alice@pool.example", time.Hour), nil, false)
			if err != nil {
				t.Fatal(err)
			}
			ctx = htcondor.WithSecurityConfig(ctx, sec)
		}
		// Cancelled, as the bridge's request context is by the time the
		// removal runs.
		ctx, cancel := context.WithCancel(ctx)
		cancel()
		return ctx
	}

	h.removeJobOnDisconnect(caller(true), "5.0")
	h.removeJobOnDisconnect(caller(false), "6.0")
	got := removals()
	if len(got) != 2 {
		t.Fatalf("schedd saw %d removals, want 2: %+v", len(got), got)
	}
	for i, want := range []struct{ user, job string }{
		{"alice@pool.example", "ClusterId == 5"},
		{"condor@pool.example", "ClusterId == 6"},
	} {
		r := got[i]
		if r.user != want.user {
			t.Errorf("removal %d ran as %q, want %q", i, r.user, want.user)
		}
		if !strings.Contains(r.constraint, want.job) || !strings.Contains(r.constraint, `Owner == "alice"`) {
			t.Errorf("removal %d constraint = %q, want %s confined to Owner == \"alice\"", i, r.constraint, want.job)
		}
	}

	// With no caller identity there is no owner to confine it to, and
	// nothing is removed.
	h.removeJobOnDisconnect(htcondor.WithUserRequest(context.Background(), "test request"), "7.0")
	if n := len(removals()); n != 2 {
		t.Errorf("a removal with no caller identity reached the schedd")
	}
}
