package sessioncache

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/client"
	"github.com/bbockelm/cedar/message"
	"github.com/bbockelm/cedar/security"
	cedarserver "github.com/bbockelm/cedar/server"
)

// TestEntryRecordRoundTripSessionAttributes: the attributes cedar records on a
// session -- the client's own identity and outcome (MyRemoteUserName,
// MyAuthenticated), the server's view of the peer (User, Authenticated) and
// the peer credential's authorization limits (LimitAuthorization) -- and the
// tag the session is stored under survive a persist/restore.
func TestEntryRecordRoundTripSessionAttributes(t *testing.T) {
	policy := classad.New()
	_ = policy.Set("User", "alice@pool.example")
	_ = policy.Set("Authenticated", true)
	_ = policy.Set("MyRemoteUserName", "condor@pool.example")
	_ = policy.Set("MyAuthenticated", false)
	_ = policy.Set(security.AttrLimitAuthorization, "READ,ADVERTISE_STARTD")
	ki := &security.KeyInfo{Data: []byte("session-key-attrs"), Protocol: "AESGCM"}
	orig := security.NewSessionEntry("attrs-1", "<10.0.0.1:9618>", ki, policy,
		time.Now().Add(time.Hour), 30*time.Minute, "token-sha256:abcd")

	got, err := RecordToEntry(EntryToRecord(orig))
	if err != nil {
		t.Fatal(err)
	}
	if got.Tag() != "token-sha256:abcd" {
		t.Errorf("tag = %q, want token-sha256:abcd", got.Tag())
	}
	for attr, want := range map[string]string{
		"User":                          "alice@pool.example",
		"MyRemoteUserName":              "condor@pool.example",
		security.AttrLimitAuthorization: "READ,ADVERTISE_STARTD",
	} {
		if v, ok := got.Policy().EvaluateAttrString(attr); !ok || v != want {
			t.Errorf("%s = %q (ok=%v), want %q", attr, v, ok, want)
		}
	}
	for attr, want := range map[string]bool{"Authenticated": true, "MyAuthenticated": false} {
		if v, ok := got.Policy().EvaluateAttrBool(attr); !ok || v != want {
			t.Errorf("%s = %v (ok=%v), want %v", attr, v, ok, want)
		}
	}
}

const (
	readCmd  = 81011 // registered at READ
	writeCmd = 81012 // registered at WRITE
)

// limitedServer serves readCmd and writeCmd over TOKEN, authorizing every
// authenticated identity at every level, so only a session's authorization
// limits can refuse a command. A cedar server keeps its sessions in the
// process-wide cache, which is the one a daemon persists.
func limitedServer(t *testing.T, keyFile string) string {
	t.Helper()
	srv := cedarserver.New(&security.SecurityConfig{
		AuthMethods:             []security.AuthMethod{security.AuthToken},
		Authentication:          security.SecurityRequired,
		CryptoMethods:           []security.CryptoMethod{security.CryptoAES},
		Encryption:              security.SecurityOptional,
		Integrity:               security.SecurityOptional,
		TrustDomain:             "pool.example",
		TokenPoolSigningKeyFile: keyFile,
	})
	srv.Authorizer = func(_, _, user string) bool { return user != cedarserver.UnauthenticatedFQU }
	reply := func(ctx context.Context, c *cedarserver.Conn) error {
		m := message.NewMessageForStream(c.Stream)
		if err := m.PutInt(ctx, 1); err != nil {
			return err
		}
		return m.FinishMessage(ctx)
	}
	srv.Handle(readCmd, reply, "READ")
	srv.Handle(writeCmd, reply, "WRITE")
	ln, err := net.Listen("tcp", "127.0.0.1:0") //nolint:noctx // test-only loopback listener
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = srv.Serve(ctx, ln) }()
	t.Cleanup(func() { cancel(); _ = ln.Close() })
	return fmt.Sprintf("<%s>", ln.Addr())
}

// run sends cmd under sec and reports whether the server ran it.
func run(t *testing.T, addr string, sec *security.SecurityConfig, cmd int) (*security.SecurityNegotiation, bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cfg := *sec
	cfg.Command = cmd
	hc, err := client.ConnectAndAuthenticate(ctx, addr, &cfg)
	if err != nil {
		return nil, false
	}
	defer func() { _ = hc.Close() }()
	v, err := message.NewMessageFromStream(hc.GetStream()).GetInt(ctx)
	return hc.GetSecurityNegotiation(), err == nil && v == 1
}

// TestRestoredSessionKeepsAuthorizationLimits: a session negotiated with a
// token limited to READ is persisted, dropped from the cache and restored
// into it (a restart), and resumed by id on a new server. It still runs READ and is still refused
// WRITE: the restored session is bounded as the live one was.
func TestRestoredSessionKeepsAuthorizationLimits(t *testing.T) {
	keyDir := t.TempDir()
	keyFile := filepath.Join(keyDir, "POOL")
	if err := os.WriteFile(keyFile, []byte("restore-limits-test-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	tok, err := security.GenerateJWT(keyDir, "POOL", "alice@pool.example", "pool.example", now, now+3600, []string{"READ"})
	if err != nil {
		t.Fatalf("GenerateJWT: %v", err)
	}
	sec := &security.SecurityConfig{
		AuthMethods:    []security.AuthMethod{security.AuthToken},
		Authentication: security.SecurityRequired,
		CryptoMethods:  []security.CryptoMethod{security.CryptoAES},
		Encryption:     security.SecurityOptional,
		Integrity:      security.SecurityOptional,
		Token:          tok,
		SessionCache:   security.NewSessionCache(),
	}

	cache := security.GetSessionCache()
	addr := limitedServer(t, keyFile)
	neg, ok := run(t, addr, sec, readCmd)
	if !ok {
		t.Fatal("a READ-limited token was refused READ")
	}
	sid := neg.SessionId
	if _, ok := run(t, addr, sec, writeCmd); ok {
		t.Fatal("precondition: a READ-limited token ran WRITE before the restart")
	}

	store := &memStore{}
	for _, r := range Snapshot(cache) {
		if r.ID == sid {
			store.recs = append(store.recs, r)
		}
	}
	if len(store.recs) != 1 {
		t.Fatalf("snapshot holds %d records for the session, want 1", len(store.recs))
	}
	cache.Invalidate(sid)
	t.Cleanup(func() { cache.Invalidate(sid) })
	if n, err := Restore(context.Background(), store, cache, nil); err != nil || n != 1 {
		t.Fatalf("Restore: n=%d err=%v", n, err)
	}
	addr = limitedServer(t, keyFile)

	resume := *sec
	resume.SessionID = sid
	resume.Token = "" // only the restored session can authenticate this connection
	if neg, ok := run(t, addr, &resume, readCmd); !ok || !neg.SessionResumed {
		t.Fatalf("the restored session did not resume for READ (ran=%v)", ok)
	}
	if _, ok := run(t, addr, &resume, writeCmd); ok {
		t.Error("the restored session ran WRITE; its READ limit was lost in the restore")
	}
}
