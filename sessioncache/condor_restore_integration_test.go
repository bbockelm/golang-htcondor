//go:build integration

package sessioncache_test

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/client"
	"github.com/bbockelm/cedar/commands"
	"github.com/bbockelm/cedar/message"
	"github.com/bbockelm/cedar/security"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/sessioncache"
	"github.com/bbockelm/golang-htcondor/sessioncache/sqlite"
)

// TestRestoredSessionResumesWithCondorCollector: a session negotiated with a
// C++ collector that requires encryption is persisted to the encrypted store
// and restored into a fresh cache (a restart of this side only, so the
// collector still holds the session). A query naming the session resumes it
// rather than authenticating again, and its encrypted request and reply are
// read by both ends: the restored key and cipher are the ones the collector
// keyed the session with. The command-to-session map is not persisted, so the
// query names the session by id.
func TestRestoredSessionResumesWithCondorCollector(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	h := htcondor.SetupCondorHarnessWithConfig(t, `
SEC_DEFAULT_ENCRYPTION = REQUIRED
SEC_DEFAULT_INTEGRITY = REQUIRED
`)
	defer h.Shutdown()
	addr := h.GetCollectorAddr()

	sec := func(cache *security.SessionCache, sid string) *security.SecurityConfig {
		return &security.SecurityConfig{
			Command:        commands.QUERY_SCHEDD_ADS,
			AuthMethods:    []security.AuthMethod{security.AuthFS},
			Authentication: security.SecurityRequired,
			CryptoMethods:  []security.CryptoMethod{security.CryptoAES},
			Encryption:     security.SecurityRequired,
			Integrity:      security.SecurityRequired,
			SessionCache:   cache,
			SessionID:      sid,
		}
	}
	// query sends QUERY_SCHEDD_ADS, resuming session sid if set, and returns
	// the negotiation and how many ads came back before the end-of-results
	// marker.
	query := func(cache *security.SessionCache, sid string) (*security.SecurityNegotiation, int) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		hc, err := client.ConnectAndAuthenticate(ctx, addr, sec(cache, sid))
		if err != nil {
			t.Fatalf("connect to the collector: %v", err)
		}
		defer func() { _ = hc.Close() }()
		q := classad.New()
		_ = q.Set("MyType", "Query")
		_ = q.Set("TargetType", "Scheduler")
		_ = q.Set("Requirements", true)
		out := message.NewMessageForStream(hc.GetStream())
		if err := out.PutClassAd(ctx, q); err != nil {
			t.Fatalf("send query: %v", err)
		}
		if err := out.FinishMessage(ctx); err != nil {
			t.Fatalf("send query: %v", err)
		}
		in := message.NewMessageFromStream(hc.GetStream())
		n := 0
		for {
			more, err := in.GetInt32(ctx)
			if err != nil {
				t.Fatalf("read reply after %d ads: %v", n, err)
			}
			if more == 0 {
				return hc.GetSecurityNegotiation(), n
			}
			if _, err := in.GetClassAd(ctx); err != nil {
				t.Fatalf("read ad %d: %v", n+1, err)
			}
			n++
		}
	}

	// Wait for the schedd ad, so an empty reply cannot pass for a read one.
	live := security.NewSessionCache()
	var neg *security.SecurityNegotiation
	for deadline := time.Now().Add(60 * time.Second); ; {
		var n int
		if neg, n = query(live, ""); n > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the collector never returned a schedd ad")
		}
		time.Sleep(time.Second)
	}
	if !neg.Encryption {
		t.Fatal("precondition: the session with the collector is not encrypted")
	}
	sid := neg.SessionId
	if sid == "" {
		t.Fatal("precondition: the collector created no session")
	}

	path := filepath.Join(t.TempDir(), "sessions.db")
	keys := []sqlite.SigningKey{{ID: "POOL", Material: bytes.Repeat([]byte{9}, 24)}}
	store, err := sqlite.Open(path, keys, nil)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if err := store.Save(context.Background(), sessioncache.Snapshot(live)); err != nil {
		t.Fatalf("save: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	restored := security.NewSessionCache()
	store, err = sqlite.Open(path, keys, nil)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	defer func() { _ = store.Close() }()
	if n, err := sessioncache.Restore(context.Background(), store, restored, nil); err != nil || n == 0 {
		t.Fatalf("Restore: n=%d err=%v", n, err)
	}
	if _, ok := restored.LookupNonExpired(sid); !ok {
		t.Fatal("the collector session was not restored")
	}

	neg, n := query(restored, sid)
	if !neg.SessionResumed || neg.SessionId != sid {
		t.Fatalf("the query did not resume the restored session (resumed=%v sid match=%v)", neg.SessionResumed, neg.SessionId == sid)
	}
	if !neg.Encryption {
		t.Error("the resumed connection is not encrypted")
	}
	if n == 0 {
		t.Error("the resumed query returned no schedd ad")
	}
}
