package httpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"slices"
	"testing"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
)

// TestArchiveMirrorReadRestatesTheWindow drives /api/v1/jobs/archive
// through ServeHTTP against a current mirror and checks the constraint the
// mirror was sent by what it answered.
//
// The rewrite is invisible on a record the mirror would actually archive,
// so the archive here also holds one it never would: 10.0, stamped two
// days before it was submitted. A QDate window matches it as written; it
// is missing from the answer only if the read carried the
// EnteredHistoryTime floor.
func TestArchiveMirrorReadRestatesTheWindow(t *testing.T) {
	signingKey := writeSigningKey(t)
	cfg := tokenPoolConfig(filepath.Dir(signingKey))
	schedd := newFakeReadSchedd(t, cfg)

	const q = 1757000000
	record := func(cluster, proc int, qdate, entered int64) string {
		return fmt.Sprintf("ClusterId = %d\nProcId = %d\nOwner = \"alice\"\nUser = %q\nJobStatus = 4\nQDate = %d\nEnteredHistoryTime = %d",
			cluster, proc, localAlice, qdate, entered)
	}
	history := []string{
		record(5, 0, q-5*86400, q-5*86400+10), // before the window
		record(10, 0, q, q-2*86400),           // stamped before it was submitted
		record(11, 0, q, q+100),
		record(11, 1, q, q+100),
		record(12, 0, q, q+200),
	}
	mirror := newFakeMirrorAds(t, cfg, nil, history)

	server, err := NewServer(Config{
		ListenAddr:      "127.0.0.1:0",
		ScheddName:      "fake-schedd",
		ScheddAddr:      schedd.addr,
		ClientConfig:    cfg,
		HTCondorConfig:  cfg,
		SigningKeyPath:  signingKey,
		TrustDomain:     mirrorAuthzTrustDomain,
		UIDDomain:       mirrorAuthzTrustDomain,
		SessionTTL:      time.Hour,
		OAuth2DBPath:    filepath.Join(t.TempDir(), "oauth2.db"),
		Collector:       htcondor.NewCollector("<127.0.0.1:1>"),
		DBMirrorAddress: mirror.addr,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	server.setupRoutes()
	sid, _, err := server.sessionStore.Create("alice")
	if err != nil {
		t.Fatalf("session create: %v", err)
	}

	list := func(t *testing.T, params url.Values) []string {
		t.Helper()
		params.Set("projection", "ClusterId,ProcId")
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
			"/api/v1/jobs/archive?"+params.Encode(), nil)
		req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sid}) //nolint:gosec // test cookie
		rec := httptest.NewRecorder()
		server.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
		}
		var reply jobsReply
		if err := json.Unmarshal(rec.Body.Bytes(), &reply); err != nil {
			t.Fatalf("decoding: %v (%s)", err, rec.Body.String())
		}
		if reply.Source != "htcondordb" {
			t.Fatalf("source %q, want the mirror", reply.Source)
		}
		var ids []string
		for _, row := range reply.rows() {
			ids = append(ids, fmt.Sprintf("%v.%v", row["ClusterId"], row["ProcId"]))
		}
		slices.Sort(ids)
		return ids
	}
	window := fmt.Sprintf("QDate >= %d && QDate < %d", q, q+86400)

	for _, c := range []struct {
		name   string
		params url.Values
		want   []string
	}{
		{"window", url.Values{"constraint": {window}}, []string{"11.0", "11.1", "12.0"}},
		{"window and cursor", url.Values{"constraint": {window}, "before_cluster": {"11"}, "before_proc": {"1"}}, []string{"11.0"}},
		// No window, no floor: the impossible record is there, and the
		// cursor still pages on (ClusterId, ProcId).
		{"cursor", url.Values{"before_cluster": {"11"}, "before_proc": {"1"}}, []string{"10.0", "11.0", "5.0"}},
		{"cursor at a cluster's first proc", url.Values{"before_cluster": {"11"}, "before_proc": {"0"}}, []string{"10.0", "5.0"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := list(t, c.params); !slices.Equal(got, c.want) {
				t.Errorf("got %v, want %v", got, c.want)
			}
		})
	}
}
