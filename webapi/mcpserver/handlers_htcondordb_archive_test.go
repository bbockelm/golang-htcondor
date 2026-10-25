package mcpserver

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/PelicanPlatform/classad/db"
	"github.com/PelicanPlatform/classad/dbrpc"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/config"
	"github.com/bbockelm/golang-htcondor/webapi/dbmirror"
)

// testHistoryMirror is an in-process htcondordb whose tables have the kinds
// production gives them: "jobs" a plain table and "history" an ARCHIVE,
// created with the config htcondordb's schedd-sync uses
// (cmd/htcondordb/scheddsync_manager.go).
//
// The kind is the point. query_history_db read "history" with
// dbrpc.Client.QueryTable, whose op resolves plain tables only, and
// failed every call in production with "no such table: history". A
// fixture that made history a plain table would have answered that op
// and passed.
type testHistoryMirror struct {
	srv *dbrpc.Server
	cat *db.Catalog
	// wrap, when set, wraps the server's end of each session, so a test
	// can make the mirror answer some requests the way a different
	// server version would.
	wrap func(dbrpc.MsgConn) dbrpc.MsgConn
}

func newHistoryMirror(t *testing.T) *testHistoryMirror {
	t.Helper()
	cat, err := db.OpenCatalog(t.TempDir())
	if err != nil {
		t.Fatalf("open catalog: %v", err)
	}
	if _, err := cat.CreateTable("jobs"); err != nil {
		t.Fatalf("create jobs table: %v", err)
	}
	if _, err := cat.CreateArchiveTable("history", db.ArchiveConfig{
		ZoneAttrs: []string{"CompletionDate", "EnteredHistoryTime"},
	}); err != nil {
		t.Fatalf("create history archive: %v", err)
	}
	if _, ok := cat.ArchiveTable("history"); !ok {
		t.Fatal("history must be an archive, as in production")
	}
	if _, ok := cat.Table("history"); ok {
		t.Fatal("history must not also be a plain table; production has no such table")
	}
	srv := dbrpc.NewServerCatalog(cat)
	t.Cleanup(func() { srv.Close(); _ = cat.Close() })
	return &testHistoryMirror{srv: srv, cat: cat}
}

// dial opens a session over a fresh pipe, in the shape Server.dbClient
// returns.
func (m *testHistoryMirror) dial(context.Context) (*dbrpc.Client, func(), *dbmirror.Info, error) {
	c, s := net.Pipe()
	sconn := dbrpc.NewStreamConn(s)
	if m.wrap != nil {
		sconn = m.wrap(sconn)
	}
	go func() { _ = m.srv.ServeConn(sconn) }()
	cl := dbrpc.NewClient(dbrpc.NewStreamConn(c))
	return cl, func() { _ = cl.Close() }, &dbmirror.Info{Name: "test-mirror"}, nil
}

// archive appends a completed job the way the history syncer does. The
// Environment is large and outside the default working set, so a row
// carrying it shows the projection was not applied.
func (m *testHistoryMirror) archive(t *testing.T, owner string, cluster int) {
	t.Helper()
	cl, closer, _, _ := m.dial(context.Background())
	defer closer()
	ad := fmt.Sprintf("ClusterId = %d\nProcId = 0\nOwner = %q\nJobStatus = 4\nExitCode = 0\n"+
		"CompletionDate = %d\nEnteredHistoryTime = %d\nEnvironment = %q",
		cluster, owner, 1700000000+cluster, 1700000000+cluster, strings.Repeat("X=1 ", 64))
	if err := cl.ArchiveAppend(context.Background(), "history", ad); err != nil {
		t.Fatalf("archive append: %v", err)
	}
}

// historyServer is a Server whose DB tools read m.
func historyServer(m *testHistoryMirror, admins ...string) *Server {
	s := &Server{
		dbMirror:   dbmirror.NewLocator(htcondor.NewCollector("collector.example"), config.NewEmpty()),
		dbClientFn: m.dial,
	}
	if len(admins) > 0 {
		s.adminUsers = map[string]struct{}{}
		for _, a := range admins {
			s.adminUsers[a] = struct{}{}
		}
	}
	return s
}

// historyCall runs query_history_db and returns its records, has_more
// and text.
func historyCall(t *testing.T, s *Server, user string, args map[string]interface{}) ([]*classad.ClassAd, bool, string) {
	t.Helper()
	ctx := htcondor.WithAuthenticatedUser(context.Background(), user)
	res, err := s.toolQueryHistoryDB(ctx, args)
	if err != nil {
		t.Fatalf("query_history_db: %v", err)
	}
	m, ok := res.(map[string]interface{})
	if !ok {
		t.Fatalf("result is %T, want a map", res)
	}
	sc, _ := m["structuredContent"].(map[string]interface{})
	records, _ := sc["records"].([]*classad.ClassAd)
	hasMore, _ := sc["has_more"].(bool)
	content, _ := m["content"].([]map[string]interface{})
	text := ""
	if len(content) > 0 {
		text, _ = content[0]["text"].(string)
	}
	return records, hasMore, text
}

// TestQueryHistoryDBReadsTheArchive is the regression test for
// query_history_db failing on every call against a real htcondordb
// ("dbrpc: no such table: history"): it must read history as the
// archive it is, owner-scoped, newest first, with the default projection.
func TestQueryHistoryDBReadsTheArchive(t *testing.T) {
	m := newHistoryMirror(t)
	m.archive(t, "alice", 1)
	m.archive(t, "bob", 2)
	m.archive(t, "alice", 3)
	m.archive(t, "alice", 4)
	s := historyServer(m)

	records, hasMore, text := historyCall(t, s, "alice", map[string]interface{}{})
	if got := fmt.Sprint(clusters(t, records)); got != "[4 3 1]" {
		t.Errorf("alice's history = %s, want [4 3 1]: her own jobs, most recently archived first", got)
	}
	if hasMore {
		t.Error("has_more = true with every match returned")
	}
	for _, r := range records {
		if owner, _ := r.EvaluateAttrString("Owner"); owner != "alice" {
			t.Errorf("owner scoping leaked a record owned by %q", owner)
		}
		if _, ok := r.Lookup("Environment"); ok {
			t.Error("Environment returned without being asked for: the default projection was not applied")
		}
		if _, ok := r.Lookup("CompletionDate"); !ok {
			t.Error("CompletionDate missing: it is in the default working set")
		}
	}
	if !strings.Contains(text, "most recently archived first") {
		t.Errorf("text does not say what order the records are in: %q", text)
	}
}

// TestQueryHistoryDBLimitIsTheNewest: a limit keeps the newest matches,
// and has_more is true only when a match was actually left out -- not
// merely because the page came back full.
func TestQueryHistoryDBLimitIsTheNewest(t *testing.T) {
	m := newHistoryMirror(t)
	for c := 1; c <= 3; c++ {
		m.archive(t, "alice", c)
	}
	s := historyServer(m)

	records, hasMore, _ := historyCall(t, s, "alice", map[string]interface{}{"limit": float64(2)})
	if got := fmt.Sprint(clusters(t, records)); got != "[3 2]" {
		t.Errorf("limit=2 returned %s, want the newest two [3 2]", got)
	}
	if !hasMore {
		t.Error("has_more = false with a match left out")
	}

	records, hasMore, _ = historyCall(t, s, "alice", map[string]interface{}{"limit": float64(3)})
	if len(records) != 3 {
		t.Errorf("limit=3 returned %d records, want 3", len(records))
	}
	if hasMore {
		t.Error("has_more = true when the limit exactly equals the matches")
	}
}

// TestQueryHistoryDBProjection: a named projection narrows the rows, and
// ["*"] returns every attribute and says what that costs.
func TestQueryHistoryDBProjection(t *testing.T) {
	m := newHistoryMirror(t)
	m.archive(t, "alice", 1)
	s := historyServer(m)

	records, _, _ := historyCall(t, s, "alice", map[string]interface{}{"projection": []interface{}{"ClusterId", "ExitCode"}})
	if len(records) != 1 {
		t.Fatalf("got %d records, want 1", len(records))
	}
	if _, ok := records[0].Lookup("ExitCode"); !ok {
		t.Error("projected ExitCode missing")
	}
	if _, ok := records[0].Lookup("CompletionDate"); ok {
		t.Error("CompletionDate returned outside the requested projection")
	}

	records, _, text := historyCall(t, s, "alice", map[string]interface{}{"projection": []interface{}{"*"}})
	if len(records) != 1 {
		t.Fatalf("got %d records, want 1", len(records))
	}
	if _, ok := records[0].Lookup("Environment"); !ok {
		t.Error(`["*"] did not return every attribute`)
	}
	if !strings.Contains(text, "Returning every attribute") {
		t.Errorf(`["*"] answer does not carry the cost note: %q`, text)
	}
}

// TestQueryHistoryDBAdminSeesEveryOwner: scoping is unchanged by the
// switch of op -- an MCP admin is unconfined.
func TestQueryHistoryDBAdminSeesEveryOwner(t *testing.T) {
	m := newHistoryMirror(t)
	m.archive(t, "alice", 1)
	m.archive(t, "bob", 2)
	s := historyServer(m, "root")

	records, _, _ := historyCall(t, s, "root", map[string]interface{}{})
	if got := fmt.Sprint(clusters(t, records)); got != "[2 1]" {
		t.Errorf("admin history = %s, want every owner's [2 1]", got)
	}
}
