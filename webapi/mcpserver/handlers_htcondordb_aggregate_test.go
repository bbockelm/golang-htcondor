package mcpserver

import (
	"context"
	"encoding/binary"
	"fmt"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/PelicanPlatform/classad/db"
	"github.com/PelicanPlatform/classad/dbrpc"

	htcondor "github.com/bbockelm/golang-htcondor"
)

// Request opcodes and response statuses of the dbrpc wire protocol, as
// the fake older mirrors below need them. They are the protocol, so they
// cannot change under a client without breaking every deployed mirror.
const (
	wireOpAggregate                = 15 // AggregateTable, unfiltered
	wireOpAggregateBucketed        = 45 // AggregateBucketedTable
	wireOpArchiveAggregate         = 53 // ArchiveAggregate
	wireOpAggregateFiltered        = 55 // AggregateTable / AggregateBucketedTable with filters
	wireOpArchiveAggregateFiltered = 56 // ArchiveAggregate(Bucketed) with widths or filters
	wireOpArchiveAggregateStats    = 65 // ArchiveAggregateStats

	wireStErr    = -1
	wireStBadReq = -4
)

// olderMirrorConn is the server end of a session made to answer some
// requests the way an older htcondordb did, without running one.
//
// answer is consulted for each request frame before the real server
// sees it; a non-nil reply is written back in place of the server's
// answer and the request is dropped.
type olderMirrorConn struct {
	dbrpc.MsgConn
	wmu    sync.Mutex // the server and answer both write
	answer func(reqID uint64, op byte, body []byte) []byte
}

func (c *olderMirrorConn) WriteMsg(b []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	return c.MsgConn.WriteMsg(b)
}

func (c *olderMirrorConn) ReadMsg() ([]byte, error) {
	for {
		frame, err := c.MsgConn.ReadMsg()
		if err != nil || len(frame) < 9 {
			return frame, err
		}
		reqID := binary.LittleEndian.Uint64(frame)
		if reply := c.answer(reqID, frame[8], frame[9:]); reply != nil {
			if werr := c.WriteMsg(reply); werr != nil {
				return nil, werr
			}
			continue
		}
		return frame, nil
	}
}

// wireStr reads the leading length-prefixed string of a request body:
// for every aggregate opcode, the table name.
func wireStr(body []byte) string {
	if len(body) < 4 {
		return ""
	}
	n := int(binary.LittleEndian.Uint32(body))
	if len(body)-4 < n {
		return ""
	}
	return string(body[4 : 4+n])
}

func wireResp(reqID uint64, status int32) []byte {
	b := binary.LittleEndian.AppendUint64(nil, reqID)
	//nolint:gosec // G115: the wire carries the status's two's-complement bits
	return binary.LittleEndian.AppendUint32(b, uint32(status))
}

func wireErr(reqID uint64, msg string) []byte {
	b := wireResp(reqID, wireStErr)
	//nolint:gosec // G115: a test's error message, nowhere near 4GiB
	b = binary.LittleEndian.AppendUint32(b, uint32(len(msg)))
	return append(b, msg...)
}

// tableAggregatesSkipArchives makes m answer the table aggregate opcodes
// the way htcondordb did before a table name resolved to an archive for
// them: "no such table" for any archive. Every other read of the same
// name -- the projection reads, the archive aggregate -- still works,
// which is what made the mistake invisible from the outside.
func (m *testHistoryMirror) tableAggregatesSkipArchives() {
	m.wrap = func(sc dbrpc.MsgConn) dbrpc.MsgConn {
		return &olderMirrorConn{MsgConn: sc, answer: func(reqID uint64, op byte, body []byte) []byte {
			switch op {
			case wireOpAggregate, wireOpAggregateBucketed, wireOpAggregateFiltered:
				if table := wireStr(body); table != "" {
					if _, isArchive := m.cat.ArchiveTable(table); isArchive {
						return wireErr(reqID, "no such table: "+table)
					}
				}
			}
			return nil
		}}
	}
}

// noArchiveAggregates makes m refuse the archive aggregate opcodes as a
// server too old to know them does: a bad request.
func (m *testHistoryMirror) noArchiveAggregates() {
	m.wrap = func(sc dbrpc.MsgConn) dbrpc.MsgConn {
		return &olderMirrorConn{MsgConn: sc, answer: func(reqID uint64, op byte, _ []byte) []byte {
			switch op {
			case wireOpArchiveAggregate, wireOpArchiveAggregateFiltered, wireOpArchiveAggregateStats,
				// A server that old does not resolve archives for the
				// table opcodes either.
				wireOpAggregate, wireOpAggregateBucketed, wireOpAggregateFiltered:
				return wireResp(reqID, wireStBadReq)
			}
			return nil
		}}
	}
}

// appendTo appends ad (old ClassAd text) to the archive named table.
func (m *testHistoryMirror) appendTo(t *testing.T, table, ad string) {
	t.Helper()
	cl, closer, _, _ := m.dial(context.Background())
	defer closer()
	if err := cl.ArchiveAppend(context.Background(), table, ad); err != nil {
		t.Fatalf("append to %s: %v", table, err)
	}
}

// insertJob adds a live job to the plain table named table.
func (m *testHistoryMirror) insertJob(t *testing.T, table, key, ad string) {
	t.Helper()
	ctx := context.Background()
	cl, closer, _, _ := m.dial(ctx)
	defer closer()
	tx, err := cl.BeginTable(ctx, table)
	if err != nil {
		t.Fatalf("begin %s: %v", table, err)
	}
	if err := tx.NewClassAd(ctx, key, ad); err != nil {
		t.Fatalf("insert into %s: %v", table, err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit %s: %v", table, err)
	}
}

// completed appends a finished job of owner's to history.
func (m *testHistoryMirror) completed(t *testing.T, owner string, cluster, exitCode int) {
	t.Helper()
	m.appendTo(t, "history", fmt.Sprintf("ClusterId = %d\nProcId = 0\nOwner = %q\nJobStatus = 4\nExitCode = %d\n"+
		"CompletionDate = %d\nEnteredHistoryTime = %d", cluster, owner, exitCode, 1700000000+cluster, 1700000000+cluster))
}

// aggregateCall runs aggregate_jobs as user and returns its groups as
// "key=count" strings, sorted, and its text.
func aggregateCall(t *testing.T, s *Server, user string, args map[string]interface{}) ([]string, string, error) {
	t.Helper()
	ctx := htcondor.WithAuthenticatedUser(context.Background(), user)
	res, err := s.toolAggregateJobs(ctx, args)
	if err != nil {
		return nil, "", err
	}
	m, ok := res.(map[string]interface{})
	if !ok {
		t.Fatalf("result is %T, want a map", res)
	}
	sc, _ := m["structuredContent"].(map[string]interface{})
	groups, _ := sc["groups"].([]map[string]interface{})
	var out []string
	for _, g := range groups {
		key, _ := g["key"].([]string)
		out = append(out, fmt.Sprintf("%s=%v", strings.Join(key, "/"), g["count"]))
	}
	sort.Strings(out)
	content, _ := m["content"].([]map[string]interface{})
	text := ""
	if len(content) > 0 {
		text, _ = content[0]["text"].(string)
	}
	return out, text, nil
}

// TestAggregateJobsHistoryReadsTheArchive: aggregate_jobs over history
// must reach the archive, owner-scoped, on a mirror whose table
// aggregates resolve archives and on one whose do not. It sent the table
// opcode, which on the second answers "no such table: history" while
// query_history_db reads the same name fine.
func TestAggregateJobsHistoryReadsTheArchive(t *testing.T) {
	for _, older := range []bool{false, true} {
		t.Run(fmt.Sprintf("table_aggregates_skip_archives=%v", older), func(t *testing.T) {
			m := newHistoryMirror(t)
			if older {
				m.tableAggregatesSkipArchives()
			}
			m.completed(t, "alice", 1, 0)
			m.completed(t, "alice", 2, 0)
			m.completed(t, "alice", 3, 1)
			m.completed(t, "bob", 4, 0)
			m.completed(t, "bob", 5, 2)
			s := historyServer(m, "root")

			got, text, err := aggregateCall(t, s, "alice", map[string]interface{}{
				"table": "history", "group_by": []interface{}{"ExitCode"},
			})
			if err != nil {
				t.Fatalf("aggregate_jobs over history: %v", err)
			}
			if want := "[0=2 1=1]"; fmt.Sprint(got) != want {
				t.Errorf("alice's history by ExitCode = %v, want %s: her own jobs only", got, want)
			}
			if !strings.Contains(text, `"history"`) {
				t.Errorf("text does not name the table: %q", text)
			}

			// A constraint narrows within the owner scope, never past it.
			got, _, err = aggregateCall(t, s, "alice", map[string]interface{}{
				"table": "history", "constraint": `Owner == "bob" || ExitCode == 1`,
			})
			if err != nil {
				t.Fatalf("aggregate_jobs with a constraint: %v", err)
			}
			if want := "[=1]"; fmt.Sprint(got) != want {
				t.Errorf("alice's count under an || constraint = %v, want %s: the owner scope must hold", got, want)
			}

			// An MCP admin is unconfined, as for every other read.
			got, _, err = aggregateCall(t, s, "root", map[string]interface{}{
				"table": "history", "group_by": []interface{}{"Owner"},
			})
			if err != nil {
				t.Fatalf("admin aggregate_jobs: %v", err)
			}
			if want := "[alice=3 bob=2]"; fmt.Sprint(got) != want {
				t.Errorf("admin history by Owner = %v, want %s", got, want)
			}
		})
	}
}

// TestAggregateJobsOtherArchives: epoch_history and job_metrics are
// archives too, and aggregate the same way.
func TestAggregateJobsOtherArchives(t *testing.T) {
	m := newHistoryMirror(t)
	m.tableAggregatesSkipArchives()
	for _, table := range []string{"epoch_history", "job_metrics"} {
		if _, err := m.cat.CreateArchiveTable(table, db.ArchiveConfig{}); err != nil {
			t.Fatalf("create %s archive: %v", table, err)
		}
		for i, owner := range []string{"alice", "alice", "bob"} {
			m.appendTo(t, table, fmt.Sprintf("ClusterId = %d\nProcId = 0\nOwner = %q", i+1, owner))
		}
	}
	s := historyServer(m)

	for _, table := range []string{"epoch_history", "job_metrics"} {
		got, _, err := aggregateCall(t, s, "alice", map[string]interface{}{"table": table})
		if err != nil {
			t.Errorf("aggregate_jobs over %s: %v", table, err)
			continue
		}
		if want := "[=2]"; fmt.Sprint(got) != want {
			t.Errorf("alice's %s count = %v, want %s", table, got, want)
		}
	}
}

// TestAggregateJobsLiveTableUnchanged: the live queue is a plain table
// and still aggregates as one.
func TestAggregateJobsLiveTableUnchanged(t *testing.T) {
	m := newHistoryMirror(t)
	m.tableAggregatesSkipArchives()
	m.insertJob(t, "jobs", "1.0", `ClusterId = 1
ProcId = 0
Owner = "alice"
JobStatus = 1`)
	m.insertJob(t, "jobs", "2.0", `ClusterId = 2
ProcId = 0
Owner = "alice"
JobStatus = 2`)
	m.insertJob(t, "jobs", "3.0", `ClusterId = 3
ProcId = 0
Owner = "bob"
JobStatus = 1`)
	s := historyServer(m)

	got, _, err := aggregateCall(t, s, "alice", map[string]interface{}{"group_by": []interface{}{"JobStatus"}})
	if err != nil {
		t.Fatalf("aggregate_jobs over jobs: %v", err)
	}
	if want := "[1=1 2=1]"; fmt.Sprint(got) != want {
		t.Errorf("alice's jobs by JobStatus = %v, want %s", got, want)
	}
}

// TestAggregateJobsHistoryAsPlainTable: a mirror that keeps history as an
// ordinary table rather than an archive is still counted.
func TestAggregateJobsHistoryAsPlainTable(t *testing.T) {
	cat, err := db.OpenCatalog(t.TempDir())
	if err != nil {
		t.Fatalf("open catalog: %v", err)
	}
	if _, err := cat.CreateTable("history"); err != nil {
		t.Fatalf("create history table: %v", err)
	}
	srv := dbrpc.NewServerCatalog(cat)
	t.Cleanup(func() { srv.Close(); _ = cat.Close() })
	m := &testHistoryMirror{srv: srv, cat: cat}
	m.insertJob(t, "history", "1.0", `ClusterId = 1
ProcId = 0
Owner = "alice"
ExitCode = 0`)
	m.insertJob(t, "history", "2.0", `ClusterId = 2
ProcId = 0
Owner = "bob"
ExitCode = 0`)
	s := historyServer(m)

	got, _, err := aggregateCall(t, s, "alice", map[string]interface{}{"table": "history"})
	if err != nil {
		t.Fatalf("aggregate_jobs over a plain history table: %v", err)
	}
	if want := "[=1]"; fmt.Sprint(got) != want {
		t.Errorf("alice's count = %v, want %s", got, want)
	}
}

// TestAggregateJobsArchiveAggregateUnsupported: a mirror too old to
// aggregate an archive at all gets an answer saying so, not dbrpc's
// "bad request" or a misleading "no such table".
func TestAggregateJobsArchiveAggregateUnsupported(t *testing.T) {
	m := newHistoryMirror(t)
	m.completed(t, "alice", 1, 0)
	m.noArchiveAggregates()
	s := historyServer(m)

	_, _, err := aggregateCall(t, s, "alice", map[string]interface{}{"table": "history"})
	if err == nil {
		t.Fatal("aggregate_jobs over history succeeded on a mirror that cannot aggregate an archive")
	}
	for _, want := range []string{`"history"`, "too old"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not contain %q", err, want)
		}
	}
	// The listing tool still works there, so the error can point at it.
	if !strings.Contains(err.Error(), "query_history_db") {
		t.Errorf("error %q does not say what still works", err)
	}
}

// TestAggregateJobsTooManyGroupColumns: the mirror refuses a GROUP BY
// over more columns than its frame allows as a malformed request, which
// for an archive reads as "this server is too old". Refuse it here with
// the actual reason instead.
func TestAggregateJobsTooManyGroupColumns(t *testing.T) {
	m := newHistoryMirror(t)
	s := historyServer(m)
	cols := make([]interface{}, maxAggregateGroupCols+1)
	for i := range cols {
		cols[i] = fmt.Sprintf("Attr%d", i)
	}
	for _, table := range []string{"history", "jobs"} {
		_, _, err := aggregateCall(t, s, "alice", map[string]interface{}{"table": table, "group_by": cols})
		if err == nil {
			t.Errorf("%s: a %d-column group_by was accepted", table, len(cols))
			continue
		}
		if !strings.Contains(err.Error(), "group_by") || strings.Contains(err.Error(), "too old") {
			t.Errorf("%s: error %q does not name the group_by limit", table, err)
		}
	}

	// At the limit is fine.
	m.completed(t, "alice", 1, 0)
	_, _, err := aggregateCall(t, s, "alice", map[string]interface{}{"table": "history", "group_by": cols[:maxAggregateGroupCols]})
	if err != nil {
		t.Errorf("a %d-column group_by was refused: %v", maxAggregateGroupCols, err)
	}
}
