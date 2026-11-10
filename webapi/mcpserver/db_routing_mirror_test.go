package mcpserver

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/PelicanPlatform/classad/dbrpc"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/webapi/dbmirror"
	"github.com/bbockelm/golang-htcondor/webapi/multiap/multiaptest"
)

// The mirror read behind query_job_archive, against a real htcondordb whose
// "history" is an ARCHIVE table, as it is in production: archives answer
// TopK and projections through different code than plain tables do.

// mirrorHistory returns a client to an in-process mirror holding one archived
// record per entry of entered, in that (arrival) order. Record i is ClusterId
// 100+i with EnteredHistoryTime entered[i]; a negative entry leaves
// EnteredHistoryTime off the record. Every record has CompletionDate 5000, so
// "CompletionDate >= 5000" matches them all, the way a time window does.
func mirrorHistory(t *testing.T, entered []int64) *dbrpc.Client {
	t.Helper()
	hub := multiaptest.NewHub(t)
	dbc, closer, err := hub.Dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(closer)
	for i, e := range entered {
		ad := fmt.Sprintf("ClusterId = %d\nProcId = 0\nOwner = \"alice\"\nJobStatus = 4\nCompletionDate = 5000\nCmd = \"/bin/job%d\"", 100+i, i)
		if e >= 0 {
			ad += fmt.Sprintf("\n%s = %d", dbmirror.HistoryOrderAttr, e)
		}
		if err := dbc.ArchiveAppend(context.Background(), "history", ad); err != nil {
			t.Fatal(err)
		}
	}
	return dbc
}

// shuffledEntered is n distinct entry times 1001..1000+n, appended out of
// order so that arrival order and recency disagree: a result in recency order
// was ordered by the mirror or here, not by the archive's scan.
func shuffledEntered(n int) []int64 {
	out := make([]int64, n)
	for i := range out {
		out[i] = int64(1001 + (i*7)%n) // 7 is coprime with the sizes used, so this is a permutation
	}
	return out
}

func clusters(t *testing.T, records []*classad.ClassAd) []int64 {
	t.Helper()
	out := make([]int64, 0, len(records))
	for _, r := range records {
		c, ok := r.EvaluateAttrInt("ClusterId")
		if !ok {
			t.Fatalf("record without ClusterId: %v", r)
		}
		out = append(out, c)
	}
	return out
}

// clusterFor maps an entry time back to the record that carries it.
func clusterFor(entered []int64, e int64) int64 {
	for i, v := range entered {
		if v == e {
			return int64(100 + i)
		}
	}
	return -1
}

// newestClusters is the ClusterIds of the n newest records, newest first.
func newestClusters(entered []int64, n int) []int64 {
	var out []int64
	for e := int64(1000 + len(entered)); len(out) < n; e-- {
		out = append(out, clusterFor(entered, e))
	}
	return out
}

func equalInts(a, b []int64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// The reported bug: a window matching more records than the limit declined to
// the schedd, whose scan budget then answered an old window with nothing. The
// mirror now answers with the newest `limit` matches, newest first, and says
// that more matched.
func TestMirrorHistoryServesNewestWhenOversized(t *testing.T) {
	entered := shuffledEntered(30)
	dbc := mirrorHistory(t, entered)

	records, more, d := readMirrorHistory(context.Background(), dbc, "CompletionDate >= 5000", []string{"ClusterId", "ProcId"}, 5)
	if !d.Use {
		t.Fatalf("declined (%s): %s", d.Reason, d.Note)
	}
	if !more {
		t.Error("more = false, want true: 30 records matched a limit of 5")
	}
	if got, want := clusters(t, records), newestClusters(entered, 5); !equalInts(got, want) {
		t.Errorf("ClusterIds = %v, want the newest five in recency order %v", got, want)
	}
	for _, r := range records {
		if _, ok := r.Lookup(dbmirror.HistoryOrderAttr); ok {
			t.Errorf("%s was fetched only to order by and must not be returned: %v", dbmirror.HistoryOrderAttr, r)
		}
	}
	if !strings.Contains(d.Note, "newest 5") {
		t.Errorf("note %q should say the answer is the newest 5", d.Note)
	}
}

// A caller who asked for every attribute gets whole ads, still the newest
// `limit`. Records tied with the boundary record count as equally new; the
// answer holds exactly `limit` of them and nothing older.
func TestMirrorHistoryServesNewestWholeAdsWhenOversized(t *testing.T) {
	// 20 records, entry times 1001..1020, then three more tied at 1017.
	entered := shuffledEntered(20)
	entered = append(entered, 1017, 1017, 1017)
	dbc := mirrorHistory(t, entered)

	records, more, d := readMirrorHistory(context.Background(), dbc, "CompletionDate >= 5000", nil, 5)
	if !d.Use {
		t.Fatalf("declined (%s): %s", d.Reason, d.Note)
	}
	if !more || len(records) != 5 {
		t.Fatalf("got %d records, more=%v; want 5 and more", len(records), more)
	}
	var times []int64
	for _, r := range records {
		e, ok := r.EvaluateAttrInt(dbmirror.HistoryOrderAttr)
		if !ok {
			t.Fatalf("whole ad without %s: %v", dbmirror.HistoryOrderAttr, r)
		}
		if _, ok := r.EvaluateAttrString("Cmd"); !ok {
			t.Errorf("whole ad is missing attributes: %v", r)
		}
		times = append(times, e)
	}
	// Newest first: 1020, 1019, 1018, then two of the four records at 1017.
	want := []int64{1020, 1019, 1018, 1017, 1017}
	if !equalInts(times, want) {
		t.Errorf("entry times = %v, want %v", times, want)
	}
}

// A match set within the limit is answered as before: all of it, newest first,
// with nothing said about more.
func TestMirrorHistoryWithinLimitUnchanged(t *testing.T) {
	// Neither arrival order nor its reverse is newest first, so only a
	// sort on the order key passes.
	entered := []int64{1002, 1001, 1003}
	dbc := mirrorHistory(t, entered)

	records, more, d := readMirrorHistory(context.Background(), dbc, "CompletionDate >= 5000", []string{"ClusterId"}, 5)
	if !d.Use || more {
		t.Fatalf("Use=%v more=%v (%s: %s); want served, no more", d.Use, more, d.Reason, d.Note)
	}
	if d.Note != "" {
		t.Errorf("note = %q; a complete answer keeps the routing note", d.Note)
	}
	if got, want := clusters(t, records), newestClusters(entered, 3); !equalInts(got, want) {
		t.Errorf("ClusterIds = %v, want %v", got, want)
	}
}

// topKUnsupported is a mirror too old for the TopK opcode.
type topKUnsupported struct{ *dbrpc.Client }

func (topKUnsupported) TopK(context.Context, string, string, []string, string, bool, int) ([]string, error) {
	return nil, dbrpc.ErrTopKUnsupported
}

// Without server-side ordering the mirror cannot pick the newest records out
// of an oversized match set, so the schedd answers, as it always did.
func TestMirrorHistoryOversizedFallsBackWithoutTopK(t *testing.T) {
	dbc := topKUnsupported{mirrorHistory(t, shuffledEntered(30))}
	for _, projection := range [][]string{{"ClusterId"}, nil} {
		_, _, d := readMirrorHistory(context.Background(), dbc, "CompletionDate >= 5000", projection, 5)
		if d.Use || d.Reason != dbmirror.ReasonOversized {
			t.Errorf("projection %v: Use=%v Reason=%q, want a %q decline", projection, d.Use, d.Reason, dbmirror.ReasonOversized)
		}
	}
	// Within the limit TopK is never asked, so an old mirror still serves.
	small := topKUnsupported{mirrorHistory(t, shuffledEntered(3))}
	if _, _, d := readMirrorHistory(context.Background(), small, "CompletionDate >= 5000", []string{"ClusterId"}, 5); !d.Use {
		t.Errorf("a complete answer must not need TopK: declined %s", d.Note)
	}
}

// TopK cannot rank a record with no order key, and such a record could be
// among the newest; when the ordered read comes back short of what the probe
// counted, the schedd answers instead.
func TestMirrorHistoryOversizedFallsBackWhenRecordsLackOrderKey(t *testing.T) {
	entered := []int64{1001, 1002, 1003, -1, -1, -1, -1}
	dbc := mirrorHistory(t, entered)
	_, _, d := readMirrorHistory(context.Background(), dbc, "CompletionDate >= 5000", []string{"ClusterId"}, 5)
	if d.Use || d.Reason != dbmirror.ReasonOversized {
		t.Errorf("Use=%v Reason=%q, want a %q decline", d.Use, d.Reason, dbmirror.ReasonOversized)
	}
}

// End to end through the tool result: the truncation is reported in the text
// and the structured result, next to the mirror's provenance.
func TestMirrorHistoryResultReportsTruncation(t *testing.T) {
	entered := shuffledEntered(30)
	dbc := mirrorHistory(t, entered)
	info := &dbmirror.Info{Address: "<mirror>", Name: "mirror@ap"}
	opts := &htcondor.HistoryQueryOptions{Limit: 3, Projection: []string{"ClusterId", "ProcId"}, Backwards: true}

	res, ok, d := mirrorHistoryResult(context.Background(), dbc, info, dbmirror.Decision{Use: true, Reason: dbmirror.ReasonServed, Note: "served"},
		"CompletionDate >= 5000", opts, "job history", false)
	if !ok {
		t.Fatalf("declined (%s): %s", d.Reason, d.Note)
	}
	m := res.(map[string]interface{})
	text := m["content"].([]map[string]interface{})[0]["text"].(string)
	if !strings.Contains(text, "Found 3 job history record(s)") {
		t.Errorf("missing count: %q", text)
	}
	if !strings.Contains(text, "Stopped at the requested limit of 3; more match.") {
		t.Errorf("truncation note missing: %q", text)
	}
	if !strings.Contains(text, "[source: htcondordb mirror") || !strings.Contains(text, "newest 3") {
		t.Errorf("provenance should name the mirror and the ordering: %q", text)
	}
	sc := m["structuredContent"].(map[string]interface{})
	if sc["has_more"] != true || sc["count"] != 3 || sc["scan_limit_reached"] != false {
		t.Errorf("structured = %+v, want has_more, count 3, scan_limit_reached false", sc)
	}
}
