package multiap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/PelicanPlatform/classad/dbrpc"

	"github.com/bbockelm/golang-htcondor/jobid"
	"github.com/bbockelm/golang-htcondor/webapi/apregistry"
	"github.com/bbockelm/golang-htcondor/webapi/dbmirror"
)

// seededHub is the standard population: alice has 1.0 on BOTH ap1 and
// ap2 (cluster ids are per AP), plus 2.0 on ap1; bob has 1.0 and 5.0 on
// ap1. Both APs are fresh.
func seededHub(t *testing.T) *testDB {
	hub := hubDB(t)
	hub.putJob("ap1.example.org", "alice@d", 1, 0, `Marker = "alice-ap1-1"`)
	hub.putJob("ap1.example.org", "alice@d", 2, 0, `Marker = "alice-ap1-2"`)
	hub.putJob("ap2.example.org", "alice@d", 1, 0, `Marker = "alice-ap2-1"`)
	hub.putJob("ap1.example.org", "bob@d", 1, 0, `Marker = "bob-ap1-1"`)
	hub.putJob("ap1.example.org", "bob@d", 5, 0, `Marker = "bob-ap1-5"`)
	hub.putSource("ap1.example.org", StateFresh, 3)
	hub.putSource("ap2.example.org", StateFresh, 4)
	return hub
}

func TestListJobsSelfScopedAcrossAPs(t *testing.T) {
	hub := seededHub(t)
	s := newService(t, hub, newFakeRegistry("ap1.example.org", "ap2.example.org"))

	rows, res := collect(t, s, ListRequest{User: "alice@d"})
	got := ids(s, rows)
	want := []string{"1.0@ap1.example.org", "1.0@ap2.example.org", "2.0@ap1.example.org"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("alice sees %v, want %v", got, want)
	}
	for _, r := range rows {
		if u, _ := r.Ad.EvaluateAttrString("User"); u != "alice@d" {
			t.Errorf("row %v belongs to %q", r.ID, u)
		}
	}
	if res.Sources.APs != 2 || res.Sources.Fresh != 2 || len(res.Sources.Degraded) != 0 {
		t.Errorf("sources = %+v", res.Sources)
	}

	rows, _ = collect(t, s, ListRequest{User: "bob@d"})
	if got := ids(s, rows); !reflect.DeepEqual(got, []string{"1.0@ap1.example.org", "5.0@ap1.example.org"}) {
		t.Errorf("bob sees %v", got)
	}
}

// TestListJobsScopeCannotBeWidened: the caller's constraint is
// re-serialized and ANDed; no spelling reaches another user's rows.
func TestListJobsScopeCannotBeWidened(t *testing.T) {
	hub := seededHub(t)
	s := newService(t, hub, newFakeRegistry("ap1.example.org", "ap2.example.org"))

	for _, c := range []string{
		`true || true`,
		`User == "bob@d" || true`,
		`Owner == "bob"`,
		`(true)) || ((true`,
		`MY.User =!= "alice@d"`,
	} {
		var rows []Row
		_, err := s.ListJobs(context.Background(), ListRequest{User: "alice@d", Constraint: c}, func(r Row) bool {
			rows = append(rows, r)
			return true
		})
		if err != nil {
			if StatusOf(err) != http.StatusBadRequest {
				t.Errorf("%q: error %v, want a 400", c, err)
			}
			continue
		}
		for _, r := range rows {
			if u, _ := r.Ad.EvaluateAttrString("User"); u != "alice@d" {
				t.Errorf("constraint %q widened the scope to %q's job %v", c, u, r.ID)
			}
		}
	}
	if _, err := s.ListJobs(context.Background(), ListRequest{User: "alice@d", Constraint: `true) || (true`}, func(Row) bool { return true }); StatusOf(err) != http.StatusBadRequest {
		t.Errorf("unbalanced constraint: err = %v, want 400", err)
	}
	if _, err := s.ListJobs(context.Background(), ListRequest{}, func(Row) bool { return true }); StatusOf(err) != http.StatusUnauthorized {
		t.Errorf("no user: err = %v, want 401", err)
	}
}

func TestListJobsScheddFilter(t *testing.T) {
	hub := seededHub(t)
	s := newService(t, hub, newFakeRegistry("ap1.example.org", "ap2.example.org"))

	rows, _ := collect(t, s, ListRequest{User: "alice@d", Schedd: "ap2.example.org"})
	if got := ids(s, rows); !reflect.DeepEqual(got, []string{"1.0@ap2.example.org"}) {
		t.Fatalf("?schedd=ap2 gave %v", got)
	}
	if m, _ := rows[0].Ad.EvaluateAttrString("Marker"); m != "alice-ap2-1" {
		t.Errorf("served the wrong AP's 1.0: %q", m)
	}
	rows, _ = collect(t, s, ListRequest{User: "alice@d", Schedd: "AP1.example.org"})
	if got := ids(s, rows); !reflect.DeepEqual(got, []string{"1.0@ap1.example.org", "2.0@ap1.example.org"}) {
		t.Errorf("?schedd=AP1 gave %v", got)
	}
	_, err := s.ListJobs(context.Background(), ListRequest{User: "alice@d", Schedd: "ap9"}, func(Row) bool { return true })
	if StatusOf(err) != http.StatusBadRequest {
		t.Errorf("unknown schedd: err = %v, want 400", err)
	}
}

// TestListJobsOutsideAPSetNotServed: hub rows for a schedd the registry
// does not list are not served.
func TestListJobsOutsideAPSetNotServed(t *testing.T) {
	hub := seededHub(t)
	s := newService(t, hub, newFakeRegistry("ap1.example.org"))
	rows, res := collect(t, s, ListRequest{User: "alice@d"})
	if got := ids(s, rows); !reflect.DeepEqual(got, []string{"1.0@ap1.example.org", "2.0@ap1.example.org"}) {
		t.Errorf("got %v", got)
	}
	if res.Sources.APs != 1 {
		t.Errorf("sources = %+v", res.Sources)
	}
}

func TestListJobsDegraded(t *testing.T) {
	hub := seededHub(t)
	hub.putSource("ap2.example.org", StateStale, 412)
	reg := newFakeRegistry("ap1.example.org", "ap2.example.org", "ap3.example.org")
	s := newService(t, hub, reg)

	rows, res := collect(t, s, ListRequest{User: "alice@d"})
	if got := ids(s, rows); !reflect.DeepEqual(got, []string{"1.0@ap1.example.org", "1.0@ap2.example.org", "2.0@ap1.example.org"}) {
		t.Errorf("include: got %v", got)
	}
	if res.Sources.APs != 3 || res.Sources.Fresh != 1 || len(res.Sources.Degraded) != 2 {
		t.Fatalf("include: sources = %+v", res.Sources)
	}
	byName := map[string]Degraded{}
	for _, d := range res.Sources.Degraded {
		byName[d.Schedd] = d
	}
	if d := byName["ap2.example.org"]; d.State != StateStale || d.StalenessSeconds == nil || *d.StalenessSeconds != 412 {
		t.Errorf("ap2 = %+v", d)
	}
	if d := byName["ap3.example.org"]; d.State != StateAbsent {
		t.Errorf("ap3 (not in the hub) = %+v, want absent", d)
	}

	s.Stale = StaleExclude
	rows, res = collect(t, s, ListRequest{User: "alice@d"})
	if got := ids(s, rows); !reflect.DeepEqual(got, []string{"1.0@ap1.example.org", "2.0@ap1.example.org"}) {
		t.Errorf("exclude: got %v", got)
	}
	if len(res.Sources.Degraded) != 2 {
		t.Errorf("exclude must still list the degraded APs: %+v", res.Sources)
	}
	rows, _ = collect(t, s, ListRequest{User: "alice@d", Schedd: "ap2.example.org"})
	if len(rows) != 0 {
		t.Errorf("exclude + ?schedd=ap2: got %v", ids(s, rows))
	}
}

// TestListJobsPagesExactlyOnce pages a db1: cursor one row at a time.
func TestListJobsPagesExactlyOnce(t *testing.T) {
	hub := seededHub(t)
	for c := 10; c < 17; c++ {
		hub.putJob("ap2.example.org", "alice@d", c, 0, "")
		hub.putJob("ap1.example.org", "alice@d", c, c%2, "")
	}
	s := newService(t, hub, newFakeRegistry("ap1.example.org", "ap2.example.org"))

	for _, limit := range []int{1, 2, 5} {
		seen := map[string]int{}
		token := ""
		for pages := 0; ; pages++ {
			if pages > 100 {
				t.Fatal("pagination did not terminate")
			}
			rows, res := collect(t, s, ListRequest{User: "alice@d", Limit: limit, PageToken: token})
			if len(rows) > limit {
				t.Fatalf("limit %d: page of %d", limit, len(rows))
			}
			for _, r := range rows {
				seen[s.Codec.Format(r.ID)]++
			}
			if !res.HasMore {
				break
			}
			if !strings.HasPrefix(res.NextPageToken, "db1:") {
				t.Fatalf("token %q", res.NextPageToken)
			}
			token = res.NextPageToken
		}
		if len(seen) != 17 {
			t.Errorf("limit %d: saw %d distinct jobs, want 17", limit, len(seen))
		}
		for id, n := range seen {
			if n != 1 {
				t.Errorf("limit %d: %s returned %d times", limit, id, n)
			}
		}
	}

	_, err := s.ListJobs(context.Background(), ListRequest{User: "alice@d", PageToken: encodeHistoryToken(histKey{T: 1})}, func(Row) bool { return true })
	if StatusOf(err) != http.StatusBadRequest {
		t.Errorf("a hub1: token on the job list: err = %v, want 400", err)
	}
}

// TestHistoryPagesExactlyOnce: duplicate cluster.proc on two APs, ties
// on EnteredHistoryTime, records with no EnteredHistoryTime, and another
// user's records. Every one of the caller's records exactly once, in
// order, at every page size.
func TestHistoryPagesExactlyOnce(t *testing.T) {
	hub := hubDB(t)
	hub.putSource("ap1.example.org", StateFresh, 1)
	hub.putSource("AP2.example.org", StateFresh, 1)
	want := map[string]bool{}
	add := func(schedd, user string, c, p int, entered int64) {
		hub.putHistory(schedd, user, c, p, entered)
		if user == "alice@d" {
			want[fmt.Sprintf("%d.%d@%s", c, p, schedd)] = true
		}
	}
	// Appended out of time order, as a lagging spoke would.
	add("ap1.example.org", "alice@d", 1, 0, 1000)
	add("AP2.example.org", "alice@d", 1, 0, 1000) // same cluster.proc AND same time, other AP
	add("ap1.example.org", "alice@d", 2, 0, 900)
	add("AP2.example.org", "alice@d", 2, 0, 1200)
	add("ap1.example.org", "alice@d", 3, 0, 1000)
	add("ap1.example.org", "alice@d", 3, 1, 1000)
	add("ap1.example.org", "bob@d", 1, 0, 1000)
	add("ap1.example.org", "bob@d", 9, 0, 5000)
	add("AP2.example.org", "alice@d", 4, 0, 800)
	add("ap1.example.org", "alice@d", 7, 0, -1) // no EnteredHistoryTime
	add("AP2.example.org", "alice@d", 7, 0, -1)
	add("AP2.example.org", "alice@d", 3, 0, 1100)
	for c := 20; c < 30; c++ {
		add("ap1.example.org", "alice@d", c, 0, int64(700+c%3))
	}
	s := newService(t, hub, newFakeRegistry("ap1.example.org", "AP2.example.org"))

	for _, proj := range [][]string{nil, {"User"}, {"*"}} {
		for _, limit := range []int{1, 2, 3, 7, 50} {
			var order []Row
			token := ""
			for pages := 0; ; pages++ {
				if pages > 200 {
					t.Fatal("pagination did not terminate")
				}
				rows, res, err := s.ListHistory(context.Background(), ListRequest{User: "alice@d", Limit: limit, PageToken: token, Projection: proj})
				if err != nil {
					t.Fatalf("limit %d page %d: %v", limit, pages, err)
				}
				order = append(order, rows...)
				if !res.HasMore {
					break
				}
				if !IsHistoryToken(res.NextPageToken) {
					t.Fatalf("token %q", res.NextPageToken)
				}
				token = res.NextPageToken
			}
			seen := map[string]int{}
			for _, r := range order {
				id := s.Codec.Format(r.ID)
				seen[id]++
				if u, _ := r.Ad.EvaluateAttrString("User"); u != "alice@d" {
					t.Errorf("limit %d: another user's record %s", limit, id)
				}
				if !r.Archived {
					t.Errorf("limit %d: %s not marked archived", limit, id)
				}
			}
			if len(seen) != len(want) {
				t.Errorf("limit %d: %d distinct records, want %d", limit, len(seen), len(want))
			}
			for id := range want {
				if seen[id] != 1 {
					t.Errorf("limit %d: %s seen %d times, want once", limit, id, seen[id])
				}
			}
			for i := 1; i < len(order); i++ {
				if keyOf(order[i]).before(keyOf(order[i-1])) {
					t.Errorf("limit %d: %v before %v out of order", limit, order[i-1].ID, order[i].ID)
				}
			}
		}
	}

	_, _, err := s.ListHistory(context.Background(), ListRequest{User: "alice@d", PageToken: dbmirror.EncodeCursor(dbrpc.SeqCursor{Seq: 1})})
	if StatusOf(err) != http.StatusBadRequest {
		t.Errorf("a db1: token on history: err = %v, want 400", err)
	}
}

func TestGetJobComplete(t *testing.T) {
	hub := seededHub(t)
	s := newService(t, hub, newFakeRegistry("ap1.example.org", "ap2.example.org"))
	ctx := context.Background()

	for _, tc := range []struct{ id, marker string }{
		{"1.0@ap2.example.org", "alice-ap2-1"},
		{"1.0@ap1.example.org", "alice-ap1-1"},
	} {
		id, _ := s.Codec.Parse(tc.id)
		res, err := s.GetJob(ctx, "alice@d", id, nil)
		if err != nil {
			t.Fatalf("%s: %v", tc.id, err)
		}
		if m, _ := res.Row.Ad.EvaluateAttrString("Marker"); m != tc.marker || res.Source != SourceHub {
			t.Errorf("%s: marker %q source %q", tc.id, m, res.Source)
		}
		if s.Codec.Format(res.Row.ID) != tc.id {
			t.Errorf("%s: answered %v", tc.id, res.Row.ID)
		}
	}
	// bob's job is not alice's to read.
	id, _ := s.Codec.Parse("5.0@ap1.example.org")
	if _, err := s.GetJob(ctx, "alice@d", id, nil); StatusOf(err) != http.StatusNotFound {
		t.Errorf("another user's job: err = %v, want 404", err)
	}
	id, _ = s.Codec.Parse("1.0@ap9")
	if _, err := s.GetJob(ctx, "alice@d", id, nil); StatusOf(err) != http.StatusNotFound {
		t.Errorf("unknown AP: err = %v, want 404", err)
	}
}

func TestGetJobIncomplete(t *testing.T) {
	hub := seededHub(t)
	hub.putHistory("ap2.example.org", "alice@d", 8, 0, 1000)
	s := newService(t, hub, newFakeRegistry("ap1.example.org", "ap2.example.org"))
	ctx := context.Background()

	// One match: served, with the complete id.
	res, err := s.GetJob(ctx, "alice@d", jobid.ID{Cluster: 2}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := s.Codec.Format(res.Row.ID); got != "2.0@ap1.example.org" {
		t.Errorf("2.0 resolved to %s", got)
	}
	// One match, in history only.
	res, err = s.GetJob(ctx, "alice@d", jobid.ID{Cluster: 8}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := s.Codec.Format(res.Row.ID); got != "8.0@ap2.example.org" || !res.Row.Archived {
		t.Errorf("8.0 resolved to %s archived=%v", got, res.Row.Archived)
	}
	// Two: 409 naming both, as structured ids.
	_, err = s.GetJob(ctx, "alice@d", jobid.ID{Cluster: 1}, nil)
	cands, ok := IsAmbiguous(err)
	if !ok || StatusOf(err) != http.StatusConflict {
		t.Fatalf("1.0: err = %v, want 409", err)
	}
	if len(cands) != 2 || cands[0].Schedd != "ap1.example.org" || cands[1].Schedd != "ap2.example.org" ||
		cands[0].Cluster != 1 || cands[0].JobID != "1.0@ap1.example.org" {
		t.Errorf("candidates = %+v", cands)
	}
	// None; and bob's 5.0 does not resolve for alice.
	for _, c := range []int64{99, 5} {
		if _, err := s.GetJob(ctx, "alice@d", jobid.ID{Cluster: c}, nil); StatusOf(err) != http.StatusNotFound {
			t.Errorf("%d.0: err = %v, want 404", c, err)
		}
	}
}

// TestGetJobStaleAPFallsBack: a stale AP is read from its spoke when the
// spoke is current, and from its schedd (as the caller, self-scoped)
// when it is not.
func TestGetJobStaleAPFallsBack(t *testing.T) {
	hub := seededHub(t)
	hub.putSource("ap2.example.org", StateStale, 600)
	spoke := newTestDB(t)
	spoke.putSpokeJob("alice@d", 1, 0, `Marker = "from-spoke"`)
	spoke.putSpokeJob("bob@d", 3, 0, `Marker = "bob-spoke"`)

	reg := newFakeRegistry("ap1.example.org", "ap2.example.org")
	s := newService(t, hub, reg)
	info := freshSpokeInfo("ap2.example.org", "<spoke2>")
	spokes := &fakeSpokes{set: dbmirror.NewSpokeSetForTest(info), dbs: map[string]*testDB{"<spoke2>": spoke}}
	s.Spokes = spokes
	schedd := &fakeSchedd{}
	s.Schedd = func(m apregistry.Member) ScheddQuerier {
		if m.Name != "ap2.example.org" {
			t.Errorf("schedd fallback dialled %s", m.Name)
		}
		return schedd
	}
	ctx := context.Background()
	id, _ := s.Codec.Parse("1.0@ap2.example.org")

	res, err := s.GetJob(ctx, "alice@d", id, nil)
	if err != nil {
		t.Fatal(err)
	}
	if m, _ := res.Row.Ad.EvaluateAttrString("Marker"); m != "from-spoke" || res.Source != SourceSpoke {
		t.Errorf("spoke tier: marker %q source %q", m, res.Source)
	}
	if res.Degraded == nil || res.Degraded.State != StateStale {
		t.Errorf("degraded = %+v", res.Degraded)
	}
	if s.Codec.Format(res.Row.ID) != "1.0@ap2.example.org" {
		t.Errorf("spoke row named %v", res.Row.ID)
	}
	// bob's job on the spoke is not alice's.
	bobs, _ := s.Codec.Parse("3.0@ap2.example.org")
	if _, err := s.GetJob(ctx, "alice@d", bobs, nil); StatusOf(err) != http.StatusNotFound {
		t.Errorf("bob's spoke job: err = %v, want 404", err)
	}

	// The spoke falls behind: the schedd answers.
	info.JobQueueCaughtUp = false
	ad, _ := classad.ParseOld("User = \"alice@d\"\nClusterId = 1\nProcId = 0\nMarker = \"from-schedd\"")
	schedd.ads = []*classad.ClassAd{ad}
	res, err = s.GetJob(ctx, "alice@d", id, nil)
	if err != nil {
		t.Fatal(err)
	}
	if m, _ := res.Row.Ad.EvaluateAttrString("Marker"); m != "from-schedd" || res.Source != SourceSchedd {
		t.Errorf("schedd tier: marker %q source %q", m, res.Source)
	}
	if len(schedd.constraints) == 0 || !strings.Contains(schedd.constraints[len(schedd.constraints)-1], `User == "alice@d"`) {
		t.Errorf("schedd query not self-scoped: %v", schedd.constraints)
	}

	// The schedd is unreachable too: the hub's (stale) copy, flagged.
	schedd.err = errors.New("connection refused")
	res, err = s.GetJob(ctx, "alice@d", id, nil)
	if err != nil {
		t.Fatal(err)
	}
	if m, _ := res.Row.Ad.EvaluateAttrString("Marker"); m != "alice-ap2-1" || res.Source != SourceHub || res.Degraded == nil {
		t.Errorf("last resort: marker %q source %q degraded %+v", m, res.Source, res.Degraded)
	}
}

func TestRowJSON(t *testing.T) {
	s := &Service{Codec: jobid.Default()}
	ad, _ := classad.ParseOld("ClusterId = 1\nProcId = 0\nSchedd = \"spoof\"\nCmd = \"/bin/true\"")
	out, err := s.RowJSON(Row{ID: jobid.ID{Schedd: "ap1@x", Cluster: 1}, Ad: ad})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatalf("%s: %v", out, err)
	}
	if m["schedd"] != "ap1@x" || m["cluster"] != float64(1) || m["proc"] != float64(0) || m["job_id"] != "1.0@ap1@x" || m["Cmd"] != "/bin/true" {
		t.Errorf("RowJSON = %s", out)
	}
	if _, ok := m["Schedd"]; ok {
		t.Errorf("a colliding attribute survived: %s", out)
	}
	empty, err := s.RowJSON(Row{ID: jobid.ID{Schedd: "a", Cluster: 2}, Ad: classad.New()})
	if err != nil || json.Unmarshal(empty, &m) != nil {
		t.Errorf("empty ad: %s %v", empty, err)
	}
}

func TestUserFor(t *testing.T) {
	s := &Service{UIDDomain: "d"}
	for actor, want := range map[string]string{"alice": "alice@d", "alice@other": "alice@d", "foo@bar@d": "foo@bar@d"} {
		if got, err := s.UserFor(actor); err != nil || got != want {
			t.Errorf("UserFor(%q) = %q, %v; want %q", actor, got, err, want)
		}
	}
	if _, err := s.UserFor(""); err == nil {
		t.Error("an empty actor must not map to a user")
	}
}

func TestHubSourcesAndAPs(t *testing.T) {
	hub := seededHub(t)
	s := newService(t, hub, newFakeRegistry("ap1.example.org", "ap3.example.org"))
	aps := s.APs()
	if len(aps) != 2 || aps[0].Hub.State != StateFresh || aps[1].Hub.State != StateAbsent {
		t.Errorf("APs = %+v", aps)
	}
	if st := s.Hub.Status(); !st.Reachable || st.Sources != 2 {
		t.Errorf("hub status = %+v", st)
	}
}
