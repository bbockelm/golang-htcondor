package multiap

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/PelicanPlatform/classad/db"
	"github.com/PelicanPlatform/classad/dbrpc"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/jobid"
	"github.com/bbockelm/golang-htcondor/webapi/apregistry"
	"github.com/bbockelm/golang-htcondor/webapi/dbmirror"
)

// testDB is an in-process htcondordb: a catalog served over dbrpc on
// net.Pipe connections, one per dial.
type testDB struct {
	t   *testing.T
	cat *db.Catalog
	srv *dbrpc.Server
}

func newTestDB(t *testing.T) *testDB {
	t.Helper()
	cat, err := db.OpenCatalog(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	srv := dbrpc.NewServerCatalog(cat)
	t.Cleanup(func() { srv.Close(); _ = cat.Close() })
	return &testDB{t: t, cat: cat, srv: srv}
}

func (d *testDB) dial(context.Context) (*dbrpc.Client, func(), error) {
	c, s := net.Pipe()
	go func() { _ = d.srv.ServeConn(dbrpc.NewStreamConn(s)) }()
	cl := dbrpc.NewClient(dbrpc.NewStreamConn(c))
	return cl, func() { _ = cl.Close() }, nil
}

func (d *testDB) client() *dbrpc.Client {
	cl, closer, _ := d.dial(context.Background())
	d.t.Cleanup(closer)
	return cl
}

// hubDB builds a hub-shaped catalog: jobs (mutable, opaque keys),
// history (archive) and federation_sources.
func hubDB(t *testing.T) *testDB {
	d := newTestDB(t)
	ctx := context.Background()
	cl := d.client()
	for _, tbl := range []string{TableJobs, TableSources} {
		if err := cl.CreateTable(ctx, tbl); err != nil {
			t.Fatal(err)
		}
	}
	if err := cl.CreateArchiveTable(ctx, TableHistory, db.ArchiveConfig{
		CategoricalAttrs: []string{AttrScheddName, "Owner", "GlobalJobId"},
		ValueAttrs:       []string{"ClusterId"},
		ZoneAttrs:        []string{"CompletionDate", attrEnteredHistory},
	}); err != nil {
		t.Fatal(err)
	}
	return d
}

var keySeq int

// putJob writes a live job row the way the hub does: an opaque key and
// ScheddName on the row.
func (d *testDB) putJob(schedd, user string, cluster, proc int, extra string) {
	d.t.Helper()
	ctx := context.Background()
	tx, err := d.client().BeginTable(ctx, TableJobs)
	if err != nil {
		d.t.Fatal(err)
	}
	keySeq++
	owner, _, _ := strings.Cut(user, "@")
	ad := fmt.Sprintf("ScheddName = %q\nUser = %q\nOwner = %q\nClusterId = %d\nProcId = %d\nJobStatus = 1\nKey = \"%d.%d\"",
		schedd, user, owner, cluster, proc, cluster, proc)
	if extra != "" {
		ad += "\n" + extra
	}
	if err := tx.NewClassAd(ctx, fmt.Sprintf("opaque-%d", keySeq), ad); err != nil {
		d.t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		d.t.Fatal(err)
	}
}

// putSpokeJob writes a spoke's row: keyed cluster.proc, no ScheddName.
func (d *testDB) putSpokeJob(user string, cluster, proc int, extra string) {
	d.t.Helper()
	ctx := context.Background()
	cl := d.client()
	_ = cl.CreateTable(ctx, TableJobs)
	tx, err := cl.BeginTable(ctx, TableJobs)
	if err != nil {
		d.t.Fatal(err)
	}
	ad := fmt.Sprintf("User = %q\nClusterId = %d\nProcId = %d\nJobStatus = 2\n%s", user, cluster, proc, extra)
	if err := tx.NewClassAd(ctx, fmt.Sprintf("%d.%d", cluster, proc), ad); err != nil {
		d.t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		d.t.Fatal(err)
	}
}

// putHistory appends a history record. entered < 0 leaves
// EnteredHistoryTime undefined.
func (d *testDB) putHistory(schedd, user string, cluster, proc int, entered int64) {
	d.t.Helper()
	owner, _, _ := strings.Cut(user, "@")
	ad := fmt.Sprintf("ScheddName = %q\nUser = %q\nOwner = %q\nClusterId = %d\nProcId = %d\nJobStatus = 4\nGlobalJobId = \"%s#%d.%d#%d\"",
		schedd, user, owner, cluster, proc, schedd, cluster, proc, entered)
	if entered >= 0 {
		ad += fmt.Sprintf("\nEnteredHistoryTime = %d", entered)
	}
	if err := d.client().ArchiveAppend(context.Background(), TableHistory, ad); err != nil {
		d.t.Fatal(err)
	}
}

func (d *testDB) putSource(schedd, state string, staleness int64) {
	d.t.Helper()
	ctx := context.Background()
	tx, err := d.client().BeginTable(ctx, TableSources)
	if err != nil {
		d.t.Fatal(err)
	}
	ad := fmt.Sprintf("ScheddName = %q\nState = %q\nLastSeen = %d", schedd, state, time.Now().Unix())
	if staleness >= 0 {
		ad += fmt.Sprintf("\nStalenessSeconds = %d", staleness)
	}
	if err := tx.NewClassAd(ctx, schedd, ad); err != nil {
		d.t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		d.t.Fatal(err)
	}
}

// fakeRegistry is a fixed AP set.
type fakeRegistry struct{ members []apregistry.Member }

func newFakeRegistry(names ...string) *fakeRegistry {
	r := &fakeRegistry{}
	for _, n := range names {
		r.members = append(r.members, apregistry.Member{Name: n, Address: "<127.0.0.1:1?name=" + n + ">", Present: true})
	}
	return r
}

func (r *fakeRegistry) Members() []apregistry.Member {
	return append([]apregistry.Member(nil), r.members...)
}

func (r *fakeRegistry) Get(name string) (apregistry.Member, bool) {
	for _, m := range r.members {
		if strings.EqualFold(m.Name, name) {
			return m, true
		}
	}
	return apregistry.Member{}, false
}

// fakeSpokes serves fixed spoke infos, dialing in-process databases.
type fakeSpokes struct {
	set  *dbmirror.SpokeSet
	dbs  map[string]*testDB // by Info.Address
	dial int
}

func (f *fakeSpokes) Spokes(context.Context) (*dbmirror.SpokeSet, error) { return f.set, nil }

func (f *fakeSpokes) ClientFor(ctx context.Context, info *dbmirror.Info) (*dbrpc.Client, func(), error) {
	f.dial++
	return f.dbs[info.Address].dial(ctx)
}

// fakeSchedd answers a single-job query with fixed ads and records what
// it was asked.
type fakeSchedd struct {
	mu          sync.Mutex
	ads         []*classad.ClassAd
	err         error
	constraints []string
}

func (f *fakeSchedd) QueryWithOptions(_ context.Context, constraint string, _ *htcondor.QueryOptions) ([]*classad.ClassAd, *htcondor.PageInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.constraints = append(f.constraints, constraint)
	return f.ads, nil, f.err
}

func freshSpokeInfo(schedd, addr string) *dbmirror.Info {
	return &dbmirror.Info{
		Name: "spoke-" + schedd, Address: addr, MirroredScheddName: schedd, Syncing: true,
		JobQueueCaughtUp: true, JobQueueReported: true, JobQueueLastSyncTime: time.Now().Unix(), JobQueueSecondsSync: 1,
		HistoryReported: true, HistoryLastSyncTime: time.Now().Unix(), SecondsSinceSync: 1,
	}
}

// newService wires a Service to an in-process hub and refreshes its
// sources snapshot.
func newService(t *testing.T, hub *testDB, reg Registry) *Service {
	t.Helper()
	h := NewHub(hub.dial, time.Hour)
	if err := h.Refresh(context.Background()); err != nil {
		t.Fatalf("refreshing hub sources: %v", err)
	}
	return &Service{Registry: reg, Hub: h, Codec: jobid.Default(), Stale: StaleInclude, UIDDomain: "d"}
}

func collect(t *testing.T, s *Service, req ListRequest) ([]Row, *ListResult) {
	t.Helper()
	var rows []Row
	res, err := s.ListJobs(context.Background(), req, func(r Row) bool {
		rows = append(rows, r)
		return true
	})
	if err != nil {
		t.Fatalf("ListJobs(%+v): %v", req, err)
	}
	return rows, res
}

func ids(s *Service, rows []Row) []string {
	out := make([]string, len(rows))
	for i, r := range rows {
		out[i] = s.Codec.Format(r.ID)
	}
	sort.Strings(out)
	return out
}
