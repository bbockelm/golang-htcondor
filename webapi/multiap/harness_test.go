package multiap

import (
	"context"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/PelicanPlatform/classad/dbrpc"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/jobid"
	"github.com/bbockelm/golang-htcondor/webapi/dbmirror"
	"github.com/bbockelm/golang-htcondor/webapi/multiap/multiaptest"
)

type testDB = multiaptest.DB

func newTestDB(t *testing.T) *testDB { return multiaptest.NewDB(t) }

func hubDB(t *testing.T) *testDB { return multiaptest.NewHub(t) }

func newFakeRegistry(names ...string) *multiaptest.Registry { return multiaptest.NewRegistry(names...) }

// fakeSpokes serves fixed spoke infos, dialing in-process databases.
type fakeSpokes struct {
	set  *dbmirror.SpokeSet
	dbs  map[string]*testDB // by Info.Address
	dial int
}

func (f *fakeSpokes) Spokes(context.Context) (*dbmirror.SpokeSet, error) { return f.set, nil }

func (f *fakeSpokes) ClientFor(ctx context.Context, info *dbmirror.Info) (*dbrpc.Client, func(), error) {
	f.dial++
	return f.dbs[info.Address].Dial(ctx)
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
	h := NewHub(hub.Dial, time.Hour)
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
