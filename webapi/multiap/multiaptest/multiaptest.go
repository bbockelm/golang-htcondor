// Package multiaptest provides in-process stand-ins for the federation
// hub, spokes and AP registry, for tests of the multi-AP read paths.
//
// The databases are real: a classad catalog served over dbrpc on
// net.Pipe connections, so queries, cursors and TopK run the code a hub
// runs, not a fake of it.
package multiaptest

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/db"
	"github.com/PelicanPlatform/classad/dbrpc"

	"github.com/bbockelm/golang-htcondor/webapi/apregistry"
)

// Hub table names (htcondordb federate/), duplicated so this package
// does not import the package under test.
const (
	TableJobs    = "jobs"
	TableHistory = "history"
	TableSources = "federation_sources"
)

// DB is an in-process htcondordb.
type DB struct {
	t   testing.TB
	cat *db.Catalog
	srv *dbrpc.Server
	mu  sync.Mutex
	seq int
}

// NewDB returns an empty database, closed when the test ends.
func NewDB(t testing.TB) *DB {
	t.Helper()
	cat, err := db.OpenCatalog(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	srv := dbrpc.NewServerCatalog(cat)
	t.Cleanup(func() { srv.Close(); _ = cat.Close() })
	return &DB{t: t, cat: cat, srv: srv}
}

// NewHub returns a database with the hub's tables: jobs (mutable),
// history (archive) and federation_sources.
func NewHub(t testing.TB) *DB {
	d := NewDB(t)
	ctx := context.Background()
	cl := d.client()
	for _, tbl := range []string{TableJobs, TableSources} {
		if err := cl.CreateTable(ctx, tbl); err != nil {
			t.Fatal(err)
		}
	}
	if err := cl.CreateArchiveTable(ctx, TableHistory, db.ArchiveConfig{
		CategoricalAttrs: []string{"ScheddName", "Owner", "GlobalJobId"},
		ValueAttrs:       []string{"ClusterId"},
		ZoneAttrs:        []string{"CompletionDate", "EnteredHistoryTime"},
	}); err != nil {
		t.Fatal(err)
	}
	return d
}

// Dial opens a dbrpc session over a fresh pipe.
func (d *DB) Dial(context.Context) (*dbrpc.Client, func(), error) {
	c, s := net.Pipe()
	go func() { _ = d.srv.ServeConn(dbrpc.NewStreamConn(s)) }()
	cl := dbrpc.NewClient(dbrpc.NewStreamConn(c))
	return cl, func() { _ = cl.Close() }, nil
}

func (d *DB) client() *dbrpc.Client {
	cl, closer, _ := d.Dial(context.Background())
	d.t.Cleanup(closer)
	return cl
}

func (d *DB) commit(table, key, ad string) {
	d.t.Helper()
	ctx := context.Background()
	tx, err := d.client().BeginTable(ctx, table)
	if err != nil {
		d.t.Fatal(err)
	}
	if err := tx.NewClassAd(ctx, key, ad); err != nil {
		d.t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		d.t.Fatal(err)
	}
}

// PutJob writes a live job row the way the hub does: an opaque key, and
// ScheddName on the row. extra is more ClassAd lines.
func (d *DB) PutJob(schedd, user string, cluster, proc int, extra string) {
	d.t.Helper()
	d.mu.Lock()
	d.seq++
	key := fmt.Sprintf("opaque-%d", d.seq)
	d.mu.Unlock()
	owner, _, _ := strings.Cut(user, "@")
	ad := fmt.Sprintf("ScheddName = %q\nUser = %q\nOwner = %q\nClusterId = %d\nProcId = %d\nJobStatus = 1\nKey = \"%d.%d\"",
		schedd, user, owner, cluster, proc, cluster, proc)
	if extra != "" {
		ad += "\n" + extra
	}
	d.commit(TableJobs, key, ad)
}

// PutSpokeJob writes a spoke's row: keyed cluster.proc, no ScheddName.
func (d *DB) PutSpokeJob(user string, cluster, proc int, extra string) {
	d.t.Helper()
	_ = d.client().CreateTable(context.Background(), TableJobs)
	ad := fmt.Sprintf("User = %q\nClusterId = %d\nProcId = %d\nJobStatus = 2\n%s", user, cluster, proc, extra)
	d.commit(TableJobs, fmt.Sprintf("%d.%d", cluster, proc), ad)
}

// PutHistory appends a history record. entered < 0 leaves
// EnteredHistoryTime undefined.
func (d *DB) PutHistory(schedd, user string, cluster, proc int, entered int64) {
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

// PutSource writes a federation_sources row. staleness < 0 leaves
// StalenessSeconds unset.
func (d *DB) PutSource(schedd, state string, staleness int64) {
	d.t.Helper()
	ad := fmt.Sprintf("ScheddName = %q\nState = %q\nLastSeen = %d", schedd, state, time.Now().Unix())
	if staleness >= 0 {
		ad += fmt.Sprintf("\nStalenessSeconds = %d", staleness)
	}
	d.commit(TableSources, schedd, ad)
}

// Registry is a fixed AP set.
type Registry struct {
	mu      sync.Mutex
	members []apregistry.Member
}

// NewRegistry returns a registry of present members with the given names.
func NewRegistry(names ...string) *Registry {
	r := &Registry{}
	for _, n := range names {
		r.members = append(r.members, apregistry.Member{Name: n, Address: "<127.0.0.1:1?name=" + n + ">", Present: true})
	}
	return r
}

// Members implements multiap.Registry.
func (r *Registry) Members() []apregistry.Member {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]apregistry.Member(nil), r.members...)
}

// Get implements multiap.Registry.
func (r *Registry) Get(name string) (apregistry.Member, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, m := range r.members {
		if strings.EqualFold(m.Name, name) {
			return m, true
		}
	}
	return apregistry.Member{}, false
}
