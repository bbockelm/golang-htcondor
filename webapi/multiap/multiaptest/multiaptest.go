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

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/webapi/apregistry"
)

// Hub table names (htcondordb federate/), duplicated so this package
// does not import the package under test.
const (
	TableJobs         = "jobs"
	TableHistory      = "history"
	TableEpochHistory = "epoch_history"
	TableSources      = "federation_sources"
)

// DB is an in-process htcondordb.
type DB struct {
	t   testing.TB
	cat *db.Catalog
	srv *dbrpc.Server
	mu  sync.Mutex
	seq int
	// keys is each PutJob row's opaque key, by schedd/cluster.proc and
	// then user: two users' rows may share an id on one AP.
	keys map[string]map[string]string
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

// NewMemoryHub is NewHub with the live tables -- jobs and
// federation_sources -- held in memory and no history archive: for a
// test that reads only live jobs. Closing a persistent table costs a
// test a fifth of a second; this one closes at once.
func NewMemoryHub(t testing.TB) *DB {
	d := NewDB(t)
	ctx := context.Background()
	cl := d.client()
	for _, tbl := range []string{TableJobs, TableSources} {
		if err := cl.CreateTableInMemory(ctx, tbl); err != nil {
			t.Fatal(err)
		}
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
	if d.keys == nil {
		d.keys = map[string]map[string]string{}
	}
	id := fmt.Sprintf("%s/%d.%d", schedd, cluster, proc)
	if d.keys[id] == nil {
		d.keys[id] = map[string]string{}
	}
	d.keys[id][user] = key
	d.mu.Unlock()
	owner, _, _ := strings.Cut(user, "@")
	ad := fmt.Sprintf("ScheddName = %q\nUser = %q\nOwner = %q\nClusterId = %d\nProcId = %d\nJobStatus = 1\nKey = \"%d.%d\"",
		schedd, user, owner, cluster, proc, cluster, proc)
	if extra != "" {
		ad += "\n" + extra
	}
	d.commit(TableJobs, key, ad)
}

// DeleteJob removes a live job row PutJob wrote, as the hub does when
// the job leaves its AP's queue. The id must name one user's row; with
// two users' rows under it, DeleteUserJob says whose.
func (d *DB) DeleteJob(schedd string, cluster, proc int) {
	d.t.Helper()
	d.mu.Lock()
	users := d.keys[fmt.Sprintf("%s/%d.%d", schedd, cluster, proc)]
	d.mu.Unlock()
	if len(users) != 1 {
		d.t.Fatalf("multiaptest: %d rows hold %d.%d on %s; use DeleteUserJob", len(users), cluster, proc, schedd)
	}
	for user := range users {
		d.DeleteUserJob(schedd, user, cluster, proc)
	}
}

// DeleteUserJob removes user's live job row cluster.proc on schedd.
func (d *DB) DeleteUserJob(schedd, user string, cluster, proc int) {
	d.t.Helper()
	d.mu.Lock()
	id := fmt.Sprintf("%s/%d.%d", schedd, cluster, proc)
	key, ok := d.keys[id][user]
	if ok {
		delete(d.keys[id], user)
	}
	d.mu.Unlock()
	if !ok {
		d.t.Fatalf("multiaptest: no job %d.%d of %s on %s to delete", cluster, proc, user, schedd)
	}
	ctx := context.Background()
	tx, err := d.client().BeginTable(ctx, TableJobs)
	if err != nil {
		d.t.Fatal(err)
	}
	if err := tx.DestroyClassAd(ctx, key); err != nil {
		d.t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		d.t.Fatal(err)
	}
}

// EnableEpochHistory creates the hub's epoch_history archive, as a hub
// federating it has.
func (d *DB) EnableEpochHistory() {
	d.t.Helper()
	if err := d.client().CreateArchiveTable(context.Background(), TableEpochHistory, db.ArchiveConfig{
		CategoricalAttrs: []string{"ScheddName", "Owner", "User", "GlobalJobId"},
		ValueAttrs:       []string{"ClusterId"},
		ZoneAttrs:        []string{"EpochWriteDate", "EnteredHistoryTime"},
	}); err != nil {
		d.t.Fatal(err)
	}
}

// PutEpoch appends an epoch_history record: one run instance's EpochAdType
// record (EPOCH, INPUT, OUTPUT, ...) written at writeDate, with extra
// ClassAd lines.
func (d *DB) PutEpoch(schedd, user string, cluster, proc int, adType string, writeDate int64, extra string) {
	d.t.Helper()
	owner, _, _ := strings.Cut(user, "@")
	ad := fmt.Sprintf("ScheddName = %q\nUser = %q\nOwner = %q\nClusterId = %d\nProcId = %d\nEpochAdType = %q\n"+
		"EpochWriteDate = %d\nRunInstanceID = 0\nGlobalJobId = \"%s#%d.%d#1\"",
		schedd, user, owner, cluster, proc, adType, writeDate, schedd, cluster, proc)
	if extra != "" {
		ad += "\n" + extra
	}
	if err := d.client().ArchiveAppend(context.Background(), TableEpochHistory, ad); err != nil {
		d.t.Fatal(err)
	}
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

// PutSource writes a federation_sources row with its jobs stream
// connected. staleness < 0 leaves StalenessSeconds unset.
func (d *DB) PutSource(schedd, state string, staleness int64) {
	d.t.Helper()
	ad := fmt.Sprintf("ScheddName = %q\nState = %q\nLastSeen = %d\nJobsConnected = true", schedd, state, time.Now().Unix())
	if staleness >= 0 {
		ad += fmt.Sprintf("\nStalenessSeconds = %d", staleness)
	}
	d.commit(TableSources, schedd, ad)
}

// PutSourceAd writes a federation_sources row verbatim.
func (d *DB) PutSourceAd(schedd, ad string) {
	d.t.Helper()
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

// Update applies fn to the member named name (case-insensitive). It
// fails the test helper's caller by panicking on an unknown name, which
// is always a bug in the test.
func (r *Registry) Update(name string, fn func(*apregistry.Member)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range r.members {
		if strings.EqualFold(r.members[i].Name, name) {
			fn(&r.members[i])
			return
		}
	}
	panic("multiaptest: no member " + name)
}

// Remove takes the member named name (case-insensitive) out of the set.
func (r *Registry) Remove(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	kept := r.members[:0]
	for _, m := range r.members {
		if !strings.EqualFold(m.Name, name) {
			kept = append(kept, m)
		}
	}
	r.members = kept
}

// WithSchedds gives every member a schedd handle at the address addr
// returns for its name, and returns r.
func (r *Registry) WithSchedds(addr func(name string) string) *Registry {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range r.members {
		a := addr(r.members[i].Name)
		r.members[i].Address = a
		r.members[i].Schedd = htcondor.NewSchedd(r.members[i].Name, a)
	}
	return r
}
