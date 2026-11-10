package httpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/bbockelm/golang-htcondor/webapi/httpserver/appdb"
	"github.com/bbockelm/golang-htcondor/webapi/internal/fakeschedd"
	"github.com/bbockelm/golang-htcondor/webapi/jobwatch"
)

// A user name may itself contain an "@" (SSSD hands such names out), so
// the owner of "foo@bar@test.domain" is "foo@bar", split at the LAST "@"
// as HTCondor splits a fully-qualified user. These drive the three share
// mints through ServeHTTP for that caller, against a schedd holding a job
// and a watch for "foo@bar" and another for "foo": the caller's own mint,
// and the other owner's refused.
func TestShareMintsUseTheOwnerBeforeTheLastAt(t *testing.T) {
	keyFile := writeTestSigningKey(t)
	fs := fakeschedd.Start(t, keyFile, "test.domain")
	held := func(cluster int, owner string) {
		ad := fakeschedd.JobAd(cluster, 0, owner, 5)
		ad.InsertAttr("HoldReasonCode", int64(16)) // waiting for input to be spooled
		fs.AddJobs(ad)
	}
	held(1, "foo@bar")
	held(2, "foo")

	cfg := newTestConfig(t)
	cfg.ScheddAddr = fs.Addr()
	cfg.SigningKeyPath = keyFile
	cfg.TrustDomain = "test.domain"
	cfg.UIDDomain = "test.domain"
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	db, err := appdb.Open(filepath.Join(t.TempDir(), "watch.db"))
	if err != nil {
		t.Fatalf("appdb.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := appdb.Migrate(context.Background(), db); err != nil {
		t.Fatalf("appdb.Migrate: %v", err)
	}
	store := jobwatch.NewStore(db)
	s.jobWatch = store
	s.setupRoutes()
	f := &twoOwnerFixture{s: s, schedd: fs, keyFile: keyFile}

	watchFor := func(owner string) string {
		t.Helper()
		w, err := jobwatch.New(owner, "done", "ClusterId == 1", jobwatch.EventDone, "", jobwatch.ModeAll)
		if err != nil {
			t.Fatalf("jobwatch.New: %v", err)
		}
		if w, err = store.Register(context.Background(), w, time.Hour); err != nil {
			t.Fatalf("Register: %v", err)
		}
		return w.ID
	}
	ownWatch, otherWatch := watchFor("foo@bar"), watchFor("foo")

	caller := f.bearer(t, "foo@bar") // authenticates as foo@bar@test.domain
	mint := func(path string) (int, string) {
		t.Helper()
		w := f.do(t, http.MethodPost, path, "", caller)
		var resp struct {
			Owner string `json:"owner"`
		}
		if w.Code == http.StatusOK {
			if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
				t.Fatalf("POST %s: decoding %s: %v", path, w.Body.String(), err)
			}
		}
		return w.Code, resp.Owner
	}

	for _, tc := range []struct{ own, other string }{
		{"/api/v1/jobs/1.0/output/share", "/api/v1/jobs/2.0/output/share"},
		{"/api/v1/jobs/1.0/input/share", "/api/v1/jobs/2.0/input/share"},
		{"/api/v1/watches/" + ownWatch + "/share", "/api/v1/watches/" + otherWatch + "/share"},
	} {
		if code, owner := mint(tc.own); code != http.StatusOK || owner != "foo@bar" {
			t.Errorf("POST %s as foo@bar@test.domain: status %d, owner %q; want 200 for owner foo@bar", tc.own, code, owner)
		}
		if code, owner := mint(tc.other); code != http.StatusNotFound {
			t.Errorf("POST %s as foo@bar@test.domain: status %d, owner %q; want 404 (it is foo's)", tc.other, code, owner)
		}
	}
}
