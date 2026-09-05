package httpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/config"
	"github.com/bbockelm/golang-htcondor/webapi/dbmirror"
)

// The probe names an internal daemon's address and can be pressed
// repeatedly; neither belongs to a general user.
func TestDBMirrorTestRequiresAdmin(t *testing.T) {
	server, req := newDBMirrorServer(t, http.MethodPost, "/api/v1/dbmirror/test")

	rec := httptest.NewRecorder()
	server.handleDBMirrorTest(rec, req("alice", nil))
	if rec.Code != http.StatusForbidden {
		t.Errorf("non-admin: status = %d, want 403", rec.Code)
	}

	rec = httptest.NewRecorder()
	server.handleDBMirrorTest(rec,
		httptest.NewRequestWithContext(context.Background(), "GET", "/api/v1/dbmirror/test", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET: status = %d, want 405 (this runs a read, so it is a POST)", rec.Code)
	}
}

// TestDBMirrorTestReportsTheFailingStage is the whole point of the
// probe. The status card already says the mirror is not working; which
// step fails -- discovery against the collector, the authenticated
// connection, or the query itself -- is what an operator cannot get
// anywhere else, and they are different problems with different fixes.
func TestDBMirrorTestReportsTheFailingStage(t *testing.T) {
	server, req := newDBMirrorServer(t, http.MethodPost, "/api/v1/dbmirror/test")
	server.dbMirror = dbmirror.NewLocator(
		htcondor.NewCollector("collector.invalid:9618"), config.NewEmpty())

	rec := httptest.NewRecorder()
	server.handleDBMirrorTest(rec, req("root", []string{"condor-admins"}))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}

	var got dbMirrorTestResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.OK {
		t.Error("nothing is advertising to collector.invalid; the probe should not report success")
	}
	if len(got.Stages) == 0 {
		t.Fatal("a failure with no stages is no more useful than the card already was")
	}
	last := got.Stages[len(got.Stages)-1]
	if last.Name != "discover" {
		t.Errorf("the first stage to fail should be discovery, got %q", last.Name)
	}
	if last.Error == "" {
		t.Error("the failing stage must carry the error, not just a false flag")
	}
	// Stages after the failure are not invented.
	for _, st := range got.Stages[:len(got.Stages)-1] {
		if !st.OK {
			t.Errorf("stage %q is reported failed before the one that stopped the probe", st.Name)
		}
	}
}

// TestDBMirrorTestSaysWhenRoutingIsOff: "not configured" and "broken"
// are different answers, and pressing the button on a pool with no
// mirror should get the first.
func TestDBMirrorTestSaysWhenRoutingIsOff(t *testing.T) {
	server, req := newDBMirrorServer(t, http.MethodPost, "/api/v1/dbmirror/test")

	rec := httptest.NewRecorder()
	server.handleDBMirrorTest(rec, req("root", []string{"condor-admins"}))
	var got dbMirrorTestResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.OK || len(got.Stages) != 1 || got.Stages[0].Name != "configured" {
		t.Fatalf("expected a single 'configured' stage: %+v", got)
	}
	if !strings.Contains(got.Stages[0].Error, "not configured") {
		t.Errorf("the reason should say routing is off, not that something broke: %q", got.Stages[0].Error)
	}
}

// TestDBMirrorTestQueryMatchesNothing: the probe is meant to be pressed
// repeatedly while chasing a misconfiguration, so it must not move rows.
func TestDBMirrorTestQueryMatchesNothing(t *testing.T) {
	if dbMirrorTestConstraint != "false" {
		t.Errorf("the probe constraint is %q; it should match nothing so the button is free to press",
			dbMirrorTestConstraint)
	}
}
