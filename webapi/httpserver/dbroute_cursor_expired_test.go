package httpserver

import (
	"fmt"
	"net/http/httptest"
	"testing"

	"github.com/PelicanPlatform/classad/dbrpc"

	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/webapi/dbmirror"
)

// TestMirrorExpiredCursorDecline: the mirror refusing to resume a page
// token's cursor before any row is a dead token, not a failing mirror. It
// declines as page_token_expired -- which a mandatory mirror answers with
// a 400 -- rather than query_failed, which reads as an outage to retry.
func TestMirrorExpiredCursorDecline(t *testing.T) {
	logger, err := logging.New(&logging.Config{OutputPath: "stderr"})
	if err != nil {
		t.Fatal(err)
	}
	m := &mirrorRowStream{h: &Handler{logger: logger}, w: httptest.NewRecorder(), table: "jobs", key: "jobs", limit: 10}
	expired := fmt.Errorf("query: %w", &dbrpc.ServerError{Msg: "cursor expired: collections: the cursor's snapshot has been reclaimed"})
	d := m.readFailed(expired)
	if d == nil || d.Reason != dbmirror.ReasonPageTokenExpired {
		t.Fatalf("decline %+v, want reason %q", d, dbmirror.ReasonPageTokenExpired)
	}
	if d.Status() != 400 {
		t.Fatalf("status %d, want 400", d.Status())
	}
	if d := m.readFailed(&dbrpc.ServerError{Msg: "no such table: jobs"}); d == nil || d.Reason != dbmirror.ReasonQueryFailed {
		t.Fatalf("another failure: %+v, want reason %q", d, dbmirror.ReasonQueryFailed)
	}
}
