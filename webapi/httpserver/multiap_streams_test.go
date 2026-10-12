package httpserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/bbockelm/golang-htcondor/webapi/multiap/multiaptest"
)

// The change streams in multi-AP mode refuse an identity outside
// UID_DOMAIN before opening, as every other multi-AP read does: the feed
// names owners by the local part of User, and alice@other.example is not
// alice@d.
func TestMultiAPStreamsRefuseAnotherDomain(t *testing.T) {
	srv := newMultiAPServer(t, multiAPService(t, multiAPHub(t), multiaptest.NewRegistry(ap1, ap2)))
	for _, path := range []string{"/api/v1/jobs/watch", "/api/v1/dashboard/activity/stream"} {
		// Bounded: a stream wrongly opened would otherwise never end.
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		req := httptest.NewRequestWithContext(ctx, http.MethodGet, path, nil)
		req.Header.Set("X-Remote-User", "alice@other.example")
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		cancel()
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s as alice@other.example = %d %s, want 403", path, rec.Code, rec.Body.String())
		}
	}
}
